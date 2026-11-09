import unittest
from unittest.mock import patch, MagicMock
import json
from botocore.exceptions import ClientError
from engine.finding_engine import FindingEngine
from remediation.lambda_function import lambda_handler, verify_token, revoke_insecure_rule

class TestRemediationLambda(unittest.TestCase):

    def setUp(self):
        self.secret = "test-secret-cloudnet-2026"
        self.valid_payload = {
            "finding_id": "cns-fnd-unit01",
            "account_id": "123456789012",
            "resource_id": "i-0a1b2c3d4e5f67890",
            "resource_type": "EC2 Instance",
            "security_group_id": "sg-0123456789abcdef0",
            "security_group_name": "web-ssh-sec-group",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "source_cidr": "0.0.0.0/0",
            "action": "revoke_security_group_ingress"
        }

    # 1. Valid Secure Now request (GET with finding_id and token)
    @patch("boto3.client")
    @patch("remediation.lambda_function.get_signing_secret")
    def test_valid_secure_now_request(self, mock_secret, mock_boto):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret)

        mock_ec2 = MagicMock()
        mock_boto.return_value = mock_ec2
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-0123456789abcdef0",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            }]
        }
        mock_ec2.revoke_security_group_ingress.return_value = {"Return": True}

        event = {
            "httpMethod": "GET",
            "queryStringParameters": {"finding_id": "cns-fnd-unit01", "token": token},
            "headers": {"Accept": "application/json"}
        }
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["status"], "REMEDIATED")

    # 2. Invalid HMAC token
    @patch("remediation.lambda_function.get_signing_secret")
    def test_invalid_hmac_token(self, mock_secret):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret)
        tampered_token = token[:-5] + "12345"

        event = {
            "httpMethod": "GET",
            "queryStringParameters": {"token": tampered_token},
            "headers": {"Accept": "application/json"}
        }
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertIn("Forbidden", body.get("error", ""))

    # 3. Expired token
    @patch("remediation.lambda_function.get_signing_secret")
    def test_expired_token(self, mock_secret):
        mock_secret.return_value = self.secret
        expired_token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret, expires_in_seconds=-3600)

        event = {
            "httpMethod": "GET",
            "queryStringParameters": {"token": expired_token},
            "headers": {"Accept": "application/json"}
        }
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertIn("expired", body.get("details", "").lower())

    # 4. Missing token
    @patch("remediation.lambda_function.get_signing_secret")
    def test_missing_token(self, mock_secret):
        mock_secret.return_value = self.secret
        event = {"httpMethod": "GET", "queryStringParameters": {}, "headers": {"Accept": "application/json"}}
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 400)

    # 5. Missing finding ID
    @patch("remediation.lambda_function.get_signing_secret")
    def test_missing_finding_id(self, mock_secret):
        mock_secret.return_value = self.secret
        event = {"httpMethod": "GET", "queryStringParameters": None, "headers": {"Accept": "application/json"}}
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 400)

    # 6. Invalid finding ID (Finding ID mismatch)
    @patch("remediation.lambda_function.get_signing_secret")
    def test_invalid_finding_id_mismatch(self, mock_secret):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret)
        event = {
            "httpMethod": "GET",
            "queryStringParameters": {"finding_id": "cns-fnd-mismatch99", "token": token},
            "headers": {"Accept": "application/json"}
        }
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 403)
        body = json.loads(response["body"])
        self.assertIn("mismatch", body.get("details", "").lower())

    # 7. Invalid security group ID format
    @patch("remediation.lambda_function.get_signing_secret")
    def test_invalid_security_group_id(self, mock_secret):
        mock_secret.return_value = self.secret
        malicious_payload = dict(self.valid_payload)
        malicious_payload["security_group_id"] = "sg-inject;rm -rf /"
        bad_token = FindingEngine.create_remediation_token(malicious_payload, secret=self.secret)

        event = {
            "httpMethod": "GET",
            "queryStringParameters": {"token": bad_token},
            "headers": {"Accept": "application/json"}
        }
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 403)

    # 8. Security group not found
    @patch("boto3.client")
    @patch("remediation.lambda_function.get_signing_secret")
    def test_security_group_not_found(self, mock_secret, mock_boto):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret)
        mock_ec2 = MagicMock()
        mock_boto.return_value = mock_ec2
        mock_ec2.describe_security_groups.side_effect = ClientError(
            {"Error": {"Code": "InvalidGroup.NotFound", "Message": "SG not found"}},
            "DescribeSecurityGroups"
        )
        event = {"httpMethod": "GET", "queryStringParameters": {"token": token}, "headers": {"Accept": "application/json"}}
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 500)

    # 9. Target rule exists and is successfully revoked
    @patch("boto3.client")
    @patch("remediation.lambda_function.get_signing_secret")
    def test_target_rule_exists_and_revoked(self, mock_secret, mock_boto):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret)
        mock_ec2 = MagicMock()
        mock_boto.return_value = mock_ec2
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]
        }
        mock_ec2.revoke_security_group_ingress.return_value = {"Return": True}

        event = {"httpMethod": "GET", "queryStringParameters": {"token": token}, "headers": {"Accept": "application/json"}}
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(json.loads(response["body"])["status"], "REMEDIATED")

    # 10. Target rule already revoked (idempotent)
    @patch("boto3.client")
    @patch("remediation.lambda_function.get_signing_secret")
    def test_target_rule_already_revoked(self, mock_secret, mock_boto):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret)
        mock_ec2 = MagicMock()
        mock_boto.return_value = mock_ec2
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "IpPermissions": []}]
        }

        event = {"httpMethod": "GET", "queryStringParameters": {"token": token}, "headers": {"Accept": "application/json"}}
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(json.loads(response["body"])["status"], "ALREADY_SECURED")

    # 11. Wrong port
    @patch("boto3.client")
    @patch("remediation.lambda_function.get_signing_secret")
    def test_wrong_port(self, mock_secret, mock_boto):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret) # Payload port is 22
        mock_ec2 = MagicMock()
        mock_boto.return_value = mock_ec2
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]
        }

        event = {"httpMethod": "GET", "queryStringParameters": {"token": token}, "headers": {"Accept": "application/json"}}
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(json.loads(response["body"])["status"], "ALREADY_SECURED")

    # 12. Wrong protocol
    @patch("boto3.client")
    @patch("remediation.lambda_function.get_signing_secret")
    def test_wrong_protocol(self, mock_secret, mock_boto):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret) # Payload protocol is tcp
        mock_ec2 = MagicMock()
        mock_boto.return_value = mock_ec2
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "IpPermissions": [{"IpProtocol": "udp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]
        }

        event = {"httpMethod": "GET", "queryStringParameters": {"token": token}, "headers": {"Accept": "application/json"}}
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(json.loads(response["body"])["status"], "ALREADY_SECURED")

    # 13. Wrong CIDR
    @patch("boto3.client")
    @patch("remediation.lambda_function.get_signing_secret")
    def test_wrong_cidr(self, mock_secret, mock_boto):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret) # Payload CIDR is 0.0.0.0/0
        mock_ec2 = MagicMock()
        mock_boto.return_value = mock_ec2
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]
        }

        event = {"httpMethod": "GET", "queryStringParameters": {"token": token}, "headers": {"Accept": "application/json"}}
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(json.loads(response["body"])["status"], "ALREADY_SECURED")

    # 14. AWS permission failure
    @patch("boto3.client")
    @patch("remediation.lambda_function.get_signing_secret")
    def test_aws_permission_failure(self, mock_secret, mock_boto):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret)
        mock_ec2 = MagicMock()
        mock_boto.return_value = mock_ec2
        mock_ec2.describe_security_groups.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized"}},
            "DescribeSecurityGroups"
        )

        event = {"httpMethod": "GET", "queryStringParameters": {"token": token}, "headers": {"Accept": "application/json"}}
        response = lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 500)
        self.assertEqual(json.loads(response["body"])["status"], "FAILED")

    # 15. SNS notification failure handling
    @patch("boto3.client")
    @patch("remediation.lambda_function.get_signing_secret")
    @patch("services.alert_notifier.AlertNotifier.send_remediation_confirmation")
    def test_sns_notification_failure(self, mock_sns_notify, mock_secret, mock_boto):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret)
        mock_ec2 = MagicMock()
        mock_boto.return_value = mock_ec2
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "IpPermissions": []}]
        }
        mock_sns_notify.side_effect = Exception("SNS Service Error")

        event = {"httpMethod": "GET", "queryStringParameters": {"token": token}, "headers": {"Accept": "application/json"}}
        response = lambda_handler(event, None)
        # Should complete successfully despite SNS notification exception
        self.assertEqual(response["statusCode"], 200)

    # 16. Lambda malformed event
    @patch("remediation.lambda_function.get_signing_secret")
    def test_lambda_malformed_event(self, mock_secret):
        mock_secret.return_value = self.secret
        response = lambda_handler({}, None)
        self.assertEqual(response["statusCode"], 400)

    # 17. API Gateway query-string request (v2 HTTP API)
    @patch("boto3.client")
    @patch("remediation.lambda_function.get_signing_secret")
    def test_api_gateway_query_string_request(self, mock_secret, mock_boto):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret)
        mock_ec2 = MagicMock()
        mock_boto.return_value = mock_ec2
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "IpPermissions": []}]
        }

        apigw_event = {
            "version": "2.0",
            "routeKey": "GET /secure",
            "rawQueryString": f"finding_id=cns-fnd-unit01&token={token}",
            "queryStringParameters": {"finding_id": "cns-fnd-unit01", "token": token},
            "requestContext": {"http": {"method": "GET"}},
            "headers": {"accept": "application/json"}
        }
        response = lambda_handler(apigw_event, None)
        self.assertEqual(response["statusCode"], 200)

    # 18. API Gateway POST request
    @patch("boto3.client")
    @patch("remediation.lambda_function.get_signing_secret")
    def test_api_gateway_post_request(self, mock_secret, mock_boto):
        mock_secret.return_value = self.secret
        token = FindingEngine.create_remediation_token(self.valid_payload, secret=self.secret)
        mock_ec2 = MagicMock()
        mock_boto.return_value = mock_ec2
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "IpPermissions": []}]
        }

        post_event = {
            "httpMethod": "POST",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"content-type": "application/json", "accept": "application/json"},
            "body": json.dumps({"finding_id": "cns-fnd-unit01", "token": token})
        }
        response = lambda_handler(post_event, None)
        self.assertEqual(response["statusCode"], 200)

if __name__ == "__main__":
    unittest.main()
