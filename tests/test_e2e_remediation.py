import unittest
from unittest.mock import patch, MagicMock
from urllib.parse import urlparse, parse_qs
import json
from engine.finding_engine import FindingEngine
from services.alert_notifier import AlertNotifier
from remediation.lambda_function import lambda_handler

class TestE2ERemediationWorkflow(unittest.TestCase):
    """
    End-to-End Simulation of the complete Secure Now workflow:
    1. Scan infrastructure & detect exposed port (e.g. port 3389 / RDP).
    2. FindingEngine calculates risk score & severity, creates finding & signed URL.
    3. AlertNotifier generates alert email with [ SECURE NOW ] CTA.
    4. User clicks link; request invokes Lambda handler.
    5. Lambda validates signature, checks EC2, and revokes vulnerable ingress rule.
    6. User receives confirmation. Subsequent clicks return 'Already Secured'.
    """

    @patch("boto3.client")
    def test_complete_secure_now_pipeline(self, mock_boto):
        secret = "e2e-shared-remediation-secret-2026"
        with patch.dict("os.environ", {"REMEDIATION_SIGNING_SECRET": secret, "API_GATEWAY_URL": "https://api.cloudnet.io/prod"}):

            # Step 1: Simulated Scan Results
            scan_results = {
                "ec2": [
                    {
                        "id": "i-0987654321fedcba0",
                        "type": "EC2",
                        "public_ip": "3.80.12.34",
                        "is_public": True,
                        "security_groups": ["sg-0a9b8c7d6e5f43210"]
                    }
                ],
                "sgs": [
                    {
                        "id": "sg-0a9b8c7d6e5f43210",
                        "name": "windows-bastion-sg",
                        "is_open": True,
                        "insecure_rules": [
                            {
                                "protocol": "tcp",
                                "from_port": 3389,
                                "to_port": 3389,
                                "cidr": "0.0.0.0/0",
                                "description": "Global RDP"
                            }
                        ]
                    }
                ]
            }

            # Step 2: Finding Generation
            findings = FindingEngine.generate_findings(scan_results, account_id="112233445566")
            self.assertEqual(len(findings), 1)
            finding = findings[0]

            self.assertEqual(finding["resource_id"], "i-0987654321fedcba0")
            self.assertEqual(finding["security_group_id"], "sg-0a9b8c7d6e5f43210")
            self.assertEqual(finding["from_port"], 3389)
            self.assertEqual(finding["severity"], "CRITICAL")
            self.assertTrue("https://api.cloudnet.io/prod/secure?" in finding["secure_url"])

            # Step 3: Alert Notification Content
            email = AlertNotifier.build_email_content(finding)
            self.assertIn("SECURE NOW", email["plain_text"])
            self.assertIn(finding["secure_url"], email["plain_text"])
            self.assertIn("3389", email["subject"])

            # Step 4: Extract token from the Secure Now link (simulating user clicking link)
            parsed_url = urlparse(finding["secure_url"])
            token = parse_qs(parsed_url.query)["token"][0]

            # Step 5: Lambda Execution Simulation (First Click -> Revokes Ingress)
            mock_ec2 = MagicMock()
            mock_boto.return_value = mock_ec2

            # Mock SG with the vulnerable rule currently present
            mock_ec2.describe_security_groups.return_value = {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-0a9b8c7d6e5f43210",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 3389,
                                "ToPort": 3389,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                            }
                        ]
                    }
                ]
            }
            mock_ec2.revoke_security_group_ingress.return_value = {"Return": True}

            api_gateway_event = {
                "httpMethod": "GET",
                "queryStringParameters": {"token": token},
                "headers": {"Accept": "application/json"}
            }

            response1 = lambda_handler(api_gateway_event, None)
            self.assertEqual(response1["statusCode"], 200)
            res1_body = json.loads(response1["body"])
            self.assertEqual(res1_body["status"], "REMEDIATED")

            # Verify that ONLY the exact 3389 rule was revoked
            mock_ec2.revoke_security_group_ingress.assert_called_once_with(
                GroupId="sg-0a9b8c7d6e5f43210",
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }
                ]
            )

            # Step 6: Second Click -> Rule is now gone, verify idempotent 'Already Secured'
            mock_ec2.reset_mock()
            mock_ec2.describe_security_groups.return_value = {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-0a9b8c7d6e5f43210",
                        "IpPermissions": []  # Empty now
                    }
                ]
            }

            response2 = lambda_handler(api_gateway_event, None)
            self.assertEqual(response2["statusCode"], 200)
            res2_body = json.loads(response2["body"])
            self.assertEqual(res2_body["status"], "ALREADY_SECURED")
            mock_ec2.revoke_security_group_ingress.assert_not_called()

if __name__ == "__main__":
    unittest.main()
