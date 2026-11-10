import unittest
from unittest.mock import patch, MagicMock
from app import app, SIMULATION_DATA
from engine.finding_engine import FindingEngine

class TestSecureAll(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        SIMULATION_DATA["findings"] = [
            {
                "finding_id": "cns-fnd-unit-test-1",
                "remediation_payload": {
                    "finding_id": "cns-fnd-unit-test-1",
                    "account_id": "826917685155",
                    "region": "us-east-1",
                    "security_group_id": "sg-0123456789abcdef0",
                    "security_group_name": "test-sg",
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "source_cidr": "0.0.0.0/0",
                    "action": "revoke_security_group_ingress"
                }
            }
        ]

    @patch("remediation.lambda_function.revoke_insecure_rule")
    def test_secure_all_success(self, mock_revoke):
        mock_revoke.return_value = ("REMEDIATED", "Successfully revoked rule")
        response = self.client.post("/api/secure-all")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(len(data["results"]), 1)
        self.assertEqual(data["results"][0]["status"], "REMEDIATED")

    @patch("remediation.lambda_function.revoke_insecure_rule")
    @patch("app.get_boto_session")
    def test_local_secure_endpoint(self, mock_get_session, mock_revoke):
        mock_revoke.return_value = ("REMEDIATED", "Successfully revoked rule")
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session
        payload = {
            "finding_id": "cns-fnd-local-test",
            "account_id": "826917685155",
            "region": "us-east-1",
            "security_group_id": "sg-0123456789abcdef0",
            "security_group_name": "test-sg",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "source_cidr": "0.0.0.0/0",
            "action": "revoke_security_group_ingress"
        }
        token = FindingEngine.create_remediation_token(payload)

        response = self.client.get(
            "/secure",
            query_string={"finding_id": payload["finding_id"], "token": token},
            headers={"Accept": "application/json"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "REMEDIATED")
        mock_revoke.assert_called_once()
        revoke_client, token_payload = mock_revoke.call_args.args
        self.assertIs(revoke_client, mock_session.client.return_value)
        self.assertEqual(token_payload["finding_id"], payload["finding_id"])

if __name__ == "__main__":
    unittest.main()
