import unittest
from unittest.mock import patch, MagicMock
from app import app, SIMULATION_DATA

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

if __name__ == "__main__":
    unittest.main()
