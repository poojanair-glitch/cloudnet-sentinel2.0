import unittest
import time
import json
import base64
from engine.finding_engine import FindingEngine

class TestFindingEngine(unittest.TestCase):

    def setUp(self):
        self.secret = "test-secret-cloudnet-2026"
        self.mock_scan_results = {
            "ec2": [
                {
                    "id": "i-0a1b2c3d4e5f67890",
                    "type": "EC2",
                    "public_ip": "54.210.10.20",
                    "is_public": True,
                    "security_groups": ["sg-0123456789abcdef0"]
                }
            ],
            "sgs": [
                {
                    "id": "sg-0123456789abcdef0",
                    "name": "web-ssh-sec-group",
                    "is_open": True,
                    "insecure_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 22,
                            "to_port": 22,
                            "cidr": "0.0.0.0/0",
                            "description": "Open SSH"
                        }
                    ]
                }
            ],
            "iam": [],
            "s3": []
        }

    def test_token_creation_and_verification(self):
        payload = {
            "finding_id": "cns-fnd-test01",
            "security_group_id": "sg-0123456789abcdef0",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "source_cidr": "0.0.0.0/0"
        }
        token = FindingEngine.create_remediation_token(payload, secret=self.secret, expires_in_seconds=3600)
        self.assertIn(".", token)

        decoded = FindingEngine.verify_remediation_token(token, secret=self.secret)
        self.assertEqual(decoded["finding_id"], "cns-fnd-test01")
        self.assertEqual(decoded["security_group_id"], "sg-0123456789abcdef0")
        self.assertEqual(decoded["from_port"], 22)
        self.assertIn("iat", decoded)
        self.assertIn("exp", decoded)

    def test_token_tamper_detection(self):
        payload = {
            "finding_id": "cns-fnd-test02",
            "security_group_id": "sg-0123456789abcdef0",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "source_cidr": "0.0.0.0/0"
        }
        token = FindingEngine.create_remediation_token(payload, secret=self.secret)
        payload_b64, sig = token.split(".")

        # Tamper with signature
        tampered_sig = sig[:-4] + "ffff"
        with self.assertRaises(ValueError) as ctx:
            FindingEngine.verify_remediation_token(f"{payload_b64}.{tampered_sig}", secret=self.secret)
        self.assertIn("tampered", str(ctx.exception).lower())

        # Tamper with payload (attacker attempts to change security_group_id)
        raw_json = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode("utf-8"))
        raw_json["security_group_id"] = "sg-attacker999999"
        tampered_payload_b64 = base64.urlsafe_b64encode(json.dumps(raw_json).encode("utf-8")).decode("utf-8").rstrip("=")
        with self.assertRaises(ValueError) as ctx:
            FindingEngine.verify_remediation_token(f"{tampered_payload_b64}.{sig}", secret=self.secret)
        self.assertIn("tampered", str(ctx.exception).lower())

    def test_token_expiration(self):
        payload = {"finding_id": "cns-fnd-expired", "security_group_id": "sg-0123456789abcdef0"}
        # Create token that expired 10 seconds ago
        token = FindingEngine.create_remediation_token(payload, secret=self.secret, expires_in_seconds=-10)
        with self.assertRaises(ValueError) as ctx:
            FindingEngine.verify_remediation_token(token, secret=self.secret)
        self.assertIn("expired", str(ctx.exception).lower())

    def test_generate_findings_from_scan(self):
        findings = FindingEngine.generate_findings(self.mock_scan_results, account_id="123456789012")
        self.assertEqual(len(findings), 1)

        f = findings[0]
        self.assertTrue(f["finding_id"].startswith("cns-fnd-"))
        self.assertEqual(f["resource_id"], "i-0a1b2c3d4e5f67890")
        self.assertEqual(f["security_group_id"], "sg-0123456789abcdef0")
        self.assertEqual(f["protocol"], "tcp")
        self.assertEqual(f["from_port"], 22)
        self.assertEqual(f["to_port"], 22)
        self.assertEqual(f["source_cidr"], "0.0.0.0/0")
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertGreaterEqual(f["risk_score"], 85)
        self.assertIn("secure?", f["secure_url"])
        self.assertIn("token=", f["secure_url"])
        self.assertIn("Revoke ingress rule", f["recommended_action"])
        self.assertEqual(f["remediation_payload"]["action"], "revoke_security_group_ingress")

    def test_all_ports_critical_severity(self):
        all_ports_scan = {
            "ec2": [],
            "sgs": [
                {
                    "id": "sg-00001111222233334",
                    "name": "open-all",
                    "is_open": True,
                    "insecure_rules": [
                        {
                            "protocol": "-1",
                            "from_port": None,
                            "to_port": None,
                            "cidr": "0.0.0.0/0",
                            "description": "Allow all"
                        }
                    ]
                }
            ]
        }
        findings = FindingEngine.generate_findings(all_ports_scan)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["port_display"], "ALL PORTS")

if __name__ == "__main__":
    unittest.main()
