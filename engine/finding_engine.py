import os
import json
import time
import hmac
import hashlib
import base64
import uuid
from typing import Dict, List, Any, Optional

DEFAULT_SIGNING_SECRET = "cloudnet-sentinel-default-remediation-secret-2026"

KNOWN_PORT_RISKS = {
    22: {
        "name": "SSH",
        "score": 85,
        "severity": "CRITICAL",
        "description": "Port 22 (SSH) is directly accessible from anywhere on the internet (0.0.0.0/0). Attackers can launch automated brute-force attacks or exploit SSH vulnerabilities to obtain remote root shell access."
    },
    3389: {
        "name": "RDP",
        "score": 85,
        "severity": "CRITICAL",
        "description": "Port 3389 (Remote Desktop Protocol) is exposed globally to the internet. This exposes systems to credential stuffing, BlueKeep-style RCE vulnerabilities, and ransomware entry points."
    },
    3306: {
        "name": "MySQL",
        "score": 90,
        "severity": "CRITICAL",
        "description": "Port 3306 (MySQL Database) is accessible from 0.0.0.0/0. Databases must never be publicly exposed to the internet, risking immediate data breaches and credential compromise."
    },
    5432: {
        "name": "PostgreSQL",
        "score": 90,
        "severity": "CRITICAL",
        "description": "Port 5432 (PostgreSQL) is exposed to the internet. Publicly accessible database ports are actively scanned and targeted for automated exfiltration and credential theft."
    },
    27017: {
        "name": "MongoDB",
        "score": 95,
        "severity": "CRITICAL",
        "description": "Port 27017 (MongoDB) is publicly exposed. MongoDB instances without network isolation are prime targets for automated ransomware wiping and data extortion."
    },
    6379: {
        "name": "Redis",
        "score": 95,
        "severity": "CRITICAL",
        "description": "Port 6379 (Redis) is open to the internet. Redis typically runs without authentication or TLS by default and can be leveraged for remote code execution."
    },
    9200: {
        "name": "Elasticsearch",
        "score": 90,
        "severity": "CRITICAL",
        "description": "Port 9200 (Elasticsearch REST API) is exposed to 0.0.0.0/0, risking unauthorized cluster takeover and bulk data exfiltration."
    },
    21: {
        "name": "FTP",
        "score": 80,
        "severity": "HIGH",
        "description": "Port 21 (FTP) is open to the internet. FTP transmits credentials and files in clear text and is vulnerable to interception."
    },
    23: {
        "name": "Telnet",
        "score": 85,
        "severity": "CRITICAL",
        "description": "Port 23 (Telnet) transmits unencrypted passwords and commands across the public internet."
    },
    80: {
        "name": "HTTP",
        "score": 50,
        "severity": "MEDIUM",
        "description": "Port 80 (HTTP) is open to the internet without encryption. Web traffic should be redirected to HTTPS (443)."
    },
    443: {
        "name": "HTTPS",
        "score": 35,
        "severity": "LOW",
        "description": "Port 443 (HTTPS) is open to the internet. Standard for public web services, but ensure backend application is patched."
    }
}


class FindingEngine:
    """
    Analyzes scanned cloud infrastructure, detects exposed ports/ingress rules,
    calculates context-aware risk scores, generates unique SecurityFindings, and signs
    tamper-proof remediation tokens for the Secure Now workflow.
    """

    @staticmethod
    def get_signing_secret() -> str:
        return os.environ.get("REMEDIATION_SIGNING_SECRET", DEFAULT_SIGNING_SECRET)

    @staticmethod
    def get_api_gateway_url() -> str:
        # Default placeholder or environment configured API Gateway endpoint
        return os.environ.get("API_GATEWAY_URL", "https://api.cloudnet-sentinel.local/prod").rstrip("/")

    @classmethod
    def create_remediation_token(cls, payload: Dict[str, Any], secret: Optional[str] = None, expires_in_seconds: int = 259200) -> str:
        """
        Creates a tamper-proof URL-safe remediation token signed with HMAC-SHA256.
        Token is valid for 72 hours (259200 seconds) by default.
        Format: <base64_payload>.<signature_hex>
        """
        signing_secret = secret or cls.get_signing_secret()
        token_payload = dict(payload)
        now = int(time.time())
        token_payload["iat"] = now
        token_payload["exp"] = now + expires_in_seconds

        serialized = json.dumps(token_payload, sort_keys=True, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(serialized.encode('utf-8')).decode('utf-8').rstrip('=')

        signature = hmac.new(
            signing_secret.encode('utf-8'),
            payload_b64.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return f"{payload_b64}.{signature}"

    @classmethod
    def verify_remediation_token(cls, token: str, secret: Optional[str] = None) -> Dict[str, Any]:
        """
        Verifies the HMAC-SHA256 signature and expiration of a remediation token.
        Returns the decoded payload if valid, otherwise raises ValueError.
        """
        signing_secret = secret or cls.get_signing_secret()
        if not token or '.' not in token:
            raise ValueError("Invalid token format: Token must contain payload and signature separated by '.'")

        payload_b64, signature = token.rsplit('.', 1)

        expected_sig = hmac.new(
            signing_secret.encode('utf-8'),
            payload_b64.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            raise ValueError("Token signature validation failed: Token has been tampered with or secret mismatch")

        # Decode base64 payload
        padding = '=' * (-len(payload_b64) % 4)
        try:
            raw_json = base64.urlsafe_b64decode(payload_b64 + padding).decode('utf-8')
            payload = json.loads(raw_json)
        except Exception as e:
            raise ValueError(f"Corrupt token payload: {e}")

        # Check expiration
        now = int(time.time())
        if "exp" in payload and now > payload["exp"]:
            raise ValueError(f"Remediation token has expired (expired at {payload['exp']}, current time is {now})")

        return payload

    @classmethod
    def generate_findings(cls, scan_results: Dict[str, Any], account_id: str = "AWS-ACCOUNT", region: str = "us-east-1") -> List[Dict[str, Any]]:
        """
        Processes scan_results (containing EC2, SGs, etc.), correlates exposed instances
        with insecure ingress rules, and produces structured security findings.
        """
        findings = []
        ec2_list = scan_results.get("ec2", [])
        sg_list = scan_results.get("sgs", []) or scan_results.get("security_groups", [])

        # Index EC2 by security group for quick correlation
        sg_to_instances: Dict[str, List[Dict[str, Any]]] = {}
        for ec2 in ec2_list:
            for sg_id in ec2.get("security_groups", []):
                sg_to_instances.setdefault(sg_id, []).append(ec2)

        api_gateway_url = cls.get_api_gateway_url()

        for sg in sg_list:
            sg_id = sg.get("id")
            sg_name = sg.get("name", sg_id)
            insecure_rules = sg.get("insecure_rules", [])

            # If sg_scanner hasn't parsed insecure_rules yet (fallback for legacy dicts)
            if not insecure_rules and sg.get("is_open"):
                insecure_rules = [{
                    "protocol": "-1",
                    "from_port": None,
                    "to_port": None,
                    "cidr": "0.0.0.0/0",
                    "description": "Legacy permissive rule"
                }]

            associated_instances = sg_to_instances.get(sg_id, [])
            instance_ids = [inst.get("id") for inst in associated_instances]
            has_public_instance = any(inst.get("is_public") for inst in associated_instances)

            for rule in insecure_rules:
                protocol = str(rule.get("protocol", "-1")).lower()
                from_port = rule.get("from_port")
                to_port = rule.get("to_port")
                cidr = rule.get("cidr", "0.0.0.0/0")

                # Generate a deterministic unique ID for this finding
                rule_key = f"{account_id}-{region}-{sg_id}-{protocol}-{from_port}-{to_port}-{cidr}"
                unique_hash = hashlib.sha256(rule_key.encode('utf-8')).hexdigest()[:10]
                finding_id = f"cns-fnd-{unique_hash}"

                # Calculate Risk & Severity
                risk_info = cls._calculate_rule_risk(protocol, from_port, to_port, cidr, has_public_instance)

                # Format human readable port representation
                port_str = cls._format_port(protocol, from_port, to_port)

                # Finding description & recommended action
                primary_resource = instance_ids[0] if instance_ids else sg_id
                resource_type = "EC2 Instance" if instance_ids else "Security Group"
                
                description = (
                    f"Security Group '{sg_name}' ({sg_id}) attached to {resource_type} {primary_resource} "
                    f"has port {port_str} exposed to the world ({cidr}). "
                    f"{risk_info['reason']}"
                )

                recommended_action = (
                    f"Revoke ingress rule allowing {protocol.upper()} traffic on {port_str} "
                    f"from {cidr} in Security Group {sg_id}."
                )

                # Build remediation payload for HMAC signing
                remediation_payload = {
                    "finding_id": finding_id,
                    "account_id": account_id,
                    "region": region,
                    "resource_id": primary_resource,
                    "resource_type": resource_type,
                    "security_group_id": sg_id,
                    "security_group_name": sg_name,
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "source_cidr": cidr,
                    "action": "revoke_security_group_ingress"
                }

                token = cls.create_remediation_token(remediation_payload)
                secure_url = f"{api_gateway_url}/secure?finding_id={finding_id}&token={token}"

                finding = {
                    "finding_id": finding_id,
                    "account_id": account_id,
                    "region": region,
                    "resource_id": primary_resource,
                    "resource_type": resource_type,
                    "instance_ids": instance_ids,
                    "security_group_id": sg_id,
                    "security_group_name": sg_name,
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "port_display": port_str,
                    "source_cidr": cidr,
                    "risk_score": risk_info["score"],
                    "severity": risk_info["severity"],
                    "service_name": risk_info["service_name"],
                    "description": description,
                    "recommended_action": recommended_action,
                    "remediation_payload": remediation_payload,
                    "secure_token": token,
                    "secure_url": secure_url,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }

                findings.append(finding)

        # Sort findings by risk score descending
        findings.sort(key=lambda x: x["risk_score"], reverse=True)
        return findings

    @staticmethod
    def _format_port(protocol: str, from_port: Optional[int], to_port: Optional[int]) -> str:
        if protocol == '-1' or (from_port is None and to_port is None):
            return "ALL PORTS"
        if from_port == to_port:
            return str(from_port)
        return f"{from_port}-{to_port}"

    @staticmethod
    def _calculate_rule_risk(protocol: str, from_port: Optional[int], to_port: Optional[int], cidr: str, has_public_instance: bool) -> Dict[str, Any]:
        # If all traffic is allowed
        if protocol == '-1' or (from_port is None and to_port is None):
            score = 98 if has_public_instance else 88
            return {
                "score": score,
                "severity": "CRITICAL",
                "service_name": "ALL TRAFFIC",
                "reason": "Allows unrestricted inbound traffic on all protocols and ports from the entire internet."
            }

        # Check single port known risks
        if from_port is not None and from_port == to_port and from_port in KNOWN_PORT_RISKS:
            info = KNOWN_PORT_RISKS[from_port]
            base_score = info["score"]
            # Boost score if attached to an actively running public EC2
            adjusted_score = min(100, base_score + (10 if has_public_instance else 0))
            return {
                "score": adjusted_score,
                "severity": info["severity"],
                "service_name": info["name"],
                "reason": info["description"]
            }

        # Check port range covering known sensitive ports
        if from_port is not None and to_port is not None:
            for sensitive_port, info in KNOWN_PORT_RISKS.items():
                if from_port <= sensitive_port <= to_port:
                    base_score = info["score"]
                    adjusted_score = min(100, base_score + (10 if has_public_instance else 0))
                    return {
                        "score": adjusted_score,
                        "severity": info["severity"],
                        "service_name": f"{info['name']} (in range {from_port}-{to_port})",
                        "reason": f"Port range includes sensitive service {info['name']} (Port {sensitive_port}) exposed to {cidr}."
                    }

        # Generic open port
        score = 75 if has_public_instance else 60
        severity = "HIGH" if score >= 70 else "MEDIUM"
        return {
            "score": score,
            "severity": severity,
            "service_name": f"{protocol.upper()}/{from_port}",
            "reason": f"Inbound {protocol.upper()} rule is reachable from any IP address ({cidr})."
        }
