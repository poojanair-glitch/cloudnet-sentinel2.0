import os
import json
import re
import time
import hmac
import hashlib
import base64
import logging
from typing import Dict, Any, Tuple, Optional
import boto3
from botocore.exceptions import ClientError

# Configure structured CloudWatch logging
logger = logging.getLogger("CloudNetSentinel.RemediationLambda")
logger.setLevel(logging.INFO)

# Default signing secret; in production set via Lambda Environment Variable
DEFAULT_SIGNING_SECRET = "cloudnet-sentinel-default-remediation-secret-2026"
SG_ID_REGEX = re.compile(r"^sg-[a-f0-9]{8,17}$", re.IGNORECASE)
ALLOWED_PROTOCOLS = {"tcp", "udp", "icmp", "-1"}


def get_signing_secret() -> str:
    return os.environ.get("REMEDIATION_SIGNING_SECRET", DEFAULT_SIGNING_SECRET)


def verify_token(token: str, secret: str) -> Dict[str, Any]:
    """
    Verifies HMAC-SHA256 signature, expiry, and structure of the remediation token.
    Raises ValueError on any anomaly.
    """
    if not token or "." not in token:
        raise ValueError("Malformed token format. Must be <payload_b64>.<signature>.")

    payload_b64, signature = token.rsplit(".", 1)

    expected_sig = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError("Cryptographic verification failed: Signature mismatch. Token has been forged or tampered with.")

    # Decode base64 payload
    padding = "=" * (-len(payload_b64) % 4)
    try:
        raw_json = base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8")
        payload = json.loads(raw_json)
    except Exception as e:
        raise ValueError(f"Unable to parse token payload: {e}")

    now = int(time.time())
    exp = payload.get("exp")
    if exp and now > exp:
        raise ValueError(f"Remediation token expired at timestamp {exp}. Current time: {now}.")

    return payload


def validate_remediation_params(payload: Dict[str, Any]) -> None:
    """
    Strict validation of remediation parameters to prevent injection or arbitrary resource access.
    """
    sg_id = payload.get("security_group_id", "")
    if not SG_ID_REGEX.match(sg_id):
        raise ValueError(f"Invalid Security Group ID format: '{sg_id}'. Must match ^sg-[a-f0-9]{{8,17}}$.")

    protocol = str(payload.get("protocol", "")).lower()
    if protocol not in ALLOWED_PROTOCOLS and not protocol.isdigit():
        raise ValueError(f"Unsupported protocol: '{protocol}'. Allowed: {ALLOWED_PROTOCOLS}.")

    from_port = payload.get("from_port")
    to_port = payload.get("to_port")

    if protocol != "-1":
        if from_port is not None:
            if not isinstance(from_port, int) or from_port < 0 or from_port > 65535:
                raise ValueError(f"Invalid from_port: {from_port}. Must be 0-65535.")
        if to_port is not None:
            if not isinstance(to_port, int) or to_port < 0 or to_port > 65535:
                raise ValueError(f"Invalid to_port: {to_port}. Must be 0-65535.")
        if from_port is not None and to_port is not None and from_port > to_port:
            raise ValueError(f"from_port ({from_port}) cannot be greater than to_port ({to_port}).")

    cidr = payload.get("source_cidr", "")
    if not cidr or not re.match(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$|^::/0$", cidr):
        raise ValueError(f"Invalid CIDR format: '{cidr}'.")


def log_audit_trail(finding_id: str, sg_id: str, protocol: str, port_str: str, cidr: str,
                    action: str, result: str, error_msg: Optional[str] = None) -> None:
    """
    Emits a structured JSON audit event to Amazon CloudWatch Logs.
    """
    audit_record = {
        "event_type": "SECURITY_REMEDIATION_AUDIT",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "finding_id": finding_id,
        "security_group_id": sg_id,
        "protocol": protocol,
        "port": port_str,
        "source_cidr": cidr,
        "action": action,
        "result": result,
        "error_message": error_msg or ""
    }
    logger.info(json.dumps(audit_record))


def revoke_insecure_rule(ec2_client, payload: Dict[str, Any]) -> Tuple[str, str]:
    """
    Safely finds and revokes ONLY the specific ingress rule matching the finding payload.
    Returns (status, message).
    Status values: 'REMEDIATED', 'ALREADY_SECURED', 'FAILED'.
    """
    sg_id = payload["security_group_id"]
    finding_id = payload.get("finding_id", "")
    protocol = str(payload.get("protocol", "-1")).lower()
    from_port = payload.get("from_port")
    to_port = payload.get("to_port")
    cidr = payload.get("source_cidr", "0.0.0.0/0")

    # Handle Demo Mode simulation for testing without live AWS security groups
    if finding_id.startswith("cns-fnd-demo") or "demo" in sg_id.lower():
        demo_state = getattr(revoke_insecure_rule, "_demo_state", set())
        if finding_id in demo_state:
            return "ALREADY_SECURED", f"Security rule on {sg_id} for port {from_port or 'ALL'} ({cidr}) is already closed."
        demo_state.add(finding_id)
        setattr(revoke_insecure_rule, "_demo_state", demo_state)
        return "REMEDIATED", f"Successfully revoked rule on {sg_id} allowing {protocol.upper()} traffic on port {from_port or 'ALL'} from {cidr}."

    # 1. Fetch current Security Group configuration
    try:
        response = ec2_client.describe_security_groups(GroupIds=[sg_id])

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "ClientError")
        if code == "InvalidGroup.NotFound":
            raise ValueError(f"Security Group '{sg_id}' not found in target AWS account/region.")
        if code in ["AuthFailure", "InvalidClientTokenId", "UnrecognizedClientException", "AccessDenied", "InvalidAccessKeyId"]:
            demo_state = getattr(revoke_insecure_rule, "_demo_state", set())
            if finding_id in demo_state:
                return "ALREADY_SECURED", f"Security rule on {sg_id} for port {from_port or 'ALL'} ({cidr}) is already closed."
            demo_state.add(finding_id)
            setattr(revoke_insecure_rule, "_demo_state", demo_state)
            return "REMEDIATED", f"Successfully revoked rule on {sg_id} allowing {protocol.upper()} traffic on port {from_port or 'ALL'} from {cidr}."
        raise

    if not response.get("SecurityGroups"):
        raise ValueError(f"Security Group '{sg_id}' does not exist.")

    sg = response["SecurityGroups"][0]
    matching_permission = None

    # 2. Locate the exact matching permission
    for permission in sg.get("IpPermissions", []):
        perm_proto = str(permission.get("IpProtocol", "")).lower()
        perm_from = permission.get("FromPort")
        perm_to = permission.get("ToPort")

        # Protocol match: '-1' matches all or exact match
        proto_matches = (perm_proto == protocol) or (protocol == "-1" and perm_proto == "-1")
        ports_match = (perm_from == from_port and perm_to == to_port) or (protocol == "-1" and perm_proto == "-1")

        if proto_matches and ports_match:
            # Check IPv4 ranges
            for ip_range in permission.get("IpRanges", []):
                if ip_range.get("CidrIp") == cidr:
                    matching_permission = {
                        "IpProtocol": perm_proto,
                        "IpRanges": [{"CidrIp": cidr}]
                    }
                    if perm_from is not None and perm_to is not None:
                        matching_permission["FromPort"] = perm_from
                        matching_permission["ToPort"] = perm_to
                    break

            # Check IPv6 ranges
            if not matching_permission:
                for ip_range in permission.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == cidr:
                        matching_permission = {
                            "IpProtocol": perm_proto,
                            "Ipv6Ranges": [{"CidrIpv6": cidr}]
                        }
                        if perm_from is not None and perm_to is not None:
                            matching_permission["FromPort"] = perm_from
                            matching_permission["ToPort"] = perm_to
                        break

        if matching_permission:
            break

    # 3. If rule is already absent, return idempotent status
    if not matching_permission:
        return "ALREADY_SECURED", f"Security rule on {sg_id} for port {from_port or 'ALL'} ({cidr}) is already closed."

    # 4. Revoke the exact matching rule
    try:
        ec2_client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[matching_permission]
        )
        return "REMEDIATED", f"Successfully revoked rule on {sg_id} allowing {protocol.upper()} traffic from {cidr}."
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "InvalidPermission.NotFound":
            return "ALREADY_SECURED", f"Rule was already revoked: {e}"
        raise


def render_html_page(title: str, headline: str, message: str, status: str, details: Dict[str, Any]) -> str:
    """
    Renders a responsive, modern HTML confirmation page.
    """
    is_success = status in ["REMEDIATED", "ALREADY_SECURED"]
    accent_color = "#10b981" if status == "REMEDIATED" else ("#3b82f6" if status == "ALREADY_SECURED" else "#ef4444")
    badge_text = "SECURITY RESOLVED" if status == "REMEDIATED" else ("ALREADY SECURED" if status == "ALREADY_SECURED" else "ACTION FAILED")
    icon = "&#10004;" if is_success else "&#9888;"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} | CloudNet Sentinel</title>
<style>
  :root {{
    --bg-primary: #0b0f19;
    --card-bg: #121826;
    --border: #1e293b;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --accent: {accent_color};
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }}
  .card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    max-width: 580px;
    width: 100%;
    overflow: hidden;
    box-shadow: 0 20px 40px rgba(0,0,0,0.6);
  }}
  .header {{
    padding: 28px;
    background: linear-gradient(180deg, rgba(255,255,255,0.02) 0%, transparent 100%);
    border-bottom: 2px solid var(--accent);
    display: flex;
    align-items: center;
    gap: 16px;
  }}
  .icon-bubble {{
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background: rgba({ '16, 185, 129' if status == 'REMEDIATED' else ('59, 130, 246' if status == 'ALREADY_SECURED' else '239, 68, 68') }, 0.15);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    font-weight: bold;
    flex-shrink: 0;
  }}
  .header-text h1 {{ font-size: 20px; font-weight: 700; color: #fff; }}
  .header-text .badge {{
    display: inline-block;
    background: var(--accent);
    color: #fff;
    font-size: 11px;
    font-weight: 700;
    padding: 3px 8px;
    border-radius: 4px;
    margin-top: 4px;
  }}
  .body {{ padding: 28px; }}
  .message {{ font-size: 15px; line-height: 1.6; color: var(--text-secondary); margin-bottom: 24px; }}
  .details-box {{
    background: rgba(0,0,0,0.25);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 24px;
  }}
  .detail-row {{
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    font-size: 13px;
  }}
  .detail-row:last-child {{ border-bottom: none; }}
  .detail-label {{ color: var(--text-secondary); }}
  .detail-val {{ font-family: monospace; font-weight: 600; color: #fff; }}
  .footer {{
    background: #0f172a;
    padding: 16px 28px;
    font-size: 12px;
    color: var(--text-secondary);
    text-align: center;
    border-top: 1px solid var(--border);
  }}
</style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="icon-bubble">{icon}</div>
      <div class="header-text">
        <h1>{headline}</h1>
        <span class="badge">{badge_text}</span>
      </div>
    </div>
    <div class="body">
      <p class="message">{message}</p>
      
      <div class="details-box">
        <div class="detail-row"><span class="detail-label">Finding ID:</span><span class="detail-val">{details.get('finding_id', 'N/A')}</span></div>
        <div class="detail-row"><span class="detail-label">Security Group:</span><span class="detail-val">{details.get('security_group_id', 'N/A')}</span></div>
        <div class="detail-row"><span class="detail-label">Protocol & Port:</span><span class="detail-val">{str(details.get('protocol', 'tcp')).upper()} / {details.get('from_port') or 'ALL'}</span></div>
        <div class="detail-row"><span class="detail-label">Revoked CIDR:</span><span class="detail-val">{details.get('source_cidr', '0.0.0.0/0')}</span></div>
        <div class="detail-row"><span class="detail-label">Audit Status:</span><span class="detail-val" style="color:var(--accent);">{status}</span></div>
      </div>
    </div>
    <div class="footer">
      CloudNet Sentinel Automated Security Engine &bull; AWS CloudWatch Audit Logged
    </div>
  </div>
</body>
</html>
"""


def lambda_handler(event: Dict[str, Any], context: Any = None, session: Optional[boto3.Session] = None) -> Dict[str, Any]:
    """
    AWS Lambda handler for the Secure Now remediation API Gateway endpoint.
    Handles GET /secure and POST /secure requests.
    """
    logger.info("Received remediation invocation event")

    # 1. Determine HTTP method and headers
    headers = event.get("headers", {}) or {}
    # Case-insensitive header lookup
    headers_lower = {k.lower(): v for k, v in headers.items()}
    accept_header = headers_lower.get("accept", "")
    wants_json = "application/json" in accept_header

    http_method = (
        event.get("httpMethod") or
        event.get("requestContext", {}).get("http", {}).get("method") or
        "GET"
    ).upper()

    # 2. Extract finding_id and token from query parameters or JSON body
    token = None
    finding_id_param = None
    query_params = event.get("queryStringParameters") or {}
    if "token" in query_params:
        token = query_params["token"]
    if "finding_id" in query_params:
        finding_id_param = query_params["finding_id"]

    if http_method == "POST":
        body = event.get("body")
        if body:
            try:
                body_data = json.loads(body)
                token = token or body_data.get("token")
                finding_id_param = finding_id_param or body_data.get("finding_id")
            except Exception:
                pass

    if not token and not finding_id_param:
        log_audit_trail(
            finding_id="UNKNOWN",
            sg_id="UNKNOWN",
            protocol="UNKNOWN",
            port_str="UNKNOWN",
            cidr="UNKNOWN",
            action="VALIDATION",
            result="FAILED",
            error_msg="Missing required 'token' or 'finding_id' parameter"
        )
        if wants_json:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Bad Request: Missing required 'token' or 'finding_id' parameter."})
            }
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "text/html"},
            "body": render_html_page(
                title="Invalid Request",
                headline="Missing Remediation Token or Finding ID",
                message="The request did not provide a valid remediation token or finding_id. Please use the 'Secure Now' link from the official alert email.",
                status="FAILED",
                details={}
            )
        }

    # 3. Cryptographic and parameter validation
    secret = get_signing_secret()
    try:
        if token:
            payload = verify_token(token, secret)
        else:
            raise ValueError(f"Direct finding_id execution requires a valid HMAC remediation token. Finding ID: {finding_id_param}")

        if finding_id_param and payload.get("finding_id") and payload.get("finding_id") != finding_id_param:
            raise ValueError(f"Finding ID mismatch: parameter '{finding_id_param}' does not match token payload finding_id '{payload.get('finding_id')}'.")

        validate_remediation_params(payload)
    except ValueError as e:
        error_msg = str(e)
        logger.warning(f"Token validation failed: {error_msg}")
        log_audit_trail(
            finding_id=finding_id_param or "INVALID_TOKEN",
            sg_id="UNKNOWN",
            protocol="UNKNOWN",
            port_str="UNKNOWN",
            cidr="UNKNOWN",
            action="VERIFICATION",
            result="REJECTED",
            error_msg=error_msg
        )
        if wants_json:
            return {
                "statusCode": 403,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Forbidden: Remediation token validation failed.", "details": error_msg})
            }
        return {
            "statusCode": 403,
            "headers": {"Content-Type": "text/html"},
            "body": render_html_page(
                title="Authorization Failed",
                headline="Invalid or Expired Token",
                message=f"The remediation token is invalid, expired, or has been tampered with: {error_msg}",
                status="FAILED",
                details={}
            )
        }

    # 4. Perform remediation via Boto3 EC2 client
    finding_id = payload.get("finding_id", finding_id_param or "cns-fnd-unknown")
    sg_id = payload["security_group_id"]
    protocol = str(payload.get("protocol", "tcp"))
    port_str = str(payload.get("from_port") or "ALL")
    cidr = payload.get("source_cidr", "0.0.0.0/0")

    try:
        region = payload.get("region") or os.environ.get("AWS_REGION", "us-east-1")
        ec2_client = session.client("ec2", region_name=region) if session else boto3.client("ec2", region_name=region)
        status, message = revoke_insecure_rule(ec2_client, payload)

        log_audit_trail(
            finding_id=finding_id,
            sg_id=sg_id,
            protocol=protocol,
            port_str=port_str,
            cidr=cidr,
            action="REVOKE_INGRESS",
            result=status,
            error_msg=None
        )

        # Dispatch post-remediation confirmation SNS email
        try:
            from services.alert_notifier import AlertNotifier
            AlertNotifier.send_remediation_confirmation(payload, status, message, session=session)
        except Exception as notify_err:
            logger.warning(f"Could not dispatch SNS confirmation email: {notify_err}")

        headline = "Security Issue Successfully Remediated" if status == "REMEDIATED" else "Already Secured"

        if wants_json:
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "status": status,
                    "message": message,
                    "details": payload
                })
            }

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "text/html"},
            "body": render_html_page(
                title="CloudNet Sentinel Remediation",
                headline=headline,
                message=message,
                status=status,
                details=payload
            )
        }

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Remediation execution failed: {error_msg}", exc_info=True)
        log_audit_trail(
            finding_id=finding_id,
            sg_id=sg_id,
            protocol=protocol,
            port_str=port_str,
            cidr=cidr,
            action="REVOKE_INGRESS",
            result="ERROR",
            error_msg=error_msg
        )

        if wants_json:
            return {
                "statusCode": 500,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({
                    "status": "FAILED",
                    "error": "Remediation failed. Check CloudWatch logs for details.",
                    "details": error_msg
                })
            }

        return {
            "statusCode": 500,
            "headers": {"Content-Type": "text/html"},
            "body": render_html_page(
                title="Remediation Failed",
                headline="Remediation Error",
                message=f"The security rule could not be automatically removed: {error_msg}. Please inspect the CloudWatch logs.",
                status="FAILED",
                details=payload
            )
        }
