import os
import json
import logging
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("CloudNetSentinel.Notifier")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


class AlertNotifier:
    """
    Handles formatting and dispatching security alert notifications
    via Amazon SNS with clear technical risk context and a 'SECURE NOW' CTA.
    """

    @staticmethod
    def get_sns_topic_arn() -> Optional[str]:
        return os.environ.get("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:826917685155:CloudNetSentinelAlerts")


    @classmethod
    def build_email_content(cls, finding: Dict[str, Any]) -> Dict[str, str]:
        """
        Builds both rich HTML and Plain Text email representations of the finding.
        """
        severity = finding.get("severity", "HIGH")
        risk_score = finding.get("risk_score", 0)
        finding_id = finding.get("finding_id", "N/A")
        resource_id = finding.get("resource_id", "N/A")
        resource_type = finding.get("resource_type", "Resource")
        sg_id = finding.get("security_group_id", "N/A")
        sg_name = finding.get("security_group_name", sg_id)
        port_display = finding.get("port_display", "ALL")
        protocol = str(finding.get("protocol", "tcp")).upper()
        source_cidr = finding.get("source_cidr", "0.0.0.0/0")
        service_name = finding.get("service_name", "Network Service")
        description = finding.get("description", "Exposed ingress port detected.")
        recommended_action = finding.get("recommended_action", "Revoke rule.")
        secure_url = finding.get("secure_url", "#")

        # Color scheme based on severity
        sev_color = "#e53e3e" if severity in ["CRITICAL", "HIGH"] else ("#dd6b20" if severity == "MEDIUM" else "#38a169")

        subject = f"[CloudNet Sentinel ALERT] [{severity}] Insecure Exposure on {resource_id} (Port {port_display})"

        plain_text = f"""================================================================================
CLOUDNET SENTINEL | SECURITY ALERT & AUTOMATED REMEDIATION
================================================================================

ALERT: Insecure Ingress Rule Detected
SEVERITY: {severity} (Risk Score: {risk_score}/100)
FINDING ID: {finding_id}

AFFECTED INFRASTRUCTURE:
------------------------
- Resource Affected : {resource_type} ({resource_id})
- Security Group    : {sg_name} ({sg_id})
- Protocol          : {protocol}
- Port Exposed      : {port_display} ({service_name})
- Source IP / CIDR  : {source_cidr} (WORLD ACCESSIBLE)

WHY IS THIS RISKY?
-------------------
{description}

RECOMMENDED ACTION:
-------------------
{recommended_action}

AUTOMATED REMEDIATION:
----------------------
Click the link below to authorize CloudNet Sentinel to immediately revoke
this vulnerable ingress rule via AWS API Gateway and Lambda:

[ SECURE NOW ]: {secure_url}

Note: This link is cryptographically signed and valid for 72 hours.
CloudNet Sentinel will verify rule existence and close only this specific ingress rule.
================================================================================
"""

        html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; margin: 0; padding: 24px; }}
  .container {{ max-width: 620px; margin: 0 auto; background-color: #121826; border-radius: 8px; border: 1px solid #1e293b; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
  .header {{ background-color: #0f172a; padding: 20px 28px; border-bottom: 2px solid {sev_color}; display: flex; align-items: center; justify-content: space-between; }}
  .brand {{ font-size: 18px; font-weight: 700; color: #ffffff; letter-spacing: 0.5px; }}
  .brand span {{ color: #38bdf8; }}
  .badge {{ background-color: {sev_color}; color: #ffffff; padding: 5px 12px; font-size: 12px; font-weight: 700; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .content {{ padding: 28px; }}
  h2 {{ margin-top: 0; font-size: 20px; color: #f8fafc; font-weight: 600; }}
  .score-badge {{ font-size: 14px; color: #94a3b8; margin-bottom: 20px; }}
  .score-badge strong {{ color: {sev_color}; font-size: 18px; }}
  .table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 13px; }}
  .table th, .table td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #1e293b; }}
  .table th {{ color: #94a3b8; font-weight: 500; width: 38%; }}
  .table td {{ color: #f1f5f9; font-weight: 600; }}
  .risk-box {{ background-color: rgba(229, 62, 62, 0.08); border-left: 4px solid {sev_color}; padding: 14px 16px; margin-bottom: 24px; border-radius: 0 4px 4px 0; }}
  .risk-box p {{ margin: 0; font-size: 13px; line-height: 1.6; color: #cbd5e1; }}
  .risk-title {{ font-size: 12px; font-weight: 700; color: {sev_color}; text-transform: uppercase; margin-bottom: 6px; }}
  .cta-section {{ text-align: center; padding: 24px 0 16px 0; border-top: 1px solid #1e293b; }}
  .btn-secure {{ display: inline-block; background-color: #2563eb; color: #ffffff !important; padding: 14px 32px; font-size: 15px; font-weight: 700; text-decoration: none; border-radius: 6px; letter-spacing: 0.5px; box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4); }}
  .btn-secure:hover {{ background-color: #1d4ed8; }}
  .footer {{ background-color: #0f172a; padding: 16px 28px; font-size: 11px; color: #64748b; text-align: center; border-top: 1px solid #1e293b; }}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">CloudNet <span>Sentinel</span></div>
      <div class="badge">{severity} PRIORITY</div>
    </div>
    <div class="content">
      <h2>Insecure Exposed Port Detected</h2>
      <div class="score-badge">Calculated Risk Score: <strong>{risk_score}/100</strong> &bull; Finding ID: <code>{finding_id}</code></div>
      
      <table class="table">
        <tr><th>Affected Resource</th><td>{resource_type} ({resource_id})</td></tr>
        <tr><th>Security Group</th><td>{sg_name} (<code>{sg_id}</code>)</td></tr>
        <tr><th>Exposed Port & Protocol</th><td>{port_display} ({protocol}) - {service_name}</td></tr>
        <tr><th>Source CIDR</th><td><code>{source_cidr}</code> (Public Internet)</td></tr>
      </table>

      <div class="risk-box">
        <div class="risk-title">Technical Risk Analysis</div>
        <p>{description}</p>
      </div>

      <div class="risk-box" style="background-color: rgba(37, 99, 235, 0.08); border-left-color: #3b82f6;">
        <div class="risk-title" style="color: #60a5fa;">Recommended Remediation</div>
        <p>{recommended_action}</p>
      </div>

      <div class="cta-section">
        <a href="{secure_url}" class="btn-secure" target="_blank">&nbsp;&nbsp;&bull; SECURE NOW &bull;&nbsp;&nbsp;</a>
        <p style="font-size: 11px; color: #64748b; margin-top: 12px;">
          Clicking "Secure Now" invokes the CloudNet Sentinel remediation API to safely remove only this specific ingress rule.
        </p>
      </div>
    </div>
    <div class="footer">
      CloudNet Sentinel Automated Security Engine &bull; Cryptographically Verified Remediation Request
    </div>
  </div>
</body>
</html>
"""
        return {
            "subject": subject,
            "plain_text": plain_text,
            "html": html_body
        }

    @classmethod
    def send_alert(cls, finding: Dict[str, Any], session: Optional[boto3.Session] = None) -> Dict[str, Any]:
        """
        Sends an alert email for a finding. If SNS_TOPIC_ARN is configured, publishes via Amazon SNS.
        Otherwise, records the preview and logs to stdout for local testing.
        """
        content = cls.build_email_content(finding)
        topic_arn = cls.get_sns_topic_arn()

        if topic_arn:
            try:
                topic_region = topic_arn.split(":")[3] if topic_arn and ":" in topic_arn else "us-east-1"
                sns_client = session.client("sns", region_name=topic_region) if session else boto3.client("sns", region_name=topic_region)
                response = sns_client.publish(
                    TopicArn=topic_arn,
                    Subject=content["subject"][:100],  # SNS subjects capped at 100 chars
                    Message=content["plain_text"]
                )
                message_id = response.get("MessageId")
                logger.info(f"Published SNS alert for finding {finding.get('finding_id')}: MessageId {message_id}")
                return {
                    "status": "SENT",
                    "channel": "SNS",
                    "message_id": message_id,
                    "topic_arn": topic_arn,
                    "subject": content["subject"],
                    "secure_url": finding.get("secure_url")
                }
            except ClientError as e:
                logger.error(f"Failed to publish SNS alert: {e}")
                return {
                    "status": "FAILED",
                    "channel": "SNS",
                    "error": str(e),
                    "secure_url": finding.get("secure_url")
                }

        # Local development / dry run mode
        logger.info(f"[LOCAL PREVIEW] Alert generated for finding {finding.get('finding_id')}")
        logger.info(f"Subject: {content['subject']}")
        logger.info(f"Remediation URL: {finding.get('secure_url')}")

        return {
            "status": "LOCAL_PREVIEW",
            "channel": "LOG",
            "subject": content["subject"],
            "secure_url": finding.get("secure_url"),
            "content": content
        }

    @classmethod
    def send_remediation_confirmation(cls, details: Dict[str, Any], status: str, message: str, session: Optional[boto3.Session] = None) -> Dict[str, Any]:
        """
        Sends post-remediation confirmation or failure email via Amazon SNS.
        """
        topic_arn = cls.get_sns_topic_arn()
        finding_id = details.get("finding_id", "N/A")
        sg_id = details.get("security_group_id") or details.get("resource_id", "N/A")
        port = details.get("from_port") or details.get("port") or "ALL"
        cidr = details.get("source_cidr", "0.0.0.0/0")
        is_success = status in ["REMEDIATED", "ALREADY_SECURED"]

        subject = f"[CloudNet Sentinel Remediation {'SUCCESSFUL' if is_success else 'FAILED'}] {sg_id} (Port {port})"

        plain_text = f"""================================================================================
CLOUDNET SENTINEL | REMEDIATION {'CONFIRMATION' if is_success else 'FAILURE NOTICE'}
================================================================================

STATUS: {status}
FINDING ID: {finding_id}
RESOURCE / SECURITY GROUP: {sg_id}
PORT: {port}
PREVIOUS EXPOSURE: {cidr}
ACTION PERFORMED: Inbound Security Group Rule Revocation
MESSAGE: {message}

================================================================================
"""

        if topic_arn:
            try:
                topic_region = topic_arn.split(":")[3] if topic_arn and ":" in topic_arn else "us-east-1"
                sns_client = session.client("sns", region_name=topic_region) if session else boto3.client("sns", region_name=topic_region)
                response = sns_client.publish(
                    TopicArn=topic_arn,
                    Subject=subject[:100],
                    Message=plain_text
                )
                return {"status": "SENT", "message_id": response.get("MessageId")}
            except Exception as e:
                logger.error(f"Failed to publish SNS remediation confirmation: {e}")
                return {"status": "FAILED", "error": str(e)}

        logger.info(f"[LOCAL PREVIEW] Remediation confirmation generated for finding {finding_id}: {status}")
        return {"status": "LOCAL_PREVIEW", "subject": subject, "text": plain_text}

