import argparse
import boto3
import json
import os
from scanner.ec2_scanner import scan_ec2
from scanner.iam_scanner import scan_iam
from scanner.s3_scanner import scan_s3
from scanner.sg_scanner import scan_security_groups
from engine.graph_engine import GraphEngine
from engine.attack_path_engine import AttackPathEngine
from engine.risk_engine import RiskEngine
from engine.cost_engine import CostEngine
from engine.fix_engine import FixEngine
from engine.finding_engine import FindingEngine
from services.alert_notifier import AlertNotifier

def main():
    parser = argparse.ArgumentParser(description="CloudNet Sentinel CLI")
    parser.add_argument("--access-key", help="AWS Access Key")
    parser.add_argument("--secret-key", help="AWS Secret Key")
    parser.add_argument("--region", default="us-east-1", help="AWS Region")
    parser.add_argument("--alert", action="store_true", help="Dispatch security alert emails via Amazon SNS for detected exposures")
    parser.add_argument("--output-json", help="Path to write findings JSON output")
    args = parser.parse_args()

    # Use environment variables if CLI args are missing
    access_key = args.access_key or os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = args.secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")
    region = args.region

    if not access_key or not secret_key:
        print("Error: AWS Credentials required (via --access-key/--secret-key or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY).")
        return

    print("==================================================")
    print("           CloudNet Sentinel Security Scan        ")
    print("==================================================")
    print(f"Region: {region}")
    
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

    # Get Account ID from STS if possible
    account_id = "AWS-ACCOUNT"
    try:
        sts = session.client("sts")
        account_id = sts.get_caller_identity().get("Account", "AWS-ACCOUNT")
        print(f"AWS Account ID: {account_id}")
    except Exception:
        pass

    print("\n[1/5] Scanning EC2 Instances...")
    ec2_data = scan_ec2(session)
    print(f"  Found {len(ec2_data)} EC2 instances")

    print("[2/5] Scanning Security Groups...")
    sg_data = scan_security_groups(session)
    print(f"  Found {len(sg_data)} Security Groups")

    print("[3/5] Scanning IAM Roles & Users...")
    iam_data = scan_iam(session)
    print(f"  Found {len(iam_data)} IAM identities")

    print("[4/5] Scanning S3 Buckets...")
    s3_data = scan_s3(session)
    print(f"  Found {len(s3_data)} S3 buckets")

    scan_results = {
        "ec2": ec2_data,
        "sgs": sg_data,
        "security_groups": sg_data,
        "iam": iam_data,
        "s3": s3_data
    }

    print("\n[5/5] Building Attack Graph & Analyzing Attack Paths...")
    ge = GraphEngine()
    graph_obj = ge.build_graph(scan_results)
    graph = graph_obj.get("graph") if isinstance(graph_obj, dict) else graph_obj

    ape = AttackPathEngine(graph_obj)
    path_data = ape.find_attack_paths()
    paths = path_data.get("paths", []) if isinstance(path_data, dict) else path_data

    print(f"\nDiscovered {len(paths)} Multi-step Attack Path(s):")
    for p in paths:
        path = p if isinstance(p, list) else p.get('path', [])
        risk = RiskEngine.calculate_risk(path, graph)
        print(f"\n  Path: {' -> '.join(path)}")
        print(f"  Risk Score: {risk['score']} ({risk['severity']})")

    # Generate Granular Security Findings & Secure Now Remediation Tokens
    print("\n==================================================")
    print("       SECURITY FINDINGS & AUTOMATED REMEDIATION  ")
    print("==================================================")
    findings = FindingEngine.generate_findings(scan_results, account_id=account_id)
    print(f"Identified {len(findings)} Insecure Ingress Rule Finding(s):\n")

    for idx, f in enumerate(findings, 1):
        print(f"Finding #{idx}: [{f['severity']}] {f['resource_type']} {f['resource_id']}")
        print(f"  Finding ID     : {f['finding_id']}")
        print(f"  Security Group : {f['security_group_name']} ({f['security_group_id']})")
        print(f"  Port & Protocol: {f['port_display']} ({f['protocol'].upper()}) - {f['service_name']}")
        print(f"  Source CIDR    : {f['source_cidr']}")
        print(f"  Risk Score     : {f['risk_score']}/100")
        print(f"  Description    : {f['description']}")
        print(f"  Action         : {f['recommended_action']}")
        print(f"  SECURE NOW URL : {f['secure_url']}")
        print("-" * 50)

        # Dispatch Alert if requested
        if args.alert or os.getenv("SNS_TOPIC_ARN"):
            alert_res = AlertNotifier.send_alert(f, session=session)
            print(f"  Alert Status   : {alert_res.get('status')} via {alert_res.get('channel')}")
            print("-" * 50)

    # Save to JSON if requested
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as jf:
            json.dump(findings, jf, indent=2)
        print(f"\nFindings written to {args.output_json}")

    print("\nScan & Remediation Generation Complete.")


if __name__ == "__main__":
    main()
