#!/usr/bin/env python3
"""
CloudNet Sentinel - Automated Remediation Deployment Helper
Packages the Lambda code, validates configuration, and deploys or updates the CloudFormation stack.
"""
import os
import sys
import zipfile
import io
import argparse
import boto3
from botocore.exceptions import ClientError


def package_lambda_zip() -> bytes:
    """
    Creates an in-memory zip file containing remediation/lambda_function.py.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    lambda_file = os.path.join(base_dir, "lambda_function.py")

    if not os.path.exists(lambda_file):
        raise FileNotFoundError(f"Cannot find lambda_function.py at {lambda_file}")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(lambda_file, arcname="lambda_function.py")
    buf.seek(0)
    return buf.getvalue()


def deploy_stack(region: str, stack_name: str, email: str, secret: str, update_code: bool = True):
    print(f"Deploying CloudNet Sentinel Remediation Infrastructure to AWS region: {region}")
    session = boto3.Session(region_name=region)
    cfn = session.client("cloudformation")
    lambda_client = session.client("lambda")

    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cloudformation.yaml")
    with open(template_path, "r", encoding="utf-8") as f:
        template_body = f.read()

    parameters = [
        {"ParameterKey": "RemediationSigningSecret", "ParameterValue": secret},
        {"ParameterKey": "AlertEmailAddress", "ParameterValue": email}
    ]

    try:
        # Check if stack exists
        try:
            cfn.describe_stacks(StackName=stack_name)
            exists = True
        except ClientError:
            exists = False

        if not exists:
            print(f"Creating new CloudFormation stack '{stack_name}'...")
            cfn.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Parameters=parameters,
                Capabilities=["CAPABILITY_NAMED_IAM"]
            )
            print("Stack creation initiated. Waiting for CREATE_COMPLETE...")
            waiter = cfn.get_waiter("stack_create_complete")
            waiter.wait(StackName=stack_name)
            print("Stack created successfully!")
        else:
            print(f"Stack '{stack_name}' already exists. Updating...")
            try:
                cfn.update_stack(
                    StackName=stack_name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=["CAPABILITY_NAMED_IAM"]
                )
                print("Waiting for UPDATE_COMPLETE...")
                waiter = cfn.get_waiter("stack_update_complete")
                waiter.wait(StackName=stack_name)
                print("Stack updated successfully!")
            except ClientError as e:
                if "No updates are to be performed" in str(e):
                    print("No template changes detected.")
                else:
                    raise

        # Push actual Lambda zip code
        if update_code:
            print("Uploading packaged remediation lambda code...")
            zip_bytes = package_lambda_zip()
            lambda_client.update_function_code(
                FunctionName="CloudNetSentinelRemediation",
                ZipFile=zip_bytes
            )
            print("Lambda function code updated successfully!")

        # Retrieve outputs
        desc = cfn.describe_stacks(StackName=stack_name)
        outputs = {o["OutputKey"]: o["OutputValue"] for o in desc["Stacks"][0].get("Outputs", [])}

        print("\n" + "=" * 60)
        print("DEPLOYMENT COMPLETE - CONFIGURATION VALUES")
        print("=" * 60)
        print(f"API_GATEWAY_URL : {outputs.get('ApiGatewayUrl')}")
        print(f"SNS_TOPIC_ARN   : {outputs.get('SnsTopicArn')}")
        print(f"SECURE_ENDPOINT : {outputs.get('SecureNowEndpoint')}")
        print(f"REMEDIATION_SIGNING_SECRET : {secret}")
        print("=" * 60)
        print("\nAdd these variables to your environment or .env file before running scans:")
        print(f"export API_GATEWAY_URL=\"{outputs.get('ApiGatewayUrl')}\"")
        print(f"export SNS_TOPIC_ARN=\"{outputs.get('SnsTopicArn')}\"")
        print(f"export REMEDIATION_SIGNING_SECRET=\"{secret}\"")
        if email:
            print(f"\nIMPORTANT: Check '{email}' and click the AWS SNS Subscription Confirmation link!")

    except Exception as e:
        print(f"Deployment error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="CloudNet Sentinel Automated Remediation Deployer")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"), help="AWS Region")
    parser.add_argument("--stack-name", default="CloudNetSentinelRemediationStack", help="CloudFormation Stack Name")
    parser.add_argument("--email", default="", help="Email address to receive security alert emails")
    parser.add_argument("--secret", default=os.environ.get("REMEDIATION_SIGNING_SECRET", "cloudnet-sentinel-default-remediation-secret-2026"), help="HMAC Signing Secret")
    parser.add_argument("--package-only", action="store_true", help="Only build lambda.zip package without deploying to AWS")
    args = parser.parse_args()

    if args.package_only:
        zip_bytes = package_lambda_zip()
        output_zip = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lambda_package.zip")
        with open(output_zip, "wb") as f:
            f.write(zip_bytes)
        print(f"Packaged Lambda code written to: {output_zip}")
        return

    deploy_stack(args.region, args.stack_name, args.email, args.secret)


if __name__ == "__main__":
    main()
