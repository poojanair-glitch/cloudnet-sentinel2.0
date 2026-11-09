from flask import Flask, render_template, request, redirect, url_for, jsonify, session as flask_session
import boto3
import threading

from scanner.ec2_scanner import scan_ec2
from scanner.iam_scanner import scan_iam
from scanner.s3_scanner import scan_s3
from scanner.sg_scanner import scan_security_groups

from engine.graph_engine import GraphEngine
from engine.attack_path_engine import AttackPathEngine
from engine.explanation_engine import ExplanationEngine
from engine.asset_intelligence_engine import AssetIntelligenceEngine
from engine.cost_engine import CostEngine
from engine.finding_engine import FindingEngine
from services.alert_notifier import AlertNotifier

from realtime.event_simulator import EventSimulator
from realtime.correlation_engine import CorrelationEngine


app = Flask(__name__)
app.secret_key = 'super-secret-key-cloudnet'

# Global state for simulation (in-memory)
SIMULATION_DATA = {
    "events": [],
    "graph": None,
    "attack_paths": []
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login-screen')
def login_screen():
    return render_template('login.html')

@app.route('/signup-screen')
def signup_screen():
    return render_template('signup.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        return redirect(url_for('login_screen'))
    return render_template('signup.html')

def get_boto_session():
    """Returns a boto3.Session using Flask session credentials or host AWS profile."""
    ak = flask_session.get('aws_ak')
    sk = flask_session.get('aws_sk')
    token = flask_session.get('aws_token')
    region = flask_session.get('region', 'us-east-1')

    if ak and sk:
        return boto3.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            aws_session_token=token,
            region_name=region
        )
    return boto3.Session(region_name=region)


@app.route('/connect-real-aws', methods=['GET', 'POST'])
def connect_real_aws():
    """Connects directly using the active AWS credentials configured on the machine."""
    region = request.args.get('region') or (request.form.get('region') if request.method == 'POST' else None) or 'us-east-1'
    try:
        sess = boto3.Session(region_name=region)
        creds = sess.get_credentials()
        if creds:
            frozen = creds.get_frozen_credentials()
            flask_session['aws_ak'] = frozen.access_key
            flask_session['aws_sk'] = frozen.secret_key
            if frozen.token:
                flask_session['aws_token'] = frozen.token
            flask_session['region'] = region
            return redirect(url_for('dashboard', region=region))
    except Exception as e:
        return f"Failed to connect using host AWS credentials: {e}", 400
    return redirect(url_for('login_screen'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ak = (request.form.get('access_key') or '').strip()
        sk = (request.form.get('secret_key') or '').strip()
        region = (request.form.get('region') or 'us-east-1').strip()
        
        if ak and sk:
            flask_session['aws_ak'] = ak
            flask_session['aws_sk'] = sk
            flask_session['region'] = region
            return redirect(url_for('dashboard', region=region))
        else:
            # Connect automatically with host credentials if left blank
            return redirect(url_for('connect_real_aws', region=region))
    return redirect(url_for('login_screen'))


@app.route('/dashboard')
def dashboard():
    # If no keys in Flask session, auto-authenticate with host AWS credentials
    if 'aws_ak' not in flask_session:
        try:
            sess = boto3.Session()
            creds = sess.get_credentials()
            if creds:
                frozen = creds.get_frozen_credentials()
                flask_session['aws_ak'] = frozen.access_key
                flask_session['aws_sk'] = frozen.secret_key
                if frozen.token:
                    flask_session['aws_token'] = frozen.token
                if 'region' not in flask_session:
                    flask_session['region'] = 'us-east-1'
        except Exception:
            pass

    if 'aws_ak' not in flask_session:
        return redirect(url_for('login_screen'))
    
    if request.args.get('region'):
        flask_session['region'] = request.args.get('region')
    elif 'region' not in flask_session:
        flask_session['region'] = 'us-east-1'

    simulate_iam = request.args.get('simulate_iam') == 'true'
    boto_session = get_boto_session()
    current_region = flask_session.get('region', 'us-east-1')

    try:
        ec2_client = boto_session.client('ec2')
        scan_results = {
            "ec2": scan_ec2(boto_session),
            "iam": scan_iam(boto_session),
            "s3": scan_s3(boto_session),
            "vpcs": ec2_client.describe_vpcs()['Vpcs'],
            "subnets": ec2_client.describe_subnets()['Subnets'],
            "sgs": scan_security_groups(boto_session)
        }
    except Exception as aws_err:
        print(f"[CloudNet Sentinel] AWS scan failed ({aws_err}). Falling back to Demo/Simulation Mode.")
        scan_results = {
            "ec2": [
                {
                    "id": "i-0a1b2c3d4e5f67890",
                    "type": "EC2",
                    "name": "web-prod-server",
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
                            "description": "Public SSH port 22 open to 0.0.0.0/0"
                        },
                        {
                            "protocol": "tcp",
                            "from_port": 3389,
                            "to_port": 3389,
                            "cidr": "0.0.0.0/0",
                            "description": "Public RDP port 3389 open to 0.0.0.0/0"
                        }
                    ]
                }
            ],
            "vpcs": [{"VpcId": "vpc-0123456789abcdef0", "CidrBlock": "10.0.0.0/16"}],
            "subnets": [{"SubnetId": "subnet-0123456789abcdef0", "CidrBlock": "10.0.1.0/24"}],
            "iam": [{"id": "arn:aws:iam::123456789012:role/AdminRole", "type": "IAM", "name": "AdminRole"}],
            "s3": [{"id": "cloudnet-sec-logs-bucket", "type": "S3", "name": "cloudnet-sec-logs-bucket"}]
        }
    
    # Linear Pipeline (Unified Flow)
    ge = GraphEngine()
    graph_obj = ge.build_graph(scan_results, simulation_flags={"simulate_iam": simulate_iam})
    
    ape = AttackPathEngine()
    path_data = ape.find_attack_paths(graph_obj)
    
    ee = ExplanationEngine()
    explanations = ee.generate_explanations(graph_obj, path_data)
    
    ce = CostEngine()
    cost = ce.generate_cost_analysis(boto_session, path_data, graph_obj)

    aie = AssetIntelligenceEngine()
    assets = aie.map_assets_to_attack_graph(graph_obj, scan_results, path_data)

    # Detect Real Insecure Ports and Generate Security Findings for Real AWS Account
    account_id = "826917685155"
    iam_user = "cloudnet-user"
    try:
        sts = boto_session.client('sts')
        caller = sts.get_caller_identity()
        account_id = caller.get('Account', account_id)
        arn = caller.get('Arn', '')
        if '/' in arn:
            iam_user = arn.split('/')[-1]
    except Exception:
        pass

    findings = FindingEngine.generate_findings(scan_results, account_id=account_id, region=current_region)
    
    # Save for background sim and alert endpoints
    SIMULATION_DATA["graph"] = graph_obj["graph"]
    SIMULATION_DATA["attack_paths"] = path_data['paths']
    SIMULATION_DATA["findings"] = findings
    
    # Remove non-serializable DiGraph object before passing to template
    del graph_obj["graph"]
    
    intelligence = {
        "graph": graph_obj,
        "attack_paths": path_data['paths'],
        "reasoning": path_data['reasoning'],
        "explanations": explanations,
        "cost": cost,
        "assets": assets,
        "findings": findings,
        "account_id": account_id,
        "iam_user": iam_user,
        "region": current_region,
        "simulation_active": simulate_iam
    }

    if not any(t.name == "SimulationThread" for t in threading.enumerate()):
        threading.Thread(target=run_simulation, name="SimulationThread", daemon=True).start()

    return render_template('dashboard.html', intelligence=intelligence)

def run_simulation():
    sim = EventSimulator()
    while True:
        if SIMULATION_DATA["graph"]:
            nodes = list(SIMULATION_DATA["graph"].nodes)
            for event in sim.simulate_events(nodes):
                ce = CorrelationEngine(SIMULATION_DATA["attack_paths"])
                correlation = ce.correlate(event)
                SIMULATION_DATA["events"].append(correlation)
                if len(SIMULATION_DATA["events"]) > 20:
                    SIMULATION_DATA["events"].pop(0)

@app.route('/api/events')
def get_events():
    return jsonify(SIMULATION_DATA["events"])

@app.route('/api/findings')
def get_findings():
    return jsonify(SIMULATION_DATA.get("findings", []))

@app.route('/api/sns/status')
def get_sns_status():
    boto_session = get_boto_session()
    topic_arn = AlertNotifier.get_sns_topic_arn()
    topic_region = topic_arn.split(":")[3] if topic_arn and ":" in topic_arn else "us-east-1"
    subscriptions = []
    try:
        sns = boto_session.client('sns', region_name=topic_region)
        resp = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
        for s in resp.get('Subscriptions', []):
            is_pending = s.get('SubscriptionArn') in ['PendingConfirmation', 'Deleted']
            subscriptions.append({
                "endpoint": s.get("Endpoint"),
                "protocol": s.get("Protocol"),
                "subscription_arn": s.get("SubscriptionArn"),
                "confirmed": not is_pending
            })
    except Exception as e:
        return jsonify({"error": str(e), "topic_arn": topic_arn}), 500

    return jsonify({
        "topic_arn": topic_arn,
        "region": topic_region,
        "subscriptions": subscriptions
    })


@app.route('/api/send-alert', methods=['POST'])
def send_alert():
    boto_session = get_boto_session()
    data = request.get_json(silent=True) or {}
    finding_id = data.get("finding_id")
    user_email = (data.get("email") or "").strip()
    findings = SIMULATION_DATA.get("findings", [])

    target_findings = [f for f in findings if f.get("finding_id") == finding_id] if finding_id else findings
    if not target_findings:
        return jsonify({"error": f"Finding '{finding_id}' not found"}), 404

    topic_arn = AlertNotifier.get_sns_topic_arn()
    topic_region = topic_arn.split(":")[3] if topic_arn and ":" in topic_arn else "us-east-1"
    subscription_status = "NOT_REQUESTED"

    # Subscribe real email to AWS SNS if supplied
    if user_email and topic_arn:
        try:
            sns_client = boto_session.client('sns', region_name=topic_region)
            sns_client.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=user_email)
            subscription_status = f"Subscribed {user_email}. Check inbox to confirm AWS SNS subscription!"
        except Exception as e:
            subscription_status = f"Subscription note: {e}"

    results = []
    for f in target_findings:
        res = AlertNotifier.send_alert(f, session=boto_session)
        results.append({"finding_id": f.get("finding_id"), "result": res})

    return jsonify({
        "status": "SUCCESS",
        "topic_arn": topic_arn,
        "subscription": subscription_status,
        "dispatched": results,
        "email": user_email
    })


@app.route('/secure', methods=['GET', 'POST'])
def secure_endpoint():
    """
    Local remediation endpoint mirroring AWS API Gateway + Lambda.
    Enables local testing of the 'Secure Now' email link.
    """
    event = {
        "httpMethod": request.method,
        "queryStringParameters": dict(request.args),
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True) if request.method == "POST" else None,
        "requestContext": {
            "http": {
                "method": request.method
            }
        }
    }
    from remediation.lambda_function import lambda_handler
    response = lambda_handler(event, None, session=get_boto_session())
    return response["body"], response["statusCode"], response.get("headers", {})

@app.route('/api/secure-all', methods=['POST'])
def secure_all():
    """
    Safely revokes ALL open/exposed ingress rules on the user's real AWS Security Groups.
    """
    boto_session = get_boto_session()
    region = flask_session.get('region', 'us-east-1')
    ec2_client = boto_session.client('ec2', region_name=region)
    findings = SIMULATION_DATA.get("findings", [])
    
    if not findings:
        sgs = scan_security_groups(boto_session)
        findings = FindingEngine.generate_findings({"sgs": sgs}, region=region)

    results = []
    from remediation.lambda_function import revoke_insecure_rule, log_audit_trail

    for f in findings:
        payload = f.get("remediation_payload", {})
        if not payload:
            continue
        try:
            status, message = revoke_insecure_rule(ec2_client, payload)
            log_audit_trail(
                finding_id=payload.get("finding_id", "UNKNOWN"),
                sg_id=payload.get("security_group_id", "UNKNOWN"),
                protocol=payload.get("protocol", "tcp"),
                port_str=str(payload.get("from_port") or "ALL"),
                cidr=payload.get("source_cidr", "0.0.0.0/0"),
                action="REVOKE_INGRESS",
                result=status
            )
            results.append({
                "finding_id": payload.get("finding_id"),
                "security_group_id": payload.get("security_group_id"),
                "security_group_name": payload.get("security_group_name"),
                "port": payload.get("from_port"),
                "protocol": payload.get("protocol"),
                "cidr": payload.get("source_cidr"),
                "status": status,
                "message": message
            })
        except Exception as e:
            results.append({
                "finding_id": payload.get("finding_id"),
                "security_group_id": payload.get("security_group_id"),
                "status": "ERROR",
                "message": str(e)
            })

    # Clear cached findings so UI refreshes to 0 insecure rules
    SIMULATION_DATA["findings"] = []

    return jsonify({
        "status": "SUCCESS",
        "total": len(findings),
        "results": results
    })

@app.route('/logout')
def logout():
    flask_session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)

