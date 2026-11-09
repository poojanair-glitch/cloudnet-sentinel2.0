import boto3
from botocore.exceptions import ClientError

def scan_security_groups(session):
    """
    Scans security groups for permissive rules and extracts detailed rule metadata.
    """
    ec2 = session.client('ec2')
    sgs = []
    
    try:
        response = ec2.describe_security_groups()
        for sg in response['SecurityGroups']:
            is_open = False
            insecure_rules = []
            all_rules = []

            for permission in sg.get('IpPermissions', []):
                protocol = permission.get('IpProtocol', '-1')
                from_port = permission.get('FromPort')
                to_port = permission.get('ToPort')

                # Check IPv4 ranges
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    desc = ip_range.get('Description', '')
                    rule_entry = {
                        'protocol': protocol,
                        'from_port': from_port,
                        'to_port': to_port,
                        'cidr': cidr,
                        'description': desc
                    }
                    all_rules.append(rule_entry)

                    if cidr == '0.0.0.0/0':
                        is_open = True
                        insecure_rules.append(rule_entry)

                # Check IPv6 ranges
                for ipv6_range in permission.get('Ipv6Ranges', []):
                    cidr_v6 = ipv6_range.get('CidrIpv6', '')
                    desc_v6 = ipv6_range.get('Description', '')
                    rule_entry = {
                        'protocol': protocol,
                        'from_port': from_port,
                        'to_port': to_port,
                        'cidr': cidr_v6,
                        'description': desc_v6
                    }
                    all_rules.append(rule_entry)

                    if cidr_v6 == '::/0':
                        is_open = True
                        insecure_rules.append(rule_entry)
            
            sgs.append({
                'id': sg['GroupId'],
                'name': sg.get('GroupName', ''),
                'description': sg.get('Description', ''),
                'vpc_id': sg.get('VpcId', ''),
                'is_open': is_open,
                'insecure_rules': insecure_rules,
                'rules': all_rules
            })
    except ClientError as e:
        print(f"Error scanning SG: {e}")
        
    return sgs

