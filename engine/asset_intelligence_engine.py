import networkx as nx

class AssetIntelligenceEngine:
    @staticmethod
    def map_assets_to_attack_graph(graph_data, scan_results, path_data):
        """
        Structured asset view with attack path roles and blast radius.
        """
        G = graph_data.get("graph")
        if not G:
            # Fallback if DiGraph object was removed for serialization
            G = nx.DiGraph()
            for edge in graph_data.get("edges", []):
                G.add_edge(edge['source'], edge['target'])

        assets = []
        paths = path_data.get("paths", [])
        
        # Flatten path nodes for quick lookup
        nodes_in_paths = set()
        for p in paths:
            for node_id in p:
                nodes_in_paths.add(node_id)

        # 1. Map EC2 Assets
        for ec2 in scan_results.get("ec2", []):
            asset_id = ec2.get("id")
            role = AssetIntelligenceEngine.derive_attack_role(asset_id, "ec2", G, paths)
            exposure = "public" if ec2.get("is_public") else "internal"
            
            assets.append({
                "resource_id": asset_id,
                "resource_type": "EC2",
                "exposure_status": exposure,
                "risk_level": "HIGH" if asset_id in nodes_in_paths or ec2.get("is_public") else "LOW",
                "attack_role": role,
                "connected_nodes": list(G.neighbors(asset_id)) if asset_id in G else [],
                "vulnerabilities": ["Public Exposure"] if ec2.get("is_public") else [],
                "recommended_fix": "Restrict Security Group rules" if ec2.get("is_public") else "None",
                "blast_radius_score": AssetIntelligenceEngine.calculate_blast_radius(asset_id, G)
            })

        # 2. Map IAM Assets
        for iam in scan_results.get("iam", []):
            asset_id = iam.get("id")
            role = AssetIntelligenceEngine.derive_attack_role(asset_id, "iam", G, paths)
            
            assets.append({
                "resource_id": asset_id,
                "resource_type": "IAM",
                "exposure_status": "internal",
                "risk_level": "HIGH" if iam.get("is_admin") or asset_id in nodes_in_paths else "LOW",
                "attack_role": role,
                "connected_nodes": list(G.neighbors(asset_id)) if asset_id in G else [],
                "vulnerabilities": ["Excessive Permissions (Administrator)"] if iam.get("is_admin") else [],
                "recommended_fix": "Apply Least Privilege policies" if iam.get("is_admin") else "None",
                "blast_radius_score": AssetIntelligenceEngine.calculate_blast_radius(asset_id, G)
            })

        # 3. Map S3 Assets
        for s3 in scan_results.get("s3", []):
            asset_id = s3.get("id")
            role = AssetIntelligenceEngine.derive_attack_role(asset_id, "s3", G, paths)
            exposure = "public" if s3.get("is_public") else "secure"
            
            assets.append({
                "resource_id": asset_id,
                "resource_type": "S3",
                "exposure_status": exposure,
                "risk_level": "HIGH" if asset_id in nodes_in_paths or s3.get("is_public") else "LOW",
                "attack_role": role,
                "connected_nodes": list(G.neighbors(asset_id)) if asset_id in G else [],
                "vulnerabilities": ["Public Access block disabled"] if s3.get("is_public") else [],
                "recommended_fix": "Enable Block Public Access" if s3.get("is_public") else "None",
                "blast_radius_score": AssetIntelligenceEngine.calculate_blast_radius(asset_id, G)
            })

        # 4. Map VPCs
        for vpc in scan_results.get("vpcs", []):
            asset_id = vpc.get("VpcId")
            assets.append({
                "resource_id": asset_id,
                "resource_type": "VPC",
                "exposure_status": "internal",
                "risk_level": "LOW",
                "attack_role": "STRUCTURAL",
                "connected_nodes": [s.get('SubnetId') for s in scan_results.get('subnets', []) if s.get('VpcId') and s.get('VpcId') == asset_id],
                "vulnerabilities": [],
                "recommended_fix": "Monitor for unauthorized peering or IGW attachments.",
                "blast_radius_score": 20
            })

        # 5. Map Subnets
        for subnet in scan_results.get("subnets", []):
            asset_id = subnet.get("SubnetId")
            is_pub = subnet.get("MapPublicIpOnLaunch", False)
            assets.append({
                "resource_id": asset_id,
                "resource_type": "SUBNET",
                "exposure_status": "public" if is_pub else "internal",
                "risk_level": "MEDIUM" if is_pub else "LOW",
                "attack_role": "STRUCTURAL",
                "connected_nodes": [asset_id], # Subnet to its VPC or EC2s could be added here
                "vulnerabilities": ["Auto-assign Public IP enabled"] if is_pub else [],
                "recommended_fix": "Disable 'MapPublicIpOnLaunch' if public access isn't required." if is_pub else "None",
                "blast_radius_score": 40 if is_pub else 10
            })

        return assets

    @staticmethod
    def derive_attack_role(node_id, node_type, G, paths):
        if node_id == "Internet": return "ENTRY_POINT"
        
        # Check if it's a target
        is_target = any(p[-1] == node_id for p in paths)
        if is_target: return "TARGET"

        # Check if it's an entry point
        is_entry = G.has_edge("Internet", node_id)
        if is_entry: return "ENTRY_POINT"

        # Check if it's an escalation node (IAM generally)
        if node_type == "iam": return "ESCALATION_NODE"

        # If it's in a path but not start/end, it's a pivot
        in_path = any(node_id in p for p in paths)
        if in_path: return "PIVOT_NODE"

        return "SECURE_NODE"

    @staticmethod
    def calculate_blast_radius(node_id, G):
        if node_id not in G: return 0
        try:
            # Simple score: count of reachable nodes from here
            reachable = nx.descendants(G, node_id)
            return len(reachable) * 10 # Scalar
        except:
            return 0
