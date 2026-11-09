import networkx as nx

class AttackPathEngine:
    def __init__(self, graph_obj=None):
        self.graph_obj = graph_obj

    def find_attack_paths(self, graph_obj=None):
        """
        Detects multi-step attack paths starting from 'Internet'.
        Expects the graph output from GraphEngine or nx.DiGraph.
        """
        target = graph_obj if graph_obj is not None else self.graph_obj
        if target is None:
            target = {}
        elif isinstance(target, nx.DiGraph):
            target = {
                "graph": target,
                "entry_points": [n for n, d in target.nodes(data=True) if d.get("public")],
                "privileged_nodes": [n for n, d in target.nodes(data=True) if d.get("is_admin")]
            }

        G = target.get("graph")

        if not G or "Internet" not in G:
            return {
                "paths": [],
                "reasoning": {
                    "entry_point": False,
                    "privilege_escalation": False,
                    "target_reachable": False,
                    "broken_step": "No Internet Entry Point identified in Graph"
                },
                "narrative": ["1. Attacker initiates automated scanning for exposed assets (0.0.0.0/0).", "2. Scan complete: 0 entry points discovered.", "3. Attack chain TERMINATED at reconnaissance stage."],
                "time_to_compromise": "N/A (Impenetrable via direct internet attack)",
                "attacker_intent": "Reconnaissance blocked"
            }

        paths = []
        targets = []
        for n, d in G.nodes(data=True):
            if d.get("type") == "iam" and d.get("is_admin"):
                targets.append(n)
            elif d.get("type") == "s3" and d.get("public"):
                targets.append(n)
                
        for target in targets:
            try:
                all_paths = nx.all_simple_paths(G, source="Internet", target=target, cutoff=6)
                for p in all_paths:
                    if len(p) >= 3:
                        paths.append(p)
            except nx.NetworkXNoPath:
                continue
                
        unique_paths = []
        for p in paths:
            if p not in unique_paths:
                unique_paths.append(p)

        # Attack Chain Reasoning
        entry_points = graph_obj.get("entry_points", [])
        privileged = graph_obj.get("privileged_nodes", [])
        
        has_entry = len(entry_points) > 0
        has_escalation = False
        if has_entry:
            # Check if any entry point can reach ANY IAM role
            for ep in entry_points:
                for n in G.neighbors(ep):
                    if G.nodes[n].get("type") == "iam":
                        has_escalation = True
                        break
        
        broken_step = "None"
        narrative = []
        time_to_compromise = "N/A"
        attacker_intent = "Unknown"
        
        narrative.append("1. Attacker initiates automated scanning for exposed assets (0.0.0.0/0).")
        
        if not has_entry:
            broken_step = "No public entry points (EC2) detected"
            narrative.append("2. Scan complete: 0 public entry points discovered.")
            narrative.append("3. Attack chain TERMINATED at reconnaissance stage (Network isolation active).")
            time_to_compromise = "N/A (Impenetrable via direct internet attack)"
            attacker_intent = "Reconnaissance blocked"
        elif not has_escalation:
            broken_step = "Public EC2 exists, but no IAM role is attached for escalation"
            narrative.append(f"2. Attacker discovers {len(entry_points)} public EC2 instances.")
            narrative.append("3. Attacker attempts SSH/RDP brute-force or unpatched CVE exploitation to gain initial shell access.")
            narrative.append("4. Initial access SUCCESSFUL. Attacker drops payload onto EC2.")
            narrative.append("5. Attempts privilege escalation via IMDS metadata query → FAILED (No IAM role attached).")
            narrative.append("6. Attack chain TERMINATED at privilege escalation stage.")
            time_to_compromise = "Initial access in minutes. Further compromise blocked."
            attacker_intent = "Botnet inclusion / Local payload execution"
        elif not unique_paths:
            broken_step = "Escalation possible, but no path to sensitive targets (Admin/Public S3)"
            narrative.append(f"2. Attacker discovers {len(entry_points)} public EC2 instances.")
            narrative.append("3. Initial access SUCCESSFUL.")
            narrative.append("4. Privilege escalation SUCCESSFUL (Non-admin IAM role hijacked).")
            narrative.append("5. Attempts lateral movement to critical targets → FAILED (Permissions too restrictive).")
            narrative.append("6. Attack chain TERMINATED before reaching critical assets.")
            time_to_compromise = "Initial access in minutes. Escalation limited."
            attacker_intent = "Limited AWS API abuse"
        else:
            narrative.append(f"2. Attacker discovers {len(entry_points)} public EC2 instances.")
            narrative.append("3. Initial access SUCCESSFUL. Shell established.")
            narrative.append("4. Privilege escalation SUCCESSFUL. Attacker hijacks AdministratorAccess IAM role via IMDS metadata query.")
            narrative.append("5. Attacker gains full administrative control of AWS environment.")
            narrative.append(f"6. {len(unique_paths)} attack paths to critical targets fully compromised.")
            time_to_compromise = "Initial access: <5 mins | Escalation: <2 mins | Full Compromise: <10 mins"
            attacker_intent = "Crypto mining cluster deployment / Data exfiltration / Ransomware"

        return {
            "paths": unique_paths,
            "reasoning": {
                "entry_point": has_entry,
                "privilege_escalation": has_escalation,
                "target_reachable": len(unique_paths) > 0,
                "broken_step": broken_step
            },
            "narrative": narrative,
            "time_to_compromise": time_to_compromise,
            "attacker_intent": attacker_intent
        }
