import networkx as nx
import uuid
import math
import random
from typing import List, Dict, Any, Tuple
from ..models.schemas import ScanResult, GraphNode, GraphEdge, AttackGraph, Severity

# Map severity to weight
SEV_WEIGHT = {Severity.CRITICAL: 9.5, Severity.HIGH: 7.5, Severity.MEDIUM: 5.0, Severity.LOW: 3.0, Severity.INFO: 1.0}
SEV_COLOR = {Severity.CRITICAL: "#ef4444", Severity.HIGH: "#f97316", Severity.MEDIUM: "#eab308", Severity.LOW: "#22c55e", Severity.INFO: "#64748b"}

def build_attack_graph(scan: ScanResult) -> AttackGraph:
    G = nx.DiGraph()
    graph_id = f"GRAPH-{uuid.uuid4().hex[:8].upper()}"
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []

    def add_node(id_, label, type_, **props):
        node = GraphNode(id=id_, label=label, type=type_, properties=props.get("properties", {}), severity=props.get("severity"), cvss=props.get("cvss"))
        nodes.append(node)
        G.add_node(id_, **props, label=label, type=type_)
        return node

    def add_edge(src, tgt, label, type_, weight=1.0, exploitability=0.5, description=None):
        eid = f"E-{uuid.uuid4().hex[:6]}"
        edge = GraphEdge(id=eid, source=src, target=tgt, label=label, type=type_, weight=weight, exploitability=exploitability, description=description)
        edges.append(edge)
        G.add_edge(src, tgt, weight=weight, exploitability=exploitability, label=label)
        return edge

    # Entry node (internet)
    entry_id = "entry-internet"
    add_node(entry_id, "Internet / Attacker", "entry", properties={"icon":"globe"})

    # Target host node
    host_label = scan.target.replace("https://","").replace("http://","").split("/")[0]
    host_id = f"host-{host_label}"
    add_node(host_id, host_label, "host", properties={"ip": next((f.value for f in scan.findings if f.key=="resolved_ip"), "unknown"), "tech": [t.name for t in scan.technologies]})

    add_edge(entry_id, host_id, "initial access", "accesses", weight=2.0, exploitability=0.7, description="Attacker can reach web service")

    # Service nodes per port
    service_ids = []
    for p in scan.ports:
        sid = f"svc-{p.port}"
        add_node(sid, f"{p.service}:{p.port}", "service", properties={"port": p.port, "banner": p.banner, "state": p.state}, severity=None)
        add_edge(host_id, sid, f"exposes {p.port}", "accesses", weight=1.5, exploitability=0.6 if p.port in [80,443] else 0.8)
        service_ids.append(sid)

    # Vulnerability nodes linked to services/host
    vuln_ids = []
    for v in scan.vulnerabilities:
        vid = f"vuln-{v.id}"
        add_node(vid, v.title, "vulnerability", severity=v.severity, cvss=v.cvss, properties={"cwe": v.cwe, "cve": v.cve, "url": v.url, "epss": v.epss, "exploit_available": v.exploit_available})
        # attach to most relevant service
        target_service = service_ids[0] if service_ids else host_id
        # heuristic: web vulns -> 80/443
        if any(x in v.title.lower() for x in ["xss","sqli","cors","header","redirect","ssrf","idor"]):
            # find web service
            web_svc = next((s for s in service_ids if "80" in s or "443" in s), target_service)
            target_service = web_svc
        weight = SEV_WEIGHT.get(v.severity, 5.0) / 2
        exploit = min(0.95, v.epss + 0.3 if v.exploit_available else v.cvss/10)
        add_edge(target_service, vid, "vulnerable to", "exploits", weight=weight, exploitability=exploit, description=v.description[:120])
        vuln_ids.append((vid, v))
        # privilege escalation from vuln
        # e.g., critical sqli -> privilege node
        if v.severity in [Severity.CRITICAL, Severity.HIGH]:
            priv_id = f"priv-{vid}"
            add_node(priv_id, f"Privilege: {v.title[:24]}", "privilege", properties={"derived_from": vid}, severity=v.severity, cvss=v.cvss)
            add_edge(vid, priv_id, "escalates to", "escalates", weight=weight*0.8, exploitability=exploit*0.9)

    # User & data nodes (business impact)
    if any(v.severity==Severity.CRITICAL for v in scan.vulnerabilities):
        user_id = f"user-admin-{uuid.uuid4().hex[:4]}"
        add_node(user_id, "Admin User", "user", properties={"privilege":"admin"})
        # connect from a critical vuln privilege
        crit_privs = [n.id for n in nodes if n.type=="privilege" and n.severity==Severity.CRITICAL]
        src = crit_privs[0] if crit_privs else (vuln_ids[0][0] if vuln_ids else host_id)
        add_edge(src, user_id, "compromises", "lateral", weight=8, exploitability=0.85, description="Attacker obtains admin session")
        data_id = f"data-crown-{uuid.uuid4().hex[:4]}"
        add_node(data_id, "Crown Jewels / DB", "data", properties={"sensitivity":"high"}, severity=Severity.CRITICAL, cvss=9.5)
        add_edge(user_id, data_id, "exfiltrates", "exfiltrates", weight=9, exploitability=0.9)

    # Subdomain nodes
    for sub in scan.subdomains[:6]:
        sid = f"sub-{sub.replace('.','-')}"
        add_node(sid, sub, "host", properties={"type":"subdomain"})
        add_edge(entry_id, sid, "discovers", "accesses", weight=1.2, exploitability=0.5)
        # link subdomain to vuln if related
        if vuln_ids:
            add_edge(sid, vuln_ids[0][0], "shares vuln", "lateral", weight=1.0, exploitability=0.4)

    # Layout positions (simple circular + hierarchical)
    # Assign positions for frontend force layout fallback
    layers = {
        "entry": 0,
        "host": 1,
        "service": 2,
        "vulnerability": 3,
        "privilege": 4,
        "user": 5,
        "data": 6
    }
    for n in nodes:
        layer = layers.get(n.type, 3)
        # jitter
        n.x = layer * 220 + random.uniform(-30,30)
        n.y = random.uniform(-200, 200) + (hash(n.id) % 200) - 100

    # Compute paths: all simple paths from entry to critical assets
    try:
        # Build metrics using networkx
        metrics = {}
        metrics["node_count"] = G.number_of_nodes()
        metrics["edge_count"] = G.number_of_edges()
        metrics["density"] = nx.density(G)
        # centrality with fallback if scipy not available
        try:
            bet = nx.betweenness_centrality(G, weight="weight")
        except Exception:
            bet = {n:0 for n in G.nodes()}
        try:
            pr = nx.pagerank(G, weight="weight")
        except Exception:
            try:
                pr = nx.pagerank_numpy(G, weight="weight")
            except Exception:
                pr = {n: 1/len(G.nodes()) for n in G.nodes()} if len(G.nodes())>0 else {}
        metrics["betweenness"] = {k: round(v,4) for k,v in sorted(bet.items(), key=lambda x: -x[1])[:5]}
        metrics["pagerank"] = {k: round(v,4) for k,v in sorted(pr.items(), key=lambda x: -x[1])[:5]}
        # shortest paths (by weight) from entry to each data/vuln critical
        targets = [n.id for n in nodes if n.type in ["data","privilege"] or (n.type=="vulnerability" and n.severity in [Severity.CRITICAL, Severity.HIGH])]
        if not targets:
            targets = [n.id for n in nodes if n.type=="vulnerability"][:2]
        all_paths = []
        critical_paths = []
        for tgt in targets:
            try:
                path = nx.shortest_path(G, source=entry_id, target=tgt, weight="weight")
                all_paths.append(path)
                # calculate path risk = sum cvss + product exploitability
                path_vulns = [vid for vid in path if vid.startswith("vuln-")]
                risk_score = 0
                exploit_product = 1.0
                for vid in path_vulns:
                    # find vuln object
                    v = next((vv for (id_, vv) in vuln_ids if id_==vid), None)
                    if v:
                        risk_score += v.cvss
                        exploit_product *= (v.epss if v.epss>0 else v.cvss/10)
                # normalize
                norm_risk = min(100, risk_score * 6 + len(path)*4)
                critical_paths.append({
                    "target": tgt,
                    "target_label": next((n.label for n in nodes if n.id==tgt), tgt),
                    "path": path,
                    "path_labels": [next((n.label for n in nodes if n.id==p), p) for p in path],
                    "length": len(path),
                    "risk_score": round(norm_risk,1),
                    "exploitability": round(exploit_product,3),
                    "severity": "critical" if norm_risk>75 else "high" if norm_risk>50 else "medium"
                })
            except nx.NetworkXNoPath:
                continue
        # Sort critical_paths by risk_score desc
        critical_paths = sorted(critical_paths, key=lambda x: -x["risk_score"])[:5]
        metrics["critical_path_count"] = len(critical_paths)
        metrics["avg_path_length"] = round(sum(len(p) for p in all_paths)/len(all_paths),2) if all_paths else 0
    except Exception as e:
        metrics = {"error": str(e), "node_count": len(nodes), "edge_count": len(edges)}
        all_paths = []
        critical_paths = []

    # Attach metrics
    return AttackGraph(
        graph_id=graph_id,
        job_id=scan.job_id,
        nodes=nodes,
        edges=edges,
        paths=all_paths if 'all_paths' in locals() else [],
        critical_paths=critical_paths if 'critical_paths' in locals() else [],
        metrics=metrics if 'metrics' in locals() else {}
    )

def get_adjacency_for_frontend(graph: AttackGraph) -> dict:
    return {
        "nodes": [n.model_dump() for n in graph.nodes],
        "edges": [e.model_dump() for e in graph.edges],
        "paths": graph.paths,
        "critical_paths": graph.critical_paths,
        "metrics": graph.metrics
    }
