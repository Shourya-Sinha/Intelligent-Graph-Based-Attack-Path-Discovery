import json
import csv
import io
import base64
from datetime import datetime
from typing import Dict, Any
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.enums import TA_LEFT, TA_CENTER
import jinja2

from ..models.schemas import ScanResult, AttackGraph, RiskAnalysisResult

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Attack Path Report - {{ scan.target }}</title>
<style>
body{font-family: Inter, Arial, sans-serif; background:#0a0e1a; color:#e2e8f0; margin:0; padding:0}
.header{background: linear-gradient(135deg,#0ea5e9,#6366f1); padding:40px; color:white}
.container{max-width:1100px; margin:0 auto; padding:24px}
.card{background:#151a2c; border:1px solid #1e293b; border-radius:16px; padding:20px; margin:16px 0}
.badge{display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700}
.critical{background:#ef4444; color:white}
.high{background:#f97316; color:white}
.medium{background:#eab308; color:black}
.low{background:#22c55e; color:white}
.info{background:#64748b; color:white}
table{width:100%; border-collapse:collapse}
th,td{padding:10px 12px; border-bottom:1px solid #1e293b; text-align:left; font-size:13px}
th{background:#0f172a; color:#94a3b8; text-transform:uppercase; letter-spacing:0.06em; font-size:11px}
h2{color:#38bdf8}
h3{color:#a5b4fc}
a{color:#38bdf8}
pre{background:#020617; padding:12px; border-radius:8px; overflow:auto; font-size:12px}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ Intelligent Graph-Based Attack Path Discovery</h1>
  <p>Advanced Scan Report &bull; {{ scan.target }} &bull; {{ scan.finished_at }} &bull; Mode: {{ scan.mode.value.upper() }}</p>
  <p>Risk: <span class="badge {{ risk.risk_level if risk else 'high' }}">{{ (risk.overall_risk_score if risk else 0) }}/100 {{ (risk.risk_level.upper() if risk else 'N/A') }}</span> &nbsp; Vulns: {{ scan.summary.total_vulns if scan.summary and scan.summary.total_vulns else scan.vulnerabilities|length }} &nbsp; Paths: {{ graph.metrics.critical_path_count if graph and graph.metrics and graph.metrics.critical_path_count else 0 }}</p>
</div>
<div class="container">
  <div class="card">
    <h2>Executive Summary</h2>
    <p>This report presents a comprehensive attack graph analysis for <b>{{ scan.target }}</b>. The scanner performed deep crawling, port fingerprinting, header/TLS analysis, and active probing. The custom Risk Engine quantified financial exposure and prioritized remediation via graph centrality and Monte Carlo simulation.</p>
    <ul>
      <li>Overall Risk Score: <b>{{ risk.overall_risk_score if risk else 'N/A' }}/100 ({{ risk.risk_level if risk else '' }})</b></li>
      <li>Exposure Score: {{ risk.exposure_score if risk else 'N/A' }}/100</li>
      <li>Single Loss Expectancy: ${{ "{:,.0f}".format(risk.financial_impact_usd.single_loss_expectancy_usd) if risk else 'N/A' }}</li>
      <li>Critical Paths Found: {{ graph.critical_paths|length if graph else 0 }}</li>
    </ul>
  </div>

  <div class="card">
    <h2>Technology & Exposure</h2>
    <p><b>Technologies:</b> {{ scan.technologies|map(attribute='name')|join(', ') if scan.technologies else 'Unknown' }}</p>
    <p><b>Open Ports:</b> {% for p in scan.ports %}<span class="badge info">{{ p.port }}/{{ p.service }}</span> {% endfor %}</p>
    <p><b>Subdomains:</b> {{ scan.subdomains|join(', ') }}</p>
    <p><b>Directories:</b> {{ scan.directories|join(', ') }}</p>
  </div>

  <div class="card">
    <h2>Vulnerabilities ({{ scan.vulnerabilities|length }})</h2>
    <table>
      <tr><th>Title</th><th>Severity</th><th>CVSS</th><th>CWE</th><th>URL</th><th>Fix</th></tr>
      {% for v in scan.vulnerabilities %}
      <tr>
        <td><b>{{ v.title }}</b><br><span style="color:#94a3b8">{{ v.description[:120] }}...</span></td>
        <td><span class="badge {{ v.severity.value }}">{{ v.severity.value }}</span></td>
        <td>{{ v.cvss }}</td>
        <td>{{ v.cwe }}</td>
        <td style="max-width:160px; word-break:break-all">{{ v.url or '-' }}</td>
        <td>{{ v.remediation[:80] }}...</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  {% if graph %}
  <div class="card">
    <h2>Attack Graph - Critical Paths</h2>
    {% for p in graph.critical_paths %}
    <div style="background:#020617; padding:12px; border-radius:8px; margin:8px 0">
      <b style="color:#f472b6">{{ p.target_label }}</b> — Risk {{ p.risk_score }}/100 — {{ p.severity }}
      <div style="margin:6px 0; color:#38bdf8">{{ p.path_labels|join(' → ') }}</div>
      <span style="font-size:12px; color:#94a3b8">Exploitability {{ p.exploitability }}</span>
    </div>
    {% endfor %}
    <p><b>Graph Metrics:</b> Nodes {{ graph.metrics.node_count if graph.metrics.node_count else 0 }}, Edges {{ graph.metrics.edge_count if graph.metrics.edge_count else 0 }}, Density {{ (graph.metrics.density|round(3)) if graph.metrics.density is defined and graph.metrics.density is not none else '0.000' }}, Betweenness {{ graph.metrics.betweenness if graph.metrics.betweenness else '{}' }}</p>
  </div>
  {% endif %}

  {% if risk %}
  <div class="card">
    <h2>Risk & Financial Quantification (FAIR + Monte Carlo)</h2>
    <p>Monte Carlo (4000 sims): Expected Loss <b>${{ "{:,.0f}".format(risk.monte_carlo.expected_loss) }}</b> | P90 ${{ "{:,.0f}".format(risk.monte_carlo.p90_loss) }} | P95 ${{ "{:,.0f}".format(risk.monte_carlo.p95_loss) }}</p>
    <h3>Compliance</h3>
    <table><tr><th>Framework</th><th>Score</th><th>Status</th></tr>
    {% for k,v in risk.compliance.items() %}
    <tr><td>{{ k }}</td><td>{{ v.score }}/100</td><td><span class="badge {{ 'critical' if v.status=='fail' else 'medium' if v.status=='warn' else 'low' }}">{{ v.status }}</span></td></tr>
    {% endfor %}</table>
    <h3>Prioritized Remediation</h3>
    {% for r in risk.recommendations %}
    <div style="border-left:3px solid #38bdf8; padding-left:12px; margin:10px 0">
      <b>{{ r.priority }} — {{ r.title }}</b> (Effort: {{ r.effort }}, Reduction: {{ r.estimated_risk_reduction }})<br>
      <span style="color:#cbd5e1">{{ r.action }}</span>
      {% if r.code %}<pre>{{ r.code }}</pre>{% endif %}
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <div class="card">
    <h2>Weakness Deep Dive & Fix Guidance</h2>
    {% for v in scan.vulnerabilities %}
    <h3>{{ loop.index }}. {{ v.title }} — {{ v.severity.value }} (CVSS {{ v.cvss }})</h3>
    <p><b>CWE:</b> {{ v.cwe }} | <b>OWASP:</b> {{ v.owasp }} | <b>MITRE:</b> {{ v.mitre_technique }} | <b>CVE:</b> {{ v.cve or 'N/A' }} | <b>EPSS:</b> {{ v.epss }} | <b>Exploit:</b> {{ v.exploit_available }}</p>
    <p>{{ v.description }}</p>
    <p><b>Impact:</b> {{ v.impact }}</p>
    <p><b>Evidence:</b> <code>{{ v.evidence }}</code></p>
    <p><b>Remediation:</b> {{ v.remediation }}</p>
    {% if v.remediation_code %}<pre>{{ v.remediation_code }}</pre>{% endif %}
    <p><b>References:</b> {{ v.references|join(', ') }}</p>
    <hr style="border-color:#1e293b">
    {% endfor %}
  </div>

  <div class="card" style="text-align:center; color:#64748b">
    Generated by Intelligent Graph-Based Attack Path Discovery Engine v2.0 &bull; {{ now }}<br>
    Confidential — For authorized security testing only.
  </div>
</div>
</body>
</html>
"""

def export_html(scan: ScanResult, graph: AttackGraph = None, risk: RiskAnalysisResult = None) -> str:
    env = jinja2.Environment(autoescape=False)
    tmpl = env.from_string(HTML_TEMPLATE)
    return tmpl.render(scan=scan, graph=graph, risk=risk, now=datetime.utcnow().isoformat())

def export_json(scan: ScanResult, graph: AttackGraph = None, risk: RiskAnalysisResult = None) -> str:
    data = {
        "scan": scan.model_dump(),
        "graph": graph.model_dump() if graph else None,
        "risk": risk.model_dump() if risk else None,
        "generated_at": datetime.utcnow().isoformat(),
        "engine": "Intelligent Graph Attack Path Discovery v2.0"
    }
    return json.dumps(data, indent=2, default=str)

def export_csv(scan: ScanResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id","title","severity","cvss","cwe","cve","owasp","url","param","evidence","description","impact","remediation","confidence","epss","exploit_available"])
    for v in scan.vulnerabilities:
        writer.writerow([v.id, v.title, v.severity.value, v.cvss, v.cwe, v.cve, v.owasp, v.url, v.param, v.evidence, v.description, v.impact, v.remediation, v.confidence, v.epss, v.exploit_available])
    return output.getvalue()

def export_sarif(scan: ScanResult) -> str:
    # SARIF 2.1.0 for GitHub/CodeQL integration
    rules = []
    results = []
    for v in scan.vulnerabilities:
        rule_id = v.cwe or v.id
        rules.append({
            "id": rule_id,
            "name": v.title,
            "shortDescription": {"text": v.title},
            "fullDescription": {"text": v.description},
            "properties": {"severity": v.severity.value, "cvss": v.cvss}
        })
        results.append({
            "ruleId": rule_id,
            "level": "error" if v.severity.value in ["critical","high"] else "warning" if v.severity.value=="medium" else "note",
            "message": {"text": f"{v.title}: {v.description}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": v.url or scan.target}}}],
            "properties": {"cwe": v.cwe, "owasp": v.owasp}
        })
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "Intelligent Graph Attack Discovery", "version": "2.0", "rules": rules}},
            "results": results
        }]
    }
    return json.dumps(sarif, indent=2)

def export_pdf(scan: ScanResult, graph: AttackGraph = None, risk: RiskAnalysisResult = None) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.6*inch, bottomMargin=0.6*inch, leftMargin=0.6*inch, rightMargin=0.6*inch,
                            title=f"Attack Path Report - {scan.target}")
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title2', parent=styles['Title'], fontSize=22, textColor=colors.HexColor("#0ea5e9"), alignment=TA_CENTER)
    h1 = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=14, textColor=colors.HexColor("#0ea5e9"), spaceBefore=12, spaceAfter=6)
    h2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=11, textColor=colors.HexColor("#6366f1"))
    normal = ParagraphStyle('Normal2', parent=styles['Normal'], fontSize=8, leading=11, textColor=colors.HexColor("#1e293b"))
    story = []
    story.append(Paragraph("Intelligent Graph-Based<br/>Attack Path Discovery", title_style))
    story.append(Paragraph(f"Advanced Security Report — {scan.target} — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} — Mode: {scan.mode.value.upper()}", styles['Normal']))
    story.append(Spacer(1, 0.15*inch))
    # summary table
    sev_counts = scan.summary.get("by_severity", {})
    data = [
        ["Overall Risk", f"{risk.overall_risk_score if risk else 0}/100 ({risk.risk_level if risk else 'N/A'})", "Exposure", f"{risk.exposure_score if risk else 0}/100"],
        ["Vulns", str(len(scan.vulnerabilities)), "Critical/High", f"{sev_counts.get('critical',0)}/{sev_counts.get('high',0)}"],
        ["Open Ports", str(len(scan.ports)), "Technologies", ", ".join([t.name for t in scan.technologies[:4]]) or "Unknown"],
        ["Scan Duration", f"{scan.duration_seconds:.1f}s" if scan.duration_seconds else "-", "Graph Nodes/Edges", f"{graph.metrics.get('node_count',0)}/{graph.metrics.get('edge_count',0)}" if graph else "-"]
    ]
    t = Table(data, colWidths=[1.2*inch, 2*inch, 1.2*inch, 2*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0ea5e9")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#f1f5f9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.white),
        ('FONTSIZE', (0,0), (-1,-1), 7),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.2*inch))

    story.append(Paragraph("Executive Summary", h1))
    story.append(Paragraph(f"This report provides a deep attack graph analysis for <b>{scan.target}</b>. The scanner executed reconnaissance, port service fingerprinting, web crawling, header/TLS hardening checks, directory discovery, and active vulnerability probing. The custom Risk Engine (FAIR + Monte Carlo + Graph Centrality) quantified financial exposure and prioritized fixes by choke-point analysis.", normal))
    story.append(Spacer(1, 0.1*inch))

    if risk:
        story.append(Paragraph("Risk & Financial Quantification", h1))
        story.append(Paragraph(f"Overall Risk <b>{risk.overall_risk_score}/100 [{risk.risk_level.upper()}]</b> — Exposure {risk.exposure_score}/100 — Single Loss Expectancy <b>${risk.financial_impact_usd['single_loss_expectancy_usd']:,.0f}</b> — Monte Carlo Expected Loss <b>${risk.monte_carlo['expected_loss']:,.0f}</b> (P90 ${risk.monte_carlo['p90_loss']:,.0f})", normal))
        # compliance
        comp_data = [["Framework","Score","Status"]]
        for k,v in risk.compliance.items():
            comp_data.append([k, f"{v['score']}/100", v['status']])
        ct = Table(comp_data, colWidths=[2*inch, 1.2*inch, 1.2*inch])
        ct.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor("#6366f1")), ('TEXTCOLOR', (0,0), (-1,0), colors.white), ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")), ('FONTSIZE', (0,0), (-1,-1), 7), ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")])]))
        story.append(ct)
        story.append(Spacer(1, 0.1*inch))

    story.append(Paragraph("Vulnerabilities", h1))
    vuln_data = [["#","Title","Severity","CVSS","CWE"]]
    for i, v in enumerate(scan.vulnerabilities, 1):
        sev_color = colors.HexColor("#ef4444" if v.severity.value=="critical" else "#f97316" if v.severity.value=="high" else "#eab308")
        vuln_data.append([str(i), Paragraph(v.title[:44], normal), Paragraph(f"<font color='{sev_color.hexval()}'><b>{v.severity.value}</b></font>", normal), str(v.cvss), v.cwe or "-"])
    vt = Table(vuln_data, colWidths=[0.25*inch, 3.0*inch, 0.9*inch, 0.6*inch, 0.9*inch])
    vt.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")), ('TEXTCOLOR', (0,0), (-1,0), colors.white), ('GRID', (0,0), (-1,-1), 0.4, colors.HexColor("#cbd5e1")), ('FONTSIZE', (0,0), (-1,-1), 7), ('VALIGN', (0,0), (-1,-1), 'TOP'), ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f1f5f9")])]))
    story.append(vt)
    story.append(Spacer(1, 0.15*inch))

    if graph and graph.critical_paths:
        story.append(Paragraph("Critical Attack Paths (Graph Engine - Dijkstra Weighted)", h1))
        for p in graph.critical_paths:
            story.append(Paragraph(f"<b>{p['target_label']}</b> — Risk {p['risk_score']}/100 — Exploitability {p['exploitability']} — {p['severity']}<br/><font color='#0ea5e9'>{' → '.join(p['path_labels'])}</font>", normal))
            story.append(Spacer(1, 0.06*inch))
        story.append(Spacer(1, 0.1*inch))

    story.append(Paragraph("Weakness Deep Dive & Fix Guidance", h1))
    for idx, v in enumerate(scan.vulnerabilities, 1):
        story.append(Paragraph(f"{idx}. {v.title} — <b>{v.severity.value.upper()}</b> (CVSS {v.cvss}) — {v.cwe or ''} | {v.owasp or ''}", h2))
        story.append(Paragraph(f"<b>Description:</b> {v.description}", normal))
        story.append(Paragraph(f"<b>Impact:</b> {v.impact}", normal))
        if v.evidence:
            story.append(Paragraph(f"<b>Evidence:</b> <font face='Courier' size=7>{v.evidence[:300]}</font>", normal))
        story.append(Paragraph(f"<b>Remediation:</b> {v.remediation}", normal))
        if v.remediation_code:
            code_style = ParagraphStyle('code', parent=normal, fontName='Courier', fontSize=6, leading=7, backColor=colors.HexColor("#020617"), textColor=colors.HexColor("#e2e8f0"), borderPadding=(6,6,6))
            story.append(Paragraph(f"<font face='Courier'>{v.remediation_code[:600].replace('<','&lt;').replace(chr(10), '<br/>')}</font>", code_style))
        story.append(Spacer(1, 0.08*inch))

    if risk and risk.recommendations:
        story.append(Paragraph("Prioritized Remediation Roadmap", h1))
        for r in risk.recommendations:
            story.append(Paragraph(f"<b>{r['priority']} — {r['title']}</b> (Effort: {r['effort']}, Risk Reduction: {r['estimated_risk_reduction']})<br/>{r['action']}", normal))
            if r.get('code'):
                story.append(Paragraph(f"<font face='Courier' size=6>{r['code'][:500].replace('<','&lt;').replace(chr(10), '<br/>')}</font>", normal))
            story.append(Spacer(1, 0.06*inch))

    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("Generated by Intelligent Graph-Based Attack Path Discovery Engine v2.0 — Confidential — For authorized testing only.", ParagraphStyle('footer', parent=normal, alignment=TA_CENTER, textColor=colors.HexColor("#64748b"), fontSize=7)))

    doc.build(story)
    return buffer.getvalue()
