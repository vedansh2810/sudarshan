from flask import Blueprint, render_template, session, redirect, url_for, request, Response
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.utils.auth_utils import login_required
import io
from datetime import datetime

results_bp = Blueprint('results', __name__)


@results_bp.route('/scan/<int:scan_id>/results')
@login_required
def view(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not scan or scan['user_id'] != session['user_id']:
        return redirect(url_for('dashboard.index'))
    
    severity_filter = request.args.get('severity', 'all')
    type_filter = request.args.get('type', 'all')
    
    vulns = Vulnerability.get_by_scan(scan_id)
    
    if severity_filter != 'all':
        vulns = [v for v in vulns if v['severity'] == severity_filter]
    if type_filter != 'all':
        vulns = [v for v in vulns if v['vuln_type'] == type_filter]
    
    counts = Vulnerability.get_count_by_severity(scan_id)
    all_types = list(set(v['vuln_type'] for v in Vulnerability.get_by_scan(scan_id)))
    
    return render_template(
        'results/view.html',
        scan=scan,
        vulnerabilities=vulns,
        counts=counts,
        all_types=all_types,
        severity_filter=severity_filter,
        type_filter=type_filter
    )

@results_bp.route('/scan/<int:scan_id>/report/pdf')
@login_required
def generate_pdf(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not scan or scan['user_id'] != session['user_id']:
        return redirect(url_for('dashboard.index'))
    
    vulns = Vulnerability.get_by_scan(scan_id)
    
    # Generate HTML report for download
    html = _generate_html_report(scan, vulns)
    return Response(
        html,
        mimetype='text/html',
        headers={
            'Content-Disposition': f'attachment; filename=sudarshan-report-scan{scan_id}.html'
        }
    )

def _generate_html_report(scan, vulns):
    s = dict(scan)
    total = len(vulns)
    critical = sum(1 for v in vulns if v['severity'] == 'critical')
    high = sum(1 for v in vulns if v['severity'] == 'high')
    medium = sum(1 for v in vulns if v['severity'] == 'medium')
    low = sum(1 for v in vulns if v['severity'] in ('low', 'info'))
    
    sev_colors = {'critical':'#dc2626','high':'#ea580c','medium':'#ca8a04','low':'#16a34a','info':'#2563eb'}
    
    vuln_rows = ''
    for i, v in enumerate(vulns, 1):
        v = dict(v)
        color = sev_colors.get(v['severity'], '#888')
        vuln_rows += f"""
        <tr>
            <td>{i}</td>
            <td><strong>{v['name']}</strong></td>
            <td><span style="color:{color};font-weight:700;text-transform:uppercase;">{v['severity']}</span></td>
            <td>{v['cvss_score']}</td>
            <td>{v['owasp_category']}</td>
            <td style="word-break:break-all;max-width:200px;">{v['affected_url']}</td>
        </tr>"""
    
    detail_sections = ''
    for i, v in enumerate(vulns, 1):
        v = dict(v)
        color = sev_colors.get(v['severity'], '#888')
        detail_sections += f"""
        <div class="finding">
            <h3 style="color:{color};">{i}. {v['name']} <span class="sev-badge" style="background:{color}20;color:{color};border:1px solid {color}50;">{v['severity'].upper()}</span></h3>
            <table class="meta-table">
                <tr><td>CVSS Score</td><td><strong style="color:{color};">{v['cvss_score']}/10</strong></td></tr>
                <tr><td>OWASP Category</td><td>{v['owasp_category']}</td></tr>
                <tr><td>Affected URL</td><td style="word-break:break-all;">{v['affected_url']}</td></tr>
                <tr><td>Parameter</td><td><code>{v['parameter']}</code></td></tr>
            </table>
            <h4>Description</h4>
            <p>{v['description']}</p>
            <h4>Impact</h4>
            <p style="color:#d97706;">{v['impact']}</p>
            <h4>Proof of Concept</h4>
            <div class="code-block">{v['payload']}</div>
            <h4 style="color:#4ade80;">Remediation</h4>
            <div class="remediation">{v['remediation']}</div>
        </div>"""
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sudarshan Security Report - Scan #{s['id']}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a1a;color:#e2e8f0;line-height:1.6;}}
.page{{max-width:1000px;margin:0 auto;padding:40px;}}
.header{{background:linear-gradient(135deg,#0f0f2a,#1a1a4e);border:1px solid rgba(0,212,170,0.3);border-radius:16px;padding:36px;margin-bottom:32px;text-align:center;}}
.logo{{font-size:32px;font-weight:900;letter-spacing:3px;color:#00d4aa;margin-bottom:8px;}}
.subtitle{{color:#64748b;font-size:15px;}}
.score-big{{font-size:64px;font-weight:900;margin:16px 0;}}
.score-A{{color:#4ade80;}} .score-B{{color:#a3e635;}} .score-C{{color:#fbbf24;}} .score-D{{color:#fb923c;}} .score-F{{color:#f87171;}}
.meta-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:32px;}}
.meta-box{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:16px;}}
.meta-label{{color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;}}
.meta-val{{font-size:16px;font-weight:700;}}
.summary-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:32px;}}
.sev-box{{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-radius:12px;padding:20px;text-align:center;}}
.sev-num{{font-size:36px;font-weight:900;}} .sev-lbl{{font-size:12px;color:#64748b;}}
h2{{font-size:22px;font-weight:800;color:#e2e8f0;margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid rgba(255,255,255,0.08);}}
h3{{font-size:17px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:12px;}}
h4{{font-size:13px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;margin:14px 0 6px;}}
.sev-badge{{font-size:11px;padding:2px 10px;border-radius:20px;}}
.finding{{background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:24px;margin-bottom:20px;}}
.meta-table{{width:100%;border-collapse:collapse;margin-bottom:12px;font-size:13px;}}
.meta-table td{{padding:6px 12px;border-bottom:1px solid rgba(255,255,255,0.05);}}
.meta-table td:first-child{{color:#64748b;width:130px;}}
code{{background:rgba(255,255,255,0.08);padding:2px 8px;border-radius:4px;font-family:monospace;font-size:12px;}}
.code-block{{background:#050510;border:1px solid rgba(0,212,170,0.15);border-radius:8px;padding:12px 16px;font-family:monospace;font-size:12px;color:#a5f3fc;white-space:pre-wrap;word-break:break-all;margin-bottom:8px;}}
.remediation{{background:rgba(22,163,74,0.08);border:1px solid rgba(22,163,74,0.2);border-radius:10px;padding:14px;color:#4ade80;font-size:14px;}}
table.vuln-table{{width:100%;border-collapse:collapse;font-size:13px;}}
table.vuln-table th{{background:rgba(255,255,255,0.05);color:#94a3b8;padding:10px 14px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;}}
table.vuln-table td{{padding:10px 14px;border-bottom:1px solid rgba(255,255,255,0.05);}}
.footer{{text-align:center;color:#334155;font-size:12px;margin-top:40px;padding-top:24px;border-top:1px solid rgba(255,255,255,0.06);}}
@media print{{body{{background:#fff;color:#000;}} .header{{border-color:#ccc;background:#f8f8f8;}} .logo{{color:#00b38f;}}}}
</style>
</head>
<body>
<div class="page">
    <div class="header">
        <div class="logo">SUDARSHAN</div>
        <div class="subtitle">Web Vulnerability Scanner &bull; Security Assessment Report</div>
        <div class="score-big score-{s.get('score', 'F')}">{s.get('score', '?')}</div>
        <div style="color:#64748b;font-size:14px;">Overall Security Score</div>
    </div>
    
    <h2>1. Executive Summary</h2>
    <p style="color:#94a3b8;margin-bottom:20px;">This report presents the automated security assessment findings for <strong style="color:#e2e8f0;">{s['target_url']}</strong>. 
    A total of <strong style="color:#e2e8f0;">{total} vulnerabilities</strong> were identified across {s.get('total_urls',0)} crawled URLs.</p>
    
    <div class="summary-grid">
        <div class="sev-box"><div class="sev-num" style="color:#dc2626;">{critical}</div><div class="sev-lbl">Critical</div></div>
        <div class="sev-box"><div class="sev-num" style="color:#ea580c;">{high}</div><div class="sev-lbl">High</div></div>
        <div class="sev-box"><div class="sev-num" style="color:#ca8a04;">{medium}</div><div class="sev-lbl">Medium</div></div>
        <div class="sev-box"><div class="sev-num" style="color:#16a34a;">{low}</div><div class="sev-lbl">Low / Info</div></div>
    </div>
    
    <h2>2. Target Information</h2>
    <div class="meta-grid">
        <div class="meta-box"><div class="meta-label">Target URL</div><div class="meta-val" style="font-size:13px;word-break:break-all;">{s['target_url']}</div></div>
        <div class="meta-box"><div class="meta-label">Scan Mode</div><div class="meta-val">{s.get('scan_mode','active').title()}</div></div>
        <div class="meta-box"><div class="meta-label">Scan Speed</div><div class="meta-val">{s.get('scan_speed','balanced').title()}</div></div>
        <div class="meta-box"><div class="meta-label">Crawl Depth</div><div class="meta-val">{s.get('crawl_depth',3)}</div></div>
        <div class="meta-box"><div class="meta-label">URLs Crawled</div><div class="meta-val">{s.get('total_urls',0)}</div></div>
        <div class="meta-box"><div class="meta-label">Duration</div><div class="meta-val">{s.get('duration',0)}s</div></div>
        <div class="meta-box"><div class="meta-label">Started</div><div class="meta-val" style="font-size:13px;">{str(s.get('started_at',''))[:16]}</div></div>
        <div class="meta-box"><div class="meta-label">Completed</div><div class="meta-val" style="font-size:13px;">{str(s.get('completed_at',''))[:16] if s.get('completed_at') else 'N/A'}</div></div>
    </div>
    
    <h2>3. Vulnerability Summary</h2>
    <table class="vuln-table">
        <thead>
            <tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>CVSS</th><th>OWASP</th><th>Affected URL</th></tr>
        </thead>
        <tbody>{vuln_rows}</tbody>
    </table>
    
    <h2>4. Detailed Findings</h2>
    {detail_sections if detail_sections else '<p style="color:#64748b;">No vulnerabilities found.</p>'}
    
    <h2>5. Conclusion &amp; Recommendations</h2>
    <div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:12px;padding:24px;color:#94a3b8;line-height:1.8;">
        <p>This automated scan has identified security issues requiring attention. Prioritize <strong style="color:#dc2626;">Critical</strong> and 
        <strong style="color:#ea580c;">High</strong> severity findings immediately. Consider implementing a Web Application Firewall (WAF) as a 
        compensating control, establish a regular security scanning cadence, and engage in professional manual penetration testing for 
        comprehensive coverage. Security is an ongoing practice — remediate, retest, and repeat.</p>
    </div>
    
    <div class="footer">
        Generated by Sudarshan Web Vulnerability Scanner &bull; {datetime.now().strftime('%Y-%m-%d %H:%M')} &bull; For authorized use only
    </div>
</div>
</body>
</html>"""
