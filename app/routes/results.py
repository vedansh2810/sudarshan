from flask import Blueprint, render_template, session, redirect, url_for, request, Response
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.utils.auth_utils import login_required
from app.utils.auth_helpers import user_can_access_scan
import html as html_lib
import json
import logging
from datetime import datetime
from fpdf import FPDF
import io

logger = logging.getLogger(__name__)
results_bp = Blueprint('results', __name__)


@results_bp.route('/scan/<int:scan_id>/results')
@login_required
def view(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return redirect(url_for('dashboard.index'))
    
    severity_filter = request.args.get('severity', 'all')
    type_filter = request.args.get('type', 'all')
    
    all_vulns = Vulnerability.get_by_scan(scan_id)
    all_types = list(set(v['vuln_type'] for v in all_vulns))
    
    vulns = all_vulns
    if severity_filter != 'all':
        vulns = [v for v in vulns if v['severity'] == severity_filter]
    if type_filter != 'all':
        vulns = [v for v in vulns if v['vuln_type'] == type_filter]
    
    # Parse AI data for template
    for v in vulns:
        if v.get('ai_analysis') and isinstance(v['ai_analysis'], str):
            try:
                v['ai_analysis_parsed'] = json.loads(v['ai_analysis'])
            except Exception:
                v['ai_analysis_parsed'] = None
        if v.get('ai_narrative') and isinstance(v['ai_narrative'], str):
            try:
                v['ai_narrative_parsed'] = json.loads(v['ai_narrative'])
            except Exception:
                v['ai_narrative_parsed'] = None
    
    counts = Vulnerability.get_count_by_severity(scan_id)
    
    return render_template(
        'results/view.html',
        scan=scan,
        vulnerabilities=vulns,
        counts=counts,
        all_types=all_types,
        severity_filter=severity_filter,
        type_filter=type_filter
    )

@results_bp.route('/scan/<int:scan_id>/report/html')
@login_required
def generate_html(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return redirect(url_for('dashboard.index'))
    
    vulns = Vulnerability.get_by_scan(scan_id)
    
    # Generate AI executive summary
    ai_summary = _get_ai_executive_summary(scan, vulns)
    
    html = _generate_html_report(scan, vulns, ai_summary=ai_summary)
    return Response(
        html,
        mimetype='text/html',
        headers={
            'Content-Disposition': f'attachment; filename=sudarshan-report-scan{scan_id}.html'
        }
    )

@results_bp.route('/scan/<int:scan_id>/report/pdf')
@login_required
def generate_pdf(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return redirect(url_for('dashboard.index'))
    
    vulns = Vulnerability.get_by_scan(scan_id)
    
    # Generate AI executive summary
    ai_summary = _get_ai_executive_summary(scan, vulns)
    
    pdf_bytes = _generate_pdf_report(scan, vulns, ai_summary=ai_summary)
    return Response(
        pdf_bytes,
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'attachment; filename=sudarshan-report-scan{scan_id}.pdf'
        }
    )

def _safe(val):
    """Return a latin-1 safe string for fpdf (which uses latin-1 by default)."""
    text = str(val) if val is not None else ''
    return text.encode('latin-1', 'replace').decode('latin-1')


def _get_ai_executive_summary(scan, vulns):
    """Generate an AI executive summary using report_writer. Returns str or None."""
    try:
        from app.ai.report_writer import generate_executive_summary
        s = dict(scan)
        from collections import Counter
        type_counter = Counter(v['vuln_type'] for v in vulns)
        top_types = ', '.join(f"{t} ({c})" for t, c in type_counter.most_common(5))

        scan_data = {
            'target_url': s['target_url'],
            'scan_date': str(s.get('started_at', ''))[:16],
            'total_urls': s.get('total_urls', 0),
            'total_vulns': len(vulns),
            'critical': sum(1 for v in vulns if v['severity'] == 'critical'),
            'high': sum(1 for v in vulns if v['severity'] == 'high'),
            'medium': sum(1 for v in vulns if v['severity'] == 'medium'),
            'low': sum(1 for v in vulns if v['severity'] in ('low', 'info')),
            'info': sum(1 for v in vulns if v['severity'] == 'info'),
            'top_types': top_types or 'None',
        }
        return generate_executive_summary(scan_data)
    except Exception as e:
        logger.debug(f"AI executive summary failed: {e}")
        return None


def _get_ai_narrative(vuln):
    """Extract AI narrative text from a vulnerability's ai_narrative JSON."""
    try:
        raw = vuln.get('ai_narrative')
        if not raw:
            return None
        data = json.loads(raw) if isinstance(raw, str) else raw
        if isinstance(data, dict):
            return data.get('narrative', data.get('attack_narrative', str(data)))
        return str(data) if data else None
    except Exception:
        return None


def _generate_pdf_report(scan, vulns, ai_summary=None):
    s = dict(scan)
    total = len(vulns)
    critical = sum(1 for v in vulns if v['severity'] == 'critical')
    high = sum(1 for v in vulns if v['severity'] == 'high')
    medium = sum(1 for v in vulns if v['severity'] == 'medium')
    low = sum(1 for v in vulns if v['severity'] in ('low', 'info'))
    
    sev_colors = {
        'critical': (220, 38, 38),
        'high': (234, 88, 12),
        'medium': (202, 138, 4),
        'low': (22, 163, 74),
        'info': (37, 99, 235),
    }

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # ── Header ──
    pdf.set_fill_color(10, 10, 26)
    pdf.rect(0, 0, 210, 50, 'F')
    pdf.set_text_color(0, 212, 170)
    pdf.set_font('Helvetica', 'B', 24)
    pdf.set_y(12)
    pdf.cell(0, 10, 'SUDARSHAN', ln=True, align='C')
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 6, 'Web Vulnerability Scanner  |  Security Assessment Report', ln=True, align='C')
    score = _safe(s.get('score', '?'))
    pdf.set_font('Helvetica', 'B', 36)
    score_colors = {'A': (74, 222, 128), 'B': (163, 230, 53), 'C': (251, 191, 36), 'D': (251, 146, 60), 'F': (248, 113, 113)}
    sc = score_colors.get(score, (148, 163, 184))
    pdf.set_text_color(*sc)
    pdf.cell(0, 18, score, ln=True, align='C')

    pdf.set_y(55)

    # ── 1. Executive Summary ──
    pdf.set_text_color(30, 30, 30)
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, '1. Executive Summary', ln=True)
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(60, 60, 60)
    if ai_summary:
        pdf.multi_cell(0, 5, _safe(ai_summary[:2000]))
    else:
        pdf.multi_cell(0, 5,
            f"This report presents the automated security assessment findings for {_safe(s['target_url'])}. "
            f"A total of {total} vulnerabilities were identified across {s.get('total_urls', 0)} crawled URLs."
        )
    pdf.ln(3)

    # Severity summary boxes
    pdf.set_font('Helvetica', 'B', 10)
    box_w = 42
    start_x = 12
    for label, count, color in [('Critical', critical, (220,38,38)), ('High', high, (234,88,12)), ('Medium', medium, (202,138,4)), ('Low/Info', low, (22,163,74))]:
        pdf.set_xy(start_x, pdf.get_y())
        pdf.set_draw_color(*color)
        pdf.set_text_color(*color)
        pdf.rect(start_x, pdf.get_y(), box_w, 14)
        pdf.set_xy(start_x, pdf.get_y() + 1)
        pdf.cell(box_w, 5, str(count), align='C')
        pdf.set_xy(start_x, pdf.get_y() + 5)
        pdf.set_font('Helvetica', '', 8)
        pdf.cell(box_w, 5, label, align='C')
        pdf.set_font('Helvetica', 'B', 10)
        start_x += box_w + 4
    pdf.ln(20)

    # ── 2. Target Information ──
    pdf.set_text_color(30, 30, 30)
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, '2. Target Information', ln=True)
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    info_rows = [
        ('Target URL', _safe(s['target_url'])),
        ('Scan Mode', _safe(s.get('scan_mode', 'active')).title()),
        ('Scan Speed', _safe(s.get('scan_speed', 'balanced')).title()),
        ('Crawl Depth', str(s.get('crawl_depth', 3))),
        ('URLs Crawled', str(s.get('total_urls', 0))),
        ('Duration', f"{s.get('duration', 0)}s"),
        ('Started', str(s.get('started_at', ''))[:16]),
        ('Completed', str(s.get('completed_at', ''))[:16] if s.get('completed_at') else 'N/A'),
    ]
    pdf.set_font('Helvetica', '', 9)
    for label, val in info_rows:
        pdf.set_text_color(100, 100, 100)
        pdf.cell(40, 6, label, border='B')
        pdf.set_text_color(30, 30, 30)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 6, val, border='B', ln=True)
        pdf.set_font('Helvetica', '', 9)
    pdf.ln(5)

    # ── 3. Vulnerability Summary Table ──
    pdf.set_text_color(30, 30, 30)
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, '3. Vulnerability Summary', ln=True)
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    if vulns:
        # Table header
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_text_color(60, 60, 60)
        col_widths = [8, 55, 20, 15, 30, 62]
        headers = ['#', 'Vulnerability', 'Severity', 'CVSS', 'OWASP', 'Affected URL']
        for i, h in enumerate(headers):
            pdf.cell(col_widths[i], 7, h, border=1, fill=True, align='C')
        pdf.ln()

        # Table rows
        pdf.set_font('Helvetica', '', 7)
        for idx, v in enumerate(vulns, 1):
            v = dict(v)
            color = sev_colors.get(v['severity'], (128, 128, 128))
            y_before = pdf.get_y()
            if y_before > 260:
                pdf.add_page()
            pdf.set_text_color(30, 30, 30)
            pdf.cell(col_widths[0], 6, str(idx), border=1, align='C')
            pdf.cell(col_widths[1], 6, _safe(v['name'])[:45], border=1)
            pdf.set_text_color(*color)
            pdf.set_font('Helvetica', 'B', 7)
            pdf.cell(col_widths[2], 6, _safe(v['severity']).upper(), border=1, align='C')
            pdf.set_text_color(30, 30, 30)
            pdf.set_font('Helvetica', '', 7)
            pdf.cell(col_widths[3], 6, str(v.get('cvss_score', '')), border=1, align='C')
            pdf.cell(col_widths[4], 6, _safe(v.get('owasp_category', ''))[:22], border=1)
            pdf.cell(col_widths[5], 6, _safe(v.get('affected_url', ''))[:48], border=1)
            pdf.ln()
    else:
        pdf.set_font('Helvetica', 'I', 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 8, 'No vulnerabilities found.', ln=True)
    pdf.ln(5)

    # ── 4. Detailed Findings ──
    pdf.set_text_color(30, 30, 30)
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, '4. Detailed Findings', ln=True)
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    for idx, v in enumerate(vulns, 1):
        v = dict(v)
        color = sev_colors.get(v['severity'], (128, 128, 128))
        lm = pdf.l_margin
        full_w = pdf.w - pdf.l_margin - pdf.r_margin

        if pdf.get_y() > 230:
            pdf.add_page()

        # Finding title
        pdf.set_x(lm)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(*color)
        pdf.multi_cell(full_w, 7, f"{idx}. {_safe(v['name'])}  [{_safe(v['severity']).upper()}]")

        # Detail items as simple key: value rows
        pdf.set_font('Helvetica', '', 9)
        detail_items = [
            ('CVSS Score', f"{v.get('cvss_score', 'N/A')}/10"),
            ('OWASP', _safe(v.get('owasp_category', 'N/A'))),
            ('Affected URL', _safe(v.get('affected_url', 'N/A'))),
            ('Parameter', _safe(v.get('parameter', 'N/A'))),
        ]
        for label, val in detail_items:
            pdf.set_x(lm)
            pdf.set_text_color(100, 100, 100)
            pdf.set_font('Helvetica', '', 9)
            label_w = 32
            pdf.cell(label_w, 5, label + ':', 0, 0)
            pdf.set_text_color(30, 30, 30)
            # Use multi_cell with explicit width for the value
            remaining_w = full_w - label_w
            safe_val = (val[:90] if val else 'N/A')
            pdf.multi_cell(remaining_w, 5, safe_val)

        # Description
        if v.get('description'):
            pdf.set_x(lm)
            pdf.set_text_color(80, 80, 80)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(full_w, 6, 'Description:', ln=True)
            pdf.set_x(lm)
            pdf.set_font('Helvetica', '', 8)
            pdf.multi_cell(full_w, 4, _safe(v['description'])[:500])

        # Impact
        if v.get('impact'):
            pdf.set_x(lm)
            pdf.set_text_color(180, 120, 0)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(full_w, 6, 'Impact:', ln=True)
            pdf.set_x(lm)
            pdf.set_font('Helvetica', '', 8)
            pdf.multi_cell(full_w, 4, _safe(v['impact'])[:500])

        # Payload / PoC
        if v.get('payload'):
            pdf.set_x(lm)
            pdf.set_text_color(60, 60, 60)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(full_w, 6, 'Proof of Concept:', ln=True)
            pdf.set_x(lm)
            pdf.set_font('Courier', '', 7)
            pdf.set_fill_color(245, 245, 250)
            pdf.multi_cell(full_w, 4, _safe(v['payload'])[:400], fill=True)

        # Remediation
        if v.get('remediation'):
            pdf.set_x(lm)
            pdf.set_text_color(22, 163, 74)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(full_w, 6, 'Remediation:', ln=True)
            pdf.set_x(lm)
            pdf.set_font('Helvetica', '', 8)
            pdf.multi_cell(full_w, 4, _safe(v['remediation'])[:500])

        # AI Attack Narrative
        narrative = _get_ai_narrative(v)
        if narrative:
            if pdf.get_y() > 240:
                pdf.add_page()
            pdf.set_x(lm)
            pdf.set_text_color(0, 150, 200)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(full_w, 6, 'AI Attack Narrative:', ln=True)
            pdf.set_x(lm)
            pdf.set_font('Helvetica', '', 8)
            pdf.set_text_color(80, 80, 80)
            pdf.multi_cell(full_w, 4, _safe(narrative)[:600])

        # False Positive Badge
        if v.get('likely_false_positive'):
            pdf.set_x(lm)
            pdf.set_fill_color(255, 240, 200)
            pdf.set_text_color(180, 120, 0)
            pdf.set_font('Helvetica', 'B', 8)
            fp_conf = v.get('fp_confidence')
            fp_text = 'LIKELY FALSE POSITIVE'
            if fp_conf is not None:
                fp_text += f' (confidence: {fp_conf:.0%})'
            pdf.cell(full_w, 6, fp_text, fill=True, ln=True, align='C')
            pdf.set_text_color(30, 30, 30)

        pdf.ln(4)
        pdf.set_draw_color(220, 220, 220)
        pdf.line(lm, pdf.get_y(), lm + full_w, pdf.get_y())
        pdf.ln(4)

    # ── 5. Conclusion ──
    if pdf.get_y() > 240:
        pdf.add_page()
    pdf.set_text_color(30, 30, 30)
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, '5. Conclusion & Recommendations', ln=True)
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(60, 60, 60)
    pdf.multi_cell(0, 5,
        "This automated scan has identified security issues requiring attention. Prioritize Critical and High severity "
        "findings immediately. Consider implementing a Web Application Firewall (WAF) as a compensating control, "
        "establish a regular security scanning cadence, and engage in professional manual penetration testing for "
        "comprehensive coverage. Security is an ongoing practice - remediate, retest, and repeat."
    )

    # ── Footer ──
    pdf.ln(10)
    pdf.set_font('Helvetica', 'I', 8)
    pdf.set_text_color(140, 140, 140)
    pdf.cell(0, 5, f"Generated by Sudarshan Web Vulnerability Scanner  |  {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  For authorized use only", align='C')

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()

def _esc(val):
    """HTML-escape a value, handling None."""
    return html_lib.escape(str(val)) if val is not None else ''

def _generate_html_report(scan, vulns, ai_summary=None):
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
            <td><strong>{_esc(v['name'])}</strong></td>
            <td><span style="color:{color};font-weight:700;text-transform:uppercase;">{_esc(v['severity'])}</span></td>
            <td>{_esc(v['cvss_score'])}</td>
            <td>{_esc(v['owasp_category'])}</td>
            <td style="word-break:break-all;max-width:200px;">{_esc(v['affected_url'])}</td>
        </tr>"""
    
    detail_sections = ''
    for i, v in enumerate(vulns, 1):
        v = dict(v)
        color = sev_colors.get(v['severity'], '#888')
        detail_sections += f"""
        <div class="finding">
            <h3 style="color:{color};">{i}. {_esc(v['name'])} <span class="sev-badge" style="background:{color}20;color:{color};border:1px solid {color}50;">{_esc(v['severity']).upper()}</span></h3>
            <table class="meta-table">
                <tr><td>CVSS Score</td><td><strong style="color:{color};">{_esc(v['cvss_score'])}/10</strong></td></tr>
                <tr><td>OWASP Category</td><td>{_esc(v['owasp_category'])}</td></tr>
                <tr><td>Affected URL</td><td style="word-break:break-all;">{_esc(v['affected_url'])}</td></tr>
                <tr><td>Parameter</td><td><code>{_esc(v['parameter'])}</code></td></tr>
            </table>
            <h4>Description</h4>
            <p>{_esc(v['description'])}</p>
            <h4>Impact</h4>
            <p style="color:#d97706;">{_esc(v['impact'])}</p>
            <h4>Proof of Concept</h4>
            <div class="code-block">{_esc(v['payload'])}</div>
            <h4 style="color:#4ade80;">Remediation</h4>
            <div class="remediation">{_esc(v['remediation'])}</div>
            {'<div style="margin-top:16px;"><h4 style="color:#0096c8;">AI Attack Narrative</h4><p style="color:#94a3b8;font-size:14px;line-height:1.7;">' + _esc(_get_ai_narrative(v) or '') + '</p></div>' if _get_ai_narrative(v) else ''}
            {'<div style="margin-top:12px;background:rgba(255,200,0,0.08);border:1px solid rgba(255,200,0,0.3);border-radius:8px;padding:10px 16px;text-align:center;"><span style="color:#fbbf24;font-weight:700;">⚠ LIKELY FALSE POSITIVE</span>' + (f' <span style="color:#94a3b8;">(confidence: {v.get("fp_confidence", 0):.0%})</span>' if v.get('fp_confidence') else '') + '</div>' if v.get('likely_false_positive') else ''}
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
        <div class="score-big score-{_esc(s.get('score', 'F'))}">{_esc(s.get('score', '?'))}</div>
        <div style="color:#64748b;font-size:14px;">Overall Security Score</div>
    </div>
    
    <h2>1. Executive Summary</h2>
    <p style="color:#94a3b8;margin-bottom:20px;">{_esc(ai_summary) if ai_summary else f'This report presents the automated security assessment findings for <strong style="color:#e2e8f0;">{_esc(s["target_url"])}</strong>. A total of <strong style="color:#e2e8f0;">{total} vulnerabilities</strong> were identified across {s.get("total_urls",0)} crawled URLs.'}</p>
    
    <div class="summary-grid">
        <div class="sev-box"><div class="sev-num" style="color:#dc2626;">{critical}</div><div class="sev-lbl">Critical</div></div>
        <div class="sev-box"><div class="sev-num" style="color:#ea580c;">{high}</div><div class="sev-lbl">High</div></div>
        <div class="sev-box"><div class="sev-num" style="color:#ca8a04;">{medium}</div><div class="sev-lbl">Medium</div></div>
        <div class="sev-box"><div class="sev-num" style="color:#16a34a;">{low}</div><div class="sev-lbl">Low / Info</div></div>
    </div>
    
    <h2>2. Target Information</h2>
    <div class="meta-grid">
        <div class="meta-box"><div class="meta-label">Target URL</div><div class="meta-val" style="font-size:13px;word-break:break-all;">{_esc(s['target_url'])}</div></div>
        <div class="meta-box"><div class="meta-label">Scan Mode</div><div class="meta-val">{_esc(s.get('scan_mode','active').title())}</div></div>
        <div class="meta-box"><div class="meta-label">Scan Speed</div><div class="meta-val">{_esc(s.get('scan_speed','balanced').title())}</div></div>
        <div class="meta-box"><div class="meta-label">Crawl Depth</div><div class="meta-val">{s.get('crawl_depth',3)}</div></div>
        <div class="meta-box"><div class="meta-label">URLs Crawled</div><div class="meta-val">{s.get('total_urls',0)}</div></div>
        <div class="meta-box"><div class="meta-label">Duration</div><div class="meta-val">{s.get('duration',0)}s</div></div>
        <div class="meta-box"><div class="meta-label">Started</div><div class="meta-val" style="font-size:13px;">{_esc(str(s.get('started_at',''))[:16])}</div></div>
        <div class="meta-box"><div class="meta-label">Completed</div><div class="meta-val" style="font-size:13px;">{_esc(str(s.get('completed_at',''))[:16]) if s.get('completed_at') else 'N/A'}</div></div>
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
