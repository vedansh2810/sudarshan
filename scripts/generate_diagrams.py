"""Generate diagrams for the Sudarshan project report using matplotlib."""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import os

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'report_diagrams')
os.makedirs(OUT_DIR, exist_ok=True)

# ── Color palette ──
NAVY = '#1a2744'
BLUE = '#2563eb'
LIGHT_BLUE = '#dbeafe'
TEAL = '#0d9488'
LIGHT_TEAL = '#ccfbf1'
PURPLE = '#7c3aed'
LIGHT_PURPLE = '#ede9fe'
ORANGE = '#ea580c'
LIGHT_ORANGE = '#fed7aa'
GRAY = '#f3f4f6'
WHITE = '#ffffff'
DARK = '#111827'


def draw_box(ax, x, y, w, h, label, facecolor, edgecolor, fontsize=9, bold=True):
    box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02",
                         facecolor=facecolor, edgecolor=edgecolor, linewidth=1.5)
    ax.add_patch(box)
    weight = 'bold' if bold else 'normal'
    ax.text(x + w/2, y + h/2, label, ha='center', va='center',
            fontsize=fontsize, fontweight=weight, color=DARK, wrap=True)


def draw_arrow(ax, x1, y1, x2, y2, label=''):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='->', color=NAVY, lw=1.5))
    if label:
        mx, my = (x1+x2)/2, (y1+y2)/2
        ax.text(mx, my+0.02, label, ha='center', va='bottom', fontsize=7, color=NAVY)


# ═══════════════════════════════════════════
# 1. System Architecture Diagram
# ═══════════════════════════════════════════
def gen_architecture():
    fig, ax = plt.subplots(1, 1, figsize=(11, 8))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 8)
    ax.axis('off')
    ax.set_title('System Architecture — Sudarshan', fontsize=14, fontweight='bold', pad=15, color=NAVY)

    # Client
    draw_box(ax, 4.0, 7.0, 3.0, 0.6, 'Client Browser', LIGHT_BLUE, BLUE, 11)
    draw_arrow(ax, 5.5, 7.0, 5.5, 6.65)

    # Flask Web Server
    draw_box(ax, 1.5, 5.5, 8.0, 1.1, '', GRAY, BLUE)
    ax.text(5.5, 6.45, 'Flask Web Server (Gunicorn)', ha='center', fontsize=10, fontweight='bold', color=NAVY)
    labels = ['Auth\nRoutes', 'Dashboard\nRoutes', 'Scan\nRoutes', 'Results\nRoutes', 'API v2\nRoutes', 'Jinja2\nTemplates']
    for i, lbl in enumerate(labels):
        draw_box(ax, 1.7 + i*1.3, 5.6, 1.15, 0.55, lbl, WHITE, BLUE, 7, False)

    # Supabase Auth (left)
    draw_box(ax, 0.0, 5.7, 1.3, 0.7, 'Supabase\nAuth', LIGHT_PURPLE, PURPLE, 8)
    draw_arrow(ax, 1.3, 6.05, 1.5, 6.05, '')

    # Scanner Engine
    draw_box(ax, 0.3, 3.3, 5.0, 1.8, '', LIGHT_TEAL, TEAL)
    ax.text(2.8, 4.95, 'Scanner Engine', ha='center', fontsize=10, fontweight='bold', color=TEAL)
    draw_box(ax, 0.5, 4.1, 2.2, 0.55, 'Scan Manager\n(Celery / Threading)', WHITE, TEAL, 7, False)
    draw_box(ax, 2.9, 4.1, 2.2, 0.55, 'Multi-threaded\nCrawler', WHITE, TEAL, 7, False)
    draw_box(ax, 0.5, 3.45, 2.2, 0.5, '16 Vulnerability\nScanner Modules', WHITE, TEAL, 7, False)
    draw_box(ax, 2.9, 3.45, 2.2, 0.5, 'Payload\nManager', WHITE, TEAL, 7, False)

    draw_arrow(ax, 3.5, 5.5, 2.8, 5.1)

    # AI/ML Layer
    draw_box(ax, 5.8, 3.3, 5.0, 1.8, '', LIGHT_PURPLE, PURPLE)
    ax.text(8.3, 4.95, 'AI / ML Intelligence Layer', ha='center', fontsize=10, fontweight='bold', color=PURPLE)
    draw_box(ax, 6.0, 4.1, 2.2, 0.55, 'SmartEngine\n(Unified AI Layer)', WHITE, PURPLE, 7, False)
    draw_box(ax, 8.4, 4.1, 2.2, 0.55, 'Groq LLM\n(Llama 3.3 70B)', WHITE, PURPLE, 7, False)
    draw_box(ax, 6.0, 3.45, 2.2, 0.5, 'PortSwigger KB\n(269 Labs)', WHITE, PURPLE, 7, False)
    draw_box(ax, 8.4, 3.45, 2.2, 0.5, 'ML FP Classifier\n(RF + GB)', WHITE, PURPLE, 7, False)

    draw_arrow(ax, 7.5, 5.5, 8.3, 5.1)
    draw_arrow(ax, 5.3, 4.2, 5.8, 4.2, '')

    # Data Layer
    draw_box(ax, 0.5, 1.2, 4.5, 1.5, '', LIGHT_ORANGE, ORANGE)
    ax.text(2.75, 2.55, 'Data Storage', ha='center', fontsize=10, fontweight='bold', color=ORANGE)
    draw_box(ax, 0.7, 1.35, 2.0, 0.85, 'PostgreSQL\n(Supabase)\n+ SQLAlchemy', WHITE, ORANGE, 7, False)
    draw_box(ax, 2.9, 1.35, 2.0, 0.85, 'SQLite\n(Dev Fallback)\n+ Migrations', WHITE, ORANGE, 7, False)

    draw_arrow(ax, 2.8, 3.3, 2.75, 2.7)

    # Infrastructure
    draw_box(ax, 5.8, 1.2, 5.0, 1.5, '', LIGHT_BLUE, BLUE)
    ax.text(8.3, 2.55, 'Infrastructure', ha='center', fontsize=10, fontweight='bold', color=BLUE)
    draw_box(ax, 6.0, 1.35, 2.2, 0.85, 'Docker + Gunicorn\nCelery + Redis\n(3 Services)', WHITE, BLUE, 7, False)
    draw_box(ax, 8.4, 1.35, 2.2, 0.85, 'SSE Streaming\nPrometheus\nRate Limiting', WHITE, BLUE, 7, False)

    draw_arrow(ax, 8.3, 3.3, 8.3, 2.7)

    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, 'system_architecture.png'), dpi=200, bbox_inches='tight')
    plt.close(fig)
    print('✓ System Architecture')


# ═══════════════════════════════════════════
# 2. Scan Pipeline Diagram
# ═══════════════════════════════════════════
def gen_pipeline():
    fig, ax = plt.subplots(1, 1, figsize=(12, 5))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 5)
    ax.axis('off')
    ax.set_title('Scan Pipeline — Data Flow', fontsize=14, fontweight='bold', pad=15, color=NAVY)

    phases = [
        ('Phase 0\nConnectivity\nCheck', 'HTTP GET\nVerify target\nreachability', LIGHT_BLUE, BLUE),
        ('Phase 1\nWeb\nCrawling', 'Multi-threaded\nDiscover URLs\nForms & Params', LIGHT_TEAL, TEAL),
        ('Phase 1.5\nAI Recon', 'LLM detects\nTech stack\nWAF & Framework', LIGHT_PURPLE, PURPLE),
        ('Phase 2\nVulnerability\nScanning', '16 scanners\nAI Analysis\nFP Verification', LIGHT_ORANGE, ORANGE),
        ('Phase 3\nPost-Scan\nAI Analysis', 'Executive summary\nRemediation plan\nAttack narratives', LIGHT_PURPLE, PURPLE),
    ]

    for i, (title, desc, fc, ec) in enumerate(phases):
        x = 0.3 + i * 2.35
        draw_box(ax, x, 2.5, 2.0, 1.5, '', fc, ec)
        ax.text(x + 1.0, 3.7, title, ha='center', va='center', fontsize=9, fontweight='bold', color=ec)
        ax.text(x + 1.0, 2.95, desc, ha='center', va='center', fontsize=7, color=DARK)
        if i < len(phases) - 1:
            draw_arrow(ax, x + 2.0, 3.25, x + 2.35, 3.25)

    # Phase 2 sub-flow (below)
    ax.text(5.45, 2.1, 'For each finding:', ha='center', fontsize=8, fontweight='bold', color=ORANGE)
    steps = ['Save to DB', 'AI Analysis\n(OWASP/CWE)', 'FP Verify\n(ML 40%+LLM 60%)', 'Attack\nNarrative']
    for i, s in enumerate(steps):
        x = 3.2 + i * 1.6
        draw_box(ax, x, 0.8, 1.35, 0.9, s, WHITE, ORANGE, 7, False)
        if i < len(steps) - 1:
            draw_arrow(ax, x + 1.35, 1.25, x + 1.6, 1.25)

    draw_arrow(ax, 5.45, 2.5, 5.45, 2.1)

    # SSE label
    ax.text(9.0, 1.9, '↑ Real-time SSE\nProgress Streaming', ha='center', fontsize=7,
            color=BLUE, style='italic')

    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, 'scan_pipeline.png'), dpi=200, bbox_inches='tight')
    plt.close(fig)
    print('✓ Scan Pipeline')


# ═══════════════════════════════════════════
# 3. ER Diagram
# ═══════════════════════════════════════════
def gen_er():
    fig, ax = plt.subplots(1, 1, figsize=(12, 9))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 9)
    ax.axis('off')
    ax.set_title('Database Entity-Relationship Diagram', fontsize=14, fontweight='bold', pad=15, color=NAVY)

    def draw_table(ax, x, y, name, cols, w=2.8):
        h_header = 0.35
        h_row = 0.22
        total_h = h_header + h_row * len(cols)
        # Header
        header = FancyBboxPatch((x, y - h_header), w, h_header,
                                boxstyle="round,pad=0.01", facecolor=BLUE, edgecolor=NAVY, lw=1.2)
        ax.add_patch(header)
        ax.text(x + w/2, y - h_header/2, name, ha='center', va='center',
                fontsize=9, fontweight='bold', color=WHITE)
        # Rows
        for i, col in enumerate(cols):
            ry = y - h_header - h_row * (i + 1)
            row = FancyBboxPatch((x, ry), w, h_row,
                                 boxstyle="round,pad=0.005", facecolor=WHITE, edgecolor='#d1d5db', lw=0.5)
            ax.add_patch(row)
            ax.text(x + 0.08, ry + h_row/2, col, ha='left', va='center', fontsize=6.5, color=DARK)
        return total_h

    # Users
    draw_table(ax, 0.3, 8.2, 'users', ['PK id', 'supabase_uid', 'username', 'email', 'is_admin'])
    # Scans
    draw_table(ax, 4.5, 8.5, 'scans', ['PK id', 'FK user_id → users', 'FK org_id → organizations',
               'target_url', 'scan_mode / scan_speed', 'status / score', 'vuln_count / duration'])
    # Vulnerabilities
    draw_table(ax, 8.5, 8.5, 'vulnerabilities', ['PK id', 'FK scan_id → scans', 'vuln_type / severity',
               'cvss_score / owasp_category', 'affected_url / parameter', 'payload / request_data',
               'ai_analysis / ai_narrative', 'fp_confidence'])
    # Organizations
    draw_table(ax, 0.3, 5.8, 'organizations', ['PK id', 'name / slug', 'plan (free/pro/enterprise)'])
    # Org Memberships
    draw_table(ax, 0.3, 4.5, 'org_memberships', ['FK user_id → users', 'FK org_id → organizations', 'role'])
    # Crawled URLs
    draw_table(ax, 4.5, 5.5, 'crawled_urls', ['PK id', 'FK scan_id → scans', 'url / status_code', 'forms_found'])
    # Scan Logs
    draw_table(ax, 4.5, 4.0, 'scan_logs', ['PK id', 'FK scan_id → scans', 'log_type / message'])
    # Webhooks
    draw_table(ax, 8.5, 5.5, 'webhooks', ['PK id', 'FK user_id → users', 'url / is_active', 'failure_count'])
    # API Keys
    draw_table(ax, 8.5, 4.0, 'api_keys', ['PK id', 'FK user_id → users', 'key_hash (HMAC-SHA256)', 'is_active / expires_at'])
    # Scan Attempts
    draw_table(ax, 4.5, 2.5, 'scan_attempts', ['PK id', 'FK scan_id → scans', 'url / parameter / payload', 'features (JSON / ML)'])
    # ML Models
    draw_table(ax, 8.5, 2.5, 'ml_models', ['PK id', 'name / version', 'training_accuracy / f1_score', 'is_active / model_path'])

    # Relationships with lines (simplified)
    lines = [
        (3.1, 7.9, 4.5, 8.1),   # users → scans
        (7.3, 8.0, 8.5, 8.0),   # scans → vulns
        (3.1, 5.5, 4.5, 5.3),   # orgs → crawled (via scans)
        (5.9, 7.5, 5.9, 5.5),   # scans → crawled
        (5.9, 5.0, 5.9, 4.0),   # scans → logs
        (5.9, 3.5, 5.9, 2.5),   # scans → attempts
        (3.1, 7.5, 8.5, 5.3),   # users → webhooks
        (3.1, 7.2, 8.5, 3.8),   # users → api_keys
        (1.7, 5.1, 1.7, 4.5),   # orgs → memberships
        (1.7, 7.0, 1.7, 5.8),   # users → orgs (memberships)
    ]
    for x1, y1, x2, y2 in lines:
        ax.plot([x1, x2], [y1, y2], '-', color='#6b7280', lw=0.8, alpha=0.6)

    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, 'er_diagram.png'), dpi=200, bbox_inches='tight')
    plt.close(fig)
    print('✓ ER Diagram')


# ═══════════════════════════════════════════
# 4. AI/ML Integration Diagram
# ═══════════════════════════════════════════
def gen_ai_ml():
    fig, ax = plt.subplots(1, 1, figsize=(11, 7))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 7)
    ax.axis('off')
    ax.set_title('AI/ML Integration Architecture', fontsize=14, fontweight='bold', pad=15, color=NAVY)

    # SmartEngine (center)
    draw_box(ax, 3.5, 4.0, 4.0, 1.2, 'SmartEngine\n(Unified Intelligence Layer)', LIGHT_PURPLE, PURPLE, 12)

    # LLM (left)
    draw_box(ax, 0.2, 4.0, 3.0, 1.2, '', LIGHT_BLUE, BLUE)
    ax.text(1.7, 5.0, 'Groq LLM', ha='center', fontsize=10, fontweight='bold', color=BLUE)
    ax.text(1.7, 4.6, 'Llama 3.3 70B Versatile', ha='center', fontsize=7, color=DARK)
    ax.text(1.7, 4.25, 'Rate Limited · Cached · Fallback', ha='center', fontsize=6.5, color='#6b7280')
    draw_arrow(ax, 3.2, 4.6, 3.5, 4.6)

    # PortSwigger (right)
    draw_box(ax, 7.8, 4.0, 3.0, 1.2, '', LIGHT_TEAL, TEAL)
    ax.text(9.3, 5.0, 'PortSwigger KB', ha='center', fontsize=10, fontweight='bold', color=TEAL)
    ax.text(9.3, 4.6, '269 Labs · 2197 Payloads', ha='center', fontsize=7, color=DARK)
    ax.text(9.3, 4.25, '31 Categories · Lab Solutions', ha='center', fontsize=6.5, color='#6b7280')
    draw_arrow(ax, 7.8, 4.6, 7.5, 4.6)

    # Functions (top)
    draw_box(ax, 1.0, 5.8, 9.0, 0.8, '', GRAY, '#9ca3af')
    ax.text(5.5, 6.35, 'AI Functions', ha='center', fontsize=9, fontweight='bold', color=NAVY)
    funcs = ['Reconnaissance', 'Smart Payloads', 'WAF Bypass', 'Verify Finding', 'Attack Narrative', 'Remediation']
    for i, f in enumerate(funcs):
        draw_box(ax, 1.2 + i*1.45, 5.9, 1.3, 0.35, f, WHITE, BLUE, 6.5, False)
    draw_arrow(ax, 5.5, 5.8, 5.5, 5.2)

    # ML Classifier (bottom)
    draw_box(ax, 3.0, 2.2, 5.0, 1.2, '', LIGHT_ORANGE, ORANGE)
    ax.text(5.5, 3.2, 'ML False-Positive Classifier', ha='center', fontsize=10, fontweight='bold', color=ORANGE)
    ax.text(5.5, 2.8, 'Random Forest + Gradient Boosting Ensemble', ha='center', fontsize=7, color=DARK)
    ax.text(5.5, 2.45, '16 Features · Trained from labeled scan_attempts', ha='center', fontsize=6.5, color='#6b7280')
    draw_arrow(ax, 5.5, 4.0, 5.5, 3.4)

    # Combined Verdict (bottom)
    draw_box(ax, 2.5, 0.6, 6.0, 1.0, '', '#fef3c7', '#d97706')
    ax.text(5.5, 1.35, 'Combined FP Verdict', ha='center', fontsize=10, fontweight='bold', color='#92400e')
    ax.text(5.5, 0.9, 'ML Score (40% weight)  +  LLM Score (60% weight)  =  Final Verdict',
            ha='center', fontsize=8, color=DARK)
    draw_arrow(ax, 5.5, 2.2, 5.5, 1.6)

    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, 'ai_ml_integration.png'), dpi=200, bbox_inches='tight')
    plt.close(fig)
    print('✓ AI/ML Integration')


if __name__ == '__main__':
    gen_architecture()
    gen_pipeline()
    gen_er()
    gen_ai_ml()
    print(f'\nAll diagrams saved to: {OUT_DIR}')
