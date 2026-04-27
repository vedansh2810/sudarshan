<p align="center">
  <h1 align="center">🛡️ Sudarshan</h1>
  <p align="center">
    <strong>AI-Powered Web Vulnerability Scanner</strong>
  </p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#api">API</a> •
    <a href="#docker">Docker</a> •
    <a href="#license">License</a>
  </p>
</p>

---

**Sudarshan** is a production-grade web vulnerability scanner that combines traditional security scanning with AI-powered analysis. It features 16 vulnerability scanners, a multi-threaded crawler, real-time progress streaming, and an integrated AI/ML pipeline for intelligent false-positive filtering and detailed attack narratives.

## Features

### 🔍 Comprehensive Scanning
- **16 Vulnerability Scanners** — SQL Injection, XSS, CSRF, SSRF, SSTI, XXE, Command Injection, Directory Traversal, JWT Attacks, Broken Auth, IDOR, Open Redirect, CORS Misconfig, Clickjacking, Security Headers, and Directory Listing
- **Multi-threaded Crawler** — Discovers URLs, forms, and injectable parameters automatically
- **3 Scan Modes** — Safe, Balanced, and Aggressive profiles with tunable speed and depth
- **Active & Passive Scanning** — Full vulnerability testing or headers-only analysis

### 🤖 AI/ML Intelligence
- **LLM-Powered Analysis** — Uses Groq (Llama 3.3 70B) for vulnerability reasoning, tech stack reconnaissance, and WAF bypass generation
- **ML False-Positive Classifier** — Random Forest + Gradient Boosting ensemble trained on scan attempt data
- **Combined Verdict** — ML (40%) + LLM (60%) weighted scoring for false-positive classification
- **PortSwigger Knowledge Base** — 269 labs, 2197 payloads, 31 categories integrated directly into analysis
- **Attack Narratives** — AI-generated professional exploitation writeups with PortSwigger lab references

### 📊 Reporting
- **HTML & PDF Reports** — Downloadable, professionally formatted security assessment reports
- **AI-Generated Executive Summaries** — Business-friendly risk analysis and prioritized remediation plans
- **CVSS Scoring & OWASP Mapping** — Industry-standard vulnerability classification

### 🏢 Multi-Tenancy & API
- **Organization Support** — Team-based access control with roles (Owner, Admin, Member, Viewer)
- **REST API v2** — Full programmatic access with HMAC-SHA256 API key authentication
- **Webhook Notifications** — Real-time HTTP callbacks on scan events
- **Plan-Based Quotas** — Free, Pro, and Enterprise tiers with resource limits

### ⚡ Real-Time Streaming
- **Server-Sent Events (SSE)** — Live progress, logs, and findings via Redis pub/sub or in-memory queues
- **Celery Task Queue** — Background scan execution with Redis broker (falls back to in-process threading)

---

## Architecture

```
sudarshan/
├── run.py                        # Entry point (auto-activates venv)
├── app/
│   ├── __init__.py               # Flask app factory
│   ├── config.py                 # Config classes (Dev/Prod)
│   ├── ai/                       # AI/LLM intelligence layer
│   │   ├── smart_engine.py       # Unified AI engine (LLM + PortSwigger + ML)
│   │   ├── llm_client.py         # Groq LLM client (rate-limited, cached)
│   │   ├── analyzer.py           # Vulnerability analysis & FP classification
│   │   └── report_writer.py      # AI-generated report sections
│   ├── ml/                       # Machine Learning
│   │   └── false_positive_classifier.py
│   ├── models/                   # SQLAlchemy ORM models
│   ├── scanner/                  # Core scanning engine
│   │   ├── scan_manager.py       # Scan orchestration
│   │   ├── crawler.py            # Multi-threaded web crawler
│   │   └── vulnerabilities/      # 16 vulnerability scanner modules
│   ├── routes/                   # Flask blueprints
│   ├── utils/                    # Utility modules
│   ├── static/                   # Local CSS & JS assets
│   └── templates/                # Jinja2 HTML templates
├── deploy/                       # Production deployment (Oracle Cloud)
│   ├── deploy.sh                 # One-command update/redeploy script
│   ├── setup-server.sh           # First-time VM provisioning
│   ├── setup-ssl.sh              # Let's Encrypt SSL automation
│   └── nginx/                    # Nginx reverse proxy configs
│       ├── nginx.conf            # HTTPS config (rate-limited)
│       └── nginx-nossl.conf      # HTTP-only (pre-SSL bootstrap)
├── data/                         # ML models, reports, PortSwigger KB
├── scripts/                      # Report generation & training scripts
├── tests/                        # pytest test suite
├── Dockerfile
├── docker-compose.yml            # Dev: web + worker + redis
├── docker-compose.prod.yml       # Prod: nginx + web + worker + redis + certbot
├── .env.production               # Production env template (no secrets)
└── requirements.txt
```

### Scan Pipeline

```
Phase 0    →  Connectivity check (HTTP GET target)
Phase 1    →  Multi-threaded crawling (URLs, forms, parameters)
Phase 1.5  →  AI Recon (tech stack, WAF, framework detection via LLM)
Phase 2    →  Parallel vulnerability scanning (16 scanners via ThreadPoolExecutor)
              ├─ Save findings to DB (batch-deduplicated)
              ├─ AI analysis (OWASP mapping, CWE classification)
              └─ Progress streaming via SSE
Finalize   →  Score calculation, webhook triggers, cleanup
```

---

## Quick Start

### Prerequisites
- Python 3.12+
- PostgreSQL (or Supabase) — falls back to SQLite for development
- Redis (optional — falls back to in-process threading)
- [Groq API key](https://console.groq.com/) (optional — AI features)

### Installation

```bash
# Clone the repository
git clone https://github.com/vedansh2810/sudarshan.git
cd sudarshan

# Create and activate virtual environment
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the project root:

```env
# Required
DATABASE_URL=postgresql://user:password@localhost:5432/sudarshan
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_KEY=your-service-key

# Optional
SECRET_KEY=your-secret-key
REDIS_URL=redis://localhost:6379/0
GROQ_API_KEY=your-groq-api-key
GROQ_MODEL=llama-3.3-70b-versatile
FLASK_ENV=development
ALLOW_LOCAL_TARGETS=true
```

### Run

```bash
# Development
python run.py

# With Celery worker (separate terminal)
celery -A app.celery_app:celery worker --loglevel=info

# Run tests
pytest tests/ -v
```

The app will be available at `http://localhost:5000`.

---

## Docker

### Development

```bash
# Build and start all services (dev)
docker compose up --build

# Services:
#   web    → Flask + Gunicorn (port 5000)
#   worker → Celery worker (concurrency 2)
#   redis  → Redis 7 Alpine (port 6379)
```

### Production (Oracle Cloud / VPS)

```bash
# 1. Provision the server (Ubuntu 22.04/24.04 VM — run once)
sudo ./deploy/setup-server.sh

# 2. Configure environment
cp .env.production .env
nano .env   # fill in all values

# 3. Start with HTTP first
cp deploy/nginx/nginx-nossl.conf deploy/nginx/nginx.conf
docker compose -f docker-compose.prod.yml up -d --build

# 4. Enable HTTPS (requires domain pointed at your server)
sudo ./deploy/setup-ssl.sh your-domain.com your@email.com

# 5. Subsequent deploys
./deploy/deploy.sh
```

**Production services:** Nginx (reverse proxy + static files) → Gunicorn (Flask) → Celery worker → Redis → Certbot (auto SSL renewal)

---

## API

### Web Routes

| Route | Description |
|-------|-------------|
| `/` | Landing page |
| `/auth/login` | User authentication |
| `/dashboard` | User dashboard with scan stats |
| `/scan/new` | Configure and start a new scan |
| `/results/<id>` | View scan results and download reports |
| `/history` | Scan history with filtering |
| `/ml-admin` | ML training data and model management |

### REST API v2

All API v2 endpoints require an `X-API-Key` header.

```bash
# Start a scan
curl -X POST http://localhost:5000/api/v2/scans \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com", "scan_mode": "active"}'

# Get scan status
curl http://localhost:5000/api/v2/scans/{scan_id} \
  -H "X-API-Key: your-api-key"

# List vulnerabilities
curl http://localhost:5000/api/v2/scans/{scan_id}/vulnerabilities \
  -H "X-API-Key: your-api-key"
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.12 / Flask 3.0 |
| **Database** | PostgreSQL (Supabase) / SQLite fallback |
| **ORM** | SQLAlchemy + Flask-Migrate |
| **Auth** | Supabase Auth (GoTrue) + PyJWT |
| **AI/LLM** | Groq API (Llama 3.3 70B Versatile) |
| **ML** | scikit-learn (Random Forest + Gradient Boosting) |
| **Task Queue** | Celery + Redis |
| **Reports** | fpdf2 (PDF) + Jinja2 (HTML) |
| **Monitoring** | Prometheus |
| **Deployment** | Docker + Nginx + Gunicorn + Let's Encrypt |

---

## Security Features

- **CSRF Protection** — Flask-WTF with 1-hour token validity
- **Rate Limiting** — Flask-Limiter (200/day, 50/hour default)
- **SSRF Protection** — IP validation prevents scanning private/internal networks
- **API Key Security** — HMAC-SHA256 hashed keys with expiration support
- **Session Management** — Secure session handling via Supabase Auth

---

## Supported Vulnerability Checks

| # | Vulnerability | Description |
|---|--------------|-------------|
| 1 | SQL Injection | Error-based, blind, time-based detection |
| 2 | Cross-Site Scripting (XSS) | Reflected, stored, DOM-based |
| 3 | CSRF | Missing or weak anti-CSRF tokens |
| 4 | Command Injection | OS command execution via user input |
| 5 | Directory Traversal | Path traversal and file inclusion |
| 6 | XXE | XML External Entity injection |
| 7 | SSRF | Server-Side Request Forgery |
| 8 | SSTI | Server-Side Template Injection |
| 9 | JWT Attacks | Algorithm confusion, weak secrets |
| 10 | Broken Authentication | Weak login mechanisms |
| 11 | IDOR | Insecure Direct Object References |
| 12 | Open Redirect | Unvalidated redirects |
| 13 | CORS Misconfiguration | Overly permissive CORS policies |
| 14 | Clickjacking | Missing frame protection |
| 15 | Security Headers | Missing or misconfigured HTTP headers |
| 16 | Directory Listing | Exposed directory indices |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any target.

---

<p align="center">
  Built with ❤️ by <a href="https://github.com/vedansh2810">Vedansh Gupta</a>
</p>
