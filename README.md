<p align="center">
  <h1 align="center">🛡️ Sudarshan</h1>
  <p align="center">
    <strong>AI-Powered Web Vulnerability Scanner</strong>
  </p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#scanners">Scanners</a> •
    <a href="#api">API</a> •
    <a href="#configuration">Configuration</a> •
    <a href="#testing">Testing</a> •
    <a href="#license">License</a>
  </p>
  <p align="center">
    <code>~24,000 lines of Python</code> · <code>22 vulnerability scanners</code> · <code>226 tests</code> · <code>37 API endpoints</code>
  </p>
</p>

---

Sudarshan is an **AI-powered web vulnerability scanner** that combines automated security testing with LLM-driven analysis. It discovers and tests web application endpoints for **22 vulnerability classes**, enriches findings with PortSwigger Web Security Academy references, and uses machine learning to filter false positives.

## Features

- **22 Vulnerability Scanners** — SQL Injection, XSS, Command Injection, SSRF, XXE, CSRF, CORS, Clickjacking, SSTI, IDOR, Directory Listing, JWT Attacks, Broken Auth, Open Redirect, Directory Traversal, Security Headers, NoSQL Injection, File Upload, Host Header Attacks, Information Disclosure, Prototype Pollution, Insecure Deserialization
- **AI-Powered Analysis** — Groq LLM (Qwen3 32B, configurable) generates executive summaries, remediation plans, and attack narratives
- **Multi-Key LLM Rotation** — Round-robin across multiple Groq API keys with automatic failover on rate limits
- **PortSwigger Integration** — 2,000+ payloads from PortSwigger Web Security Academy with lab references
- **ML False-Positive Filter** — Random Forest + Gradient Boosting ensemble classifier reduces noise
- **Real-Time Progress** — Server-Sent Events (SSE) with automatic polling fallback
- **PDF & HTML Reports** — Professional security assessment reports with AI-generated insights
- **Multi-Tenant** — Organizations with role-based access (owner, admin, member, viewer)
- **REST API (v2)** — Full JSON API with session authentication for CI/CD integration
- **Webhooks** — Event-driven notifications on scan completion, errors, and vulnerability discovery
- **DVWA Integration** — Auto-login support for testing against Damn Vulnerable Web Application
- **Scan Controls** — Pause, resume, and stop running scans in real-time

## Quick Start

### Prerequisites
- **Python 3.10+** — [Download](https://www.python.org/downloads/) (3.12+ recommended)
- **Node.js 18+** *(optional)* — [Download](https://nodejs.org/) — only needed if modifying templates
- **Supabase Account** *(for auth)* — [Sign up](https://supabase.com/) — free tier works

### One-Command Setup

```bash
git clone https://github.com/vedansh2810/sudarshan.git
cd sudarshan
python start.py
```

`start.py` automatically handles:
1. Creates virtual environment (`.venv/`)
2. Installs Python dependencies
3. Copies `.env.example` → `.env` and generates a secure `SECRET_KEY`
4. Interactively prompts for Supabase and Groq credentials (or skip to edit `.env` later)
5. Installs npm packages and builds Tailwind CSS
6. Creates required data directories
7. Starts the Flask server at `http://localhost:5000`

On subsequent runs, it detects the setup is complete and starts the server immediately.

### Configure Supabase (Required for Login/Register)

The app uses [Supabase](https://supabase.com/) for user authentication. You need a free Supabase project to enable login and registration. Follow these steps:

#### Step 1: Create a Supabase Project

1. Go to [supabase.com](https://supabase.com/) and click **Start your project** (sign in with GitHub)
2. Click **New Project**
3. Fill in:
   - **Project name:** anything (e.g., `sudarshan`)
   - **Database password:** generate a strong password (save it, you won't need it in `.env` but may need it later)
   - **Region:** choose the closest to you
4. Click **Create new project** and wait ~2 minutes for provisioning

#### Step 2: Get Your API Credentials

1. In your Supabase project dashboard, go to **Settings** (gear icon in sidebar) → **API**
2. You'll see three values — copy each one into your `.env` file:

   | Dashboard Field | `.env` Variable |
   |----------------|-----------------|
   | **Project URL** | `SUPABASE_URL` |
   | **Project API keys → `anon` `public`** | `SUPABASE_ANON_KEY` |
   | **Project API keys → `service_role` `secret`** (click "Reveal") | `SUPABASE_SERVICE_KEY` |

   Your `.env` should look like:
   ```env
   SUPABASE_URL=https://abcdefghij.supabase.co
   SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```

> **Security Note:** The `anon` key is safe to share (it's public). The `service_role` key is **secret** — never share it or commit it to git. Each tester should create their own Supabase project.

#### Step 3: Configure Redirect URL

1. In Supabase dashboard, go to **Authentication** (left sidebar) → **URL Configuration**
2. Under **Redirect URLs**, click **Add URL** and add:
   ```
   http://localhost:5000/auth/callback-handler
   ```
3. Click **Save**

This tells Supabase where to redirect users after login/signup.

#### Step 4: Enable Email Auth

- Go to **Authentication -> Providers -> Email**
- Ensure **Enable Email provider** is ON (it is by default)
- (Optional) Turn OFF **Confirm email** for faster testing -- users can log in immediately without email verification

### Set Up Groq API Key (Optional -- for AI Features)

The app uses [Groq](https://groq.com/) for AI-powered vulnerability analysis, executive summaries, and smart payload generation. Without it the app works fine, but AI features will be disabled.

#### Step 1: Create a Groq Account

1. Go to [console.groq.com](https://console.groq.com/) and sign up (free tier available)
2. Verify your email

#### Step 2: Generate API Key(s)

1. In the Groq dashboard, go to **API Keys** (left sidebar)
2. Click **Create API Key**
3. Give it a name (e.g., `sudarshan`) and click **Submit**
4. **Copy the key immediately** -- it won't be shown again
5. *(Optional)* Create multiple keys for better rate limit distribution

#### Step 3: Add to `.env`

For a single key:
```env
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

For multiple keys (round-robin rotation with automatic failover):
```env
GROQ_API_KEYS=gsk_key1,gsk_key2,gsk_key3
```

That's it. The app will automatically detect the key(s) and enable AI features on the next run. The free tier gives you generous rate limits for testing — multiple keys spread the load further.

### Other Commands

```bash
python start.py --check       # Show setup status
python start.py --setup       # Force re-run setup
python start.py --run         # Skip setup, just run
python start.py --setup-guide # Show Supabase + Groq setup instructions
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser / API Client                      │
├────────────┬──────────────────────────────────────┬──────────────┤
│ Supabase   │          Flask Application           │   REST API   │
│ Auth SDK   │  (Jinja2 Templates + Tailwind CSS)   │    (v2)      │
├────────────┴──────────────────────────────────────┴──────────────┤
│                     Flask Routes & Middleware                     │
│            (CSRF, Rate Limiting, Session, Security Headers)      │
├─────────────────┬──────────────────────┬────────────────────────┤
│  Scan Manager   │    AI Smart Engine   │   ML Classifier        │
│  (Threading/    │  (Groq LLM + Porto-  │  (scikit-learn         │
│   Celery)       │   Swigger KB)        │   ensemble)            │
├─────────────────┴──────────────────────┴────────────────────────┤
│              22 Vulnerability Scanners + Crawler                 │
│         (via centralized Scanner Registry)                       │
├─────────────────┬──────────────────────┬────────────────────────┤
│  PostgreSQL     │      SQLite          │      Redis             │
│  (Supabase)     │   (fallback)         │   (optional)           │
└─────────────────┴──────────────────────┴────────────────────────┘
```

### Scan Pipeline (5 Phases)

1. **Phase 1 — Crawling:** BFS crawler discovers URLs, forms, and injectable parameters
2. **Phase 1.5 — AI Reconnaissance:** Groq LLM analyzes target tech stack (server, framework, WAF detection)
3. **Phase 2 — Vulnerability Scanning:** 22 scanners run in parallel via `ThreadPoolExecutor` (120s timeout per scanner)
4. **Phase 3 — AI Verification:** LLM verifies each finding with prompt injection defense (9 regex filters)
5. **Phase 4 — ML Classification & Scoring:** False-positive classifier filters noise, security score (A–F) calculated

Real-time progress via SSE (Server-Sent Events) with Redis pub/sub, automatic fallback to in-memory polling. Scans support **pause**, **resume**, and **stop** controls.

### Key Design Decisions

- **Database Fallback:** App probes PostgreSQL on startup (5s timeout); if unreachable, falls back to SQLite automatically. Auto-converts `postgres://` → `postgresql+psycopg://` for Supabase/Heroku compatibility.
- **Graceful AI Degradation:** All AI/LLM features are optional. Without a Groq API key, the app works normally — AI-generated summaries are replaced with template-based fallbacks.
- **Multi-Key LLM Rotation:** The `LLMClient` supports multiple Groq API keys with round-robin rotation and token-aware rate limiting. If a key is rate-limited (429), it automatically fails over to the next key.
- **Pre-built CSS:** Tailwind CSS is compiled at build time (~32KB), not loaded from CDN. This improves performance, works offline, and removes the CDN dependency.
- **Session-Based Auth:** Supabase handles identity (email/OAuth), but Flask manages sessions server-side (8-hour expiry). Session fixation protection via `session.clear()` on login.
- **Scanner Registry:** All 22 scanner classes (24 total — `idor.py` exports 2) are registered in `app/scanner/registry.py`, eliminating duplication between `scan_manager.py` and `tasks.py`.
- **Plan-Based Limits:** Resource quotas (scans/month, concurrent scans, team size) are enforced per plan tier.
- **Prompt Injection Defense:** Target response data is sanitized through 9 regex patterns before being sent to the LLM for vulnerability verification.
- **ML Model Integrity:** SHA-256 checksum verification before loading ML models, preventing arbitrary code execution via poisoned joblib files.

### Scan Speed Profiles

| Profile | Request Delay | Threads | Timeout | Max URLs |
|---------|:------------:|:-------:|:-------:|:--------:|
| Safe | 1.0s | 3 | 10s | 75 |
| Balanced | 0.15s | 6 | 8s | 200 |
| Aggressive | 0.05s | 10 | 5s | 500 |

### Plan Limits

| Plan | Scans/Month | Concurrent | Team Size | Max URLs/Scan | AI Features |
|------|:-----------:|:----------:|:---------:|:------------:|:-----------:|
| Free | 5 | 1 | 3 | 100 | ❌ |
| Pro | 50 | 3 | 15 | 500 | ✅ |
| Enterprise | ∞ | 10 | ∞ | ∞ | ✅ |

## Scanners

| Scanner | Techniques | Payloads |
|---------|-----------|----------|
| **SQL Injection** | Error-based, UNION, time-based blind, boolean, stacked queries | 60+ custom + PortSwigger |
| **Cross-Site Scripting** | Reflected, stored, DOM-based, event handlers, polyglots | 40+ custom + PortSwigger |
| **Command Injection** | Linux/Windows, blind, IFS bypass, variable substitution | 30+ custom + PortSwigger |
| **Directory Traversal** | Path traversal, null byte, double encoding, mixed slashes | 25+ custom + PortSwigger |
| **XXE** | File retrieval, SSRF via XXE, out-of-band, parameter entities | 15+ custom + PortSwigger |
| **SSRF** | Localhost, cloud metadata (AWS/GCP/Azure), protocol smuggling | 20+ custom + PortSwigger |
| **CSRF** | Missing tokens, SameSite cookie, origin/referer validation | Behavioral analysis |
| **CORS** | Origin reflection, null origin, wildcard, credential exposure | Behavioral analysis |
| **Clickjacking** | X-Frame-Options, CSP frame-ancestors, iframe embedding | Header analysis |
| **Security Headers** | HSTS, CSP, X-Content-Type, Referrer-Policy, Permissions-Policy | Header analysis |
| **Open Redirect** | Parameter-based, path-based, encoding bypass, protocol-relative | 15+ payloads |
| **SSTI** | Jinja2, Twig, Freemarker, Velocity, Pebble detection | Template probes |
| **IDOR** | Sequential ID, UUID manipulation, parameter tampering | Access control tests |
| **Directory Listing** | Common directory enumeration, SPA-aware canary detection | Path probes |
| **Broken Auth** | Default credentials, session fixation, username enumeration | Credential lists |
| **JWT Attacks** | Algorithm confusion (none/HS256), key brute-force, claim tampering | Token manipulation |
| **NoSQL Injection** | MongoDB operator ($gt/$ne/$regex), authentication bypass, JS injection, blind boolean | Operator + JS payloads |
| **File Upload** | Dangerous extensions, MIME-type bypass, double extension, null byte bypass | Extension + MIME tests |
| **Host Header Attacks** | Host injection, X-Forwarded-Host, port injection, password reset poisoning | Header injection |
| **Information Disclosure** | .git/.env exposure, stack traces, debug pages, backup files, API docs | 30+ sensitive paths |
| **Prototype Pollution** | `__proto__`, `constructor.prototype`, JSON body, query param, form POST | Canary-based detection |
| **Insecure Deserialization** | Java/PHP/Python serialized cookies, .NET ViewState, parameter/form injection | Framework-specific probes |

## API

### REST API v2 (JSON)

All v2 endpoints use session-based authentication (login via the web UI first). CSRF is exempted on scan creation and deletion endpoints for API usage.

```bash
# Authenticate via the web UI first, then use the session cookie:

# List scans
curl http://localhost:5000/api/v2/scans \
  -b cookies.txt

# Start a scan
curl -X POST http://localhost:5000/api/v2/scans \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com", "scan_type": "full", "authorized": true}'

# Get scan results
curl http://localhost:5000/api/v2/scans/1/results \
  -b cookies.txt

# Download PDF report
curl http://localhost:5000/api/v2/scans/1/report/pdf \
  -b cookies.txt -o report.pdf
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v2/scans` | Start a new scan |
| `GET` | `/api/v2/scans` | List all scans (paginated, filterable) |
| `GET` | `/api/v2/scans/:id` | Get scan details |
| `DELETE` | `/api/v2/scans/:id` | Delete a scan |
| `GET` | `/api/v2/scans/:id/status` | Get live scan status |
| `GET` | `/api/v2/scans/:id/results` | Get vulnerabilities (filterable) |
| `POST` | `/api/v2/scans/:id/pause` | Pause a running scan |
| `POST` | `/api/v2/scans/:id/resume` | Resume a paused scan |
| `POST` | `/api/v2/scans/:id/stop` | Stop a running scan |
| `GET` | `/api/v2/scans/:id/stream` | SSE event stream |
| `GET` | `/api/v2/scans/:id/report/:fmt` | Download PDF/HTML report |
| `GET` | `/api/v2/dashboard` | Dashboard statistics |
| `GET` | `/api/v2/auth/session` | Current session info |
| `GET` | `/api/v2/checks` | List available vuln checks |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/metrics` | Prometheus metrics |

## Configuration

### Environment Variables (`.env`)

| Variable | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `SECRET_KEY` | Yes | — | Flask session encryption key |
| `SUPABASE_URL` | Yes* | — | Supabase project URL |
| `SUPABASE_ANON_KEY` | Yes* | — | Supabase public anon key |
| `SUPABASE_SERVICE_KEY` | Yes* | — | Supabase service role secret |
| `DATABASE_URL` | No | SQLite | PostgreSQL connection URI |
| `REDIS_URL` | No | — | Redis URI for Celery & SSE pub/sub |
| `GROQ_API_KEY` | No | — | Groq API key for AI features |
| `GROQ_API_KEYS` | No | — | Comma-separated Groq keys for rotation |
| `GROQ_MODEL` | No | `qwen/qwen3-32b` | LLM model to use |
| `PORT` | No | `5000` | Server port |
| `FLASK_DEBUG` | No | `1` | Debug mode (disable in production) |
| `ALLOW_LOCAL_TARGETS` | No | `false` | Allow scanning localhost/private IPs |
| `ALLOW_INSECURE_TARGETS` | No | `false` | Skip TLS verification for local testing |

*Required for user authentication. Without these, the app runs but login/register pages won't function.

## Testing

Sudarshan has **226 test cases** across 10 test files covering the full stack:

| Test File | Tests | Coverage Area |
|-----------|:-----:|---------------|
| `test_crawler.py` | 39 | URL normalization, validation, scoping, link extraction |
| `test_crawler_scanner.py` | 33 | Crawler + 6 scanner integration tests |
| `test_integration.py` | 14 | Flask routes, ORM CRUD, scanner registry |
| `test_multi_tenancy.py` | 12 | Organizations, plan limits, GDPR compliance |
| `test_new_scanners.py` | 22 | XXE, SSRF, Open Redirect, CORS, Clickjacking |
| `test_phase5_scanners.py` | 30 | NoSQL Injection, File Upload, Host Header, Info Disclosure, Prototype Pollution, Insecure Deserialization |
| `test_routes.py` | 28 | All HTTP routes, API v2, auth flows, origin validation |
| `test_smart_engine_integration.py` | 19 | AI/ML SmartEngine, report writer, singleton thread safety |
| `test_stateless_scan_manager.py` | 10 | ScanManager state: Redis → in-memory → DB fallback |
| `test_url_safety.py` | 19 | SSRF protection, cloud metadata blocking |

All tests use `unittest.mock` — zero real network calls. Integration tests use in-memory SQLite.

```bash
# Activate venv first
.venv/Scripts/activate    # Windows
source .venv/bin/activate # Linux/Mac

pytest tests/ -v
```

## Development

### Rebuild Tailwind CSS

After modifying HTML templates, rebuild the CSS:

```bash
npm run build:css       # One-time production build (minified)
npm run watch:css       # Watch mode for development
```

### Celery Worker (Optional)

For async scan execution with Redis:

```bash
celery -A app.celery_app.celery worker --loglevel=info
```

Without Redis/Celery, scans run in background threads (works fine for single-user setups).

### Sign ML Model (After Retraining)

```bash
python -m app.ml.sign_model data/ml_models/fp_classifier_v{timestamp}.joblib
```

## Tech Stack

| Layer | Technology |
|-------|-----------:|
| Backend | Python 3.12+, Flask 3.0, SQLAlchemy |
| Frontend | Jinja2, Tailwind CSS 3 (pre-built), vanilla JS |
| Database | PostgreSQL (Supabase) / SQLite fallback |
| Auth | Supabase Auth (GoTrue) + Flask sessions |
| AI/LLM | Groq API (Qwen3 32B, configurable) with multi-key rotation |
| ML | scikit-learn (Random Forest + Gradient Boosting ensemble) |
| Task Queue | Celery + Redis (optional, falls back to threading) |
| Reports | fpdf2 (PDF generation) |
| Monitoring | Prometheus client |
| Security | SSRF protection, prompt injection defense, SHA-256 model verification |
| CSS Build | Tailwind CSS 3 CLI |

## License

This project is licensed under the ISC License.
