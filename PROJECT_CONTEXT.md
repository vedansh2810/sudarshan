# Sudarshan — Web Vulnerability Scanner

**Project Type:** Full-stack web application
**Backend:** Python 3.12+ / Flask 3.0
**Database:** PostgreSQL (Supabase) with SQLite fallback
**Auth:** Supabase Auth (GoTrue) — client-side SDK + server-side token verification
**AI/LLM:** Groq API (Qwen3 32B) with multi-key rotation
**ML:** scikit-learn (Random Forest + Gradient Boosting ensemble)
**Task Queue:** Celery + Redis (optional — falls back to in-process threading)
**Frontend:** Jinja2 templates + Tailwind CSS 3 (pre-built) + vanilla JS
**Deployment:** Gunicorn (Unix) or `python run.py` (Windows/dev)

---

## Codebase Metrics

| Metric | Value |
|--------|-------|
| Python files | 87 |
| Python lines of code | ~23,900 |
| HTML templates | 17 |
| HTML template lines | ~2,300 |
| CSS files | 3 (sudarshan.css, tailwind-built.css, tailwind-input.css) |
| CSS lines | ~341 |
| JS files | 1 (utils.js — 33 lines) |
| Test files | 10 |
| Test cases | 226 |
| Vulnerability scanners | 22 modules / 24 classes |
| API endpoints | 37 total (web + API v1 + API v2) |
| PortSwigger knowledge base | ~2.8 MB (3 JSON files, 269 labs) |
| ML model | 1 trained model (~472 KB, dated 2026-03-11) |
| SQLite database | ~10.9 MB (auto-created, gitignored) |

---

## Quick Start

```bash
python start.py              # Auto-setup + run (first time: installs deps, creates .env, builds CSS)
python start.py --check      # Show setup status
python start.py --setup      # Force re-run setup
python start.py --run        # Skip setup, just run
python start.py --setup-guide  # Show Supabase + Groq setup instructions
```

---

## Project Structure

```
sudarshan/
|-- start.py                    # One-click setup & run script (501 lines, interactive credential prompting)
|-- run.py                      # Flask entry point (13 lines, used by start.py & Gunicorn)
|-- requirements.txt            # Python dependencies (45 lines)
|-- package.json                # Node.js dependencies (Tailwind CSS build)
|-- tailwind.config.js          # Tailwind CSS config (custom theme: Space Grotesk, neon cyan, dark bg)
|-- .env.example                # Environment template with setup instructions
|-- .gitignore                  # Ignores: .env, database.db, reports/, __pycache__, .venv, node_modules
|-- PROJECT_CONTEXT.md          # This file
|-- README.md                   # User-facing documentation
|
|-- app/
|   |-- __init__.py             # Flask factory: create_app(), extensions, middleware, error handlers (259 lines)
|   |-- config.py               # Configuration: env vars, security headers, DB URI, plan limits (211 lines)
|   |-- celery_app.py           # Celery worker configuration with ContextTask (30 lines)
|   |-- tasks.py                # Celery task definitions: 4-phase scan pipeline (506 lines)
|   |
|   |-- routes/
|   |   |-- main.py             # Landing page, /health, /readiness (31 lines)
|   |   |-- auth.py             # Login/register/logout/callback — Supabase Auth (194 lines)
|   |   |-- dashboard.py        # User dashboard: recent scans, trend data, stats (102 lines)
|   |   |-- scan.py             # Scan CRUD, SSE streaming (Redis + threading), pause/resume/stop (349 lines)
|   |   |-- results.py          # Scan results, PDF/HTML report generation, AI analysis (594 lines)
|   |   |-- history.py          # Scan history with search, date filter, pagination (111 lines)
|   |   |-- api.py              # API v1 — legacy: health, metrics, stats, status (62 lines)
|   |   |-- api_v2.py           # API v2 — full REST API with session auth (392 lines)
|   |   |-- ml_admin.py         # ML model admin: labeling, stats, retraining (220 lines)
|   |
|   |-- models/
|   |   |-- database.py         # SQLAlchemy models: ScanModel, VulnerabilityModel, UserModel (120 lines)
|   |   |-- user.py             # User upsert from Supabase UID (82 lines)
|   |   |-- scan.py             # Scan CRUD helpers: create, get, update, delete, for_user_query (209 lines)
|   |   |-- vulnerability.py    # Vulnerability CRUD: create, create_batch, get_by_scan, counts (137 lines)
|   |   |-- api_key.py          # API key model: hashed, scoped, org-aware (112 lines)
|   |   |-- webhook.py          # Webhook model: event-driven notifications (182 lines)
|   |   |-- organization.py     # Multi-tenant org model: roles, memberships, quotas, GDPR purge (316 lines)
|   |   |-- ml_training.py      # ML training data: ScanAttempt model, labeled data export (243 lines)
|   |
|   |-- scanner/
|   |   |-- scan_manager.py     # Orchestrator: threading + Celery, SSE, Redis pub/sub, controls (968 lines)
|   |   |-- crawler.py          # Web crawler: BFS, robots.txt, form discovery, URL normalization (622 lines)
|   |   |-- dvwa_auth.py        # DVWA auto-login for testing (160 lines)
|   |   |-- payload_manager.py  # Centralized payload system: PortSwigger + custom, dedup, stats (720 lines)
|   |   |-- registry.py         # Scanner registry: SCANNER_MAP — single source of truth (62 lines)
|   |   |-- vulnerabilities/
|   |       |-- base.py         # BaseScanner: shared logic, AI enrichment, ML verify (492 lines)
|   |       |-- sql_injection.py        # Error/UNION/time/boolean/stacked (560 lines)
|   |       |-- xss.py                  # Reflected/stored/DOM/event/polyglots (535 lines)
|   |       |-- command_injection.py    # Linux/Windows, blind, IFS bypass (364 lines)
|   |       |-- directory_traversal.py  # Path traversal, null byte, PHP wrappers (300 lines)
|   |       |-- xxe.py                  # File retrieval, SSRF via XXE, OOB (399 lines)
|   |       |-- ssrf.py                 # Cloud metadata (AWS/GCP/Azure), localhost (450 lines)
|   |       |-- csrf.py                 # Token validation, SameSite, origin checks (269 lines)
|   |       |-- cors.py                 # Origin reflection, null origin, bypass (206 lines)
|   |       |-- clickjacking.py         # X-Frame-Options, CSP frame-ancestors (96 lines)
|   |       |-- security_headers.py     # 9 headers, CSP strength, cookie flags (323 lines)
|   |       |-- open_redirect.py        # Parameter/path-based, 16 bypass payloads (302 lines)
|   |       |-- ssti.py                 # Jinja2/Twig/Freemarker/Velocity/ERB (259 lines)
|   |       |-- idor.py                 # IDORScanner + DirectoryListingScanner (219 lines)
|   |       |-- broken_auth.py          # Default creds, lockout, cookie flags (398 lines)
|   |       |-- jwt_attacks.py          # Alg none, weak secret, expired, claims (420 lines)
|   |       |-- nosql_injection.py      # MongoDB $gt/$ne/$regex, JS injection, blind (314 lines)
|   |       |-- file_upload.py          # Extension, MIME bypass, double ext, null byte (288 lines)
|   |       |-- host_header.py          # Host injection, X-Forwarded-Host, reset poisoning (156 lines)
|   |       |-- info_disclosure.py      # .git/.env, stack traces, debug pages, backups (196 lines)
|   |       |-- prototype_pollution.py  # __proto__, constructor.prototype, JSON body (322 lines)
|   |       |-- insecure_deserialization.py  # Java/PHP/Python/ViewState detection (499 lines)
|   |
|   |-- ai/
|   |   |-- smart_engine.py     # AI orchestrator: PortSwigger KB, ML integration, recon (635 lines)
|   |   |-- llm_client.py       # Groq API: multi-key rotation, token-aware rate limiting, caching (329 lines)
|   |   |-- report_writer.py    # LLM report generation: exec summary, remediation, narrative (274 lines)
|   |
|   |-- ml/
|   |   |-- false_positive_classifier.py  # ML false-positive classifier: Random Forest + GBM (293 lines)
|   |   |-- sign_model.py       # SHA-256 model integrity verification (31 lines)
|   |
|   |-- monitoring/
|   |   |-- metrics.py          # Prometheus metrics endpoint (63 lines)
|   |   |-- security_logger.py  # Structured security event logger: auth, API, SIEM (103 lines)
|   |
|   |-- utils/
|   |   |-- auth_utils.py       # @login_required decorator, session management (54 lines)
|   |   |-- auth_helpers.py     # Scan access control: owner + org member checks, @admin_required (44 lines)
|   |   |-- url_safety.py       # SSRF protection: private IP blocking, cloud metadata blocking (117 lines)
|   |
|   |-- static/
|   |   |-- css/
|   |   |   |-- sudarshan.css       # Custom design system: glass, neon, nav effects (359 lines)
|   |   |   |-- tailwind-built.css  # Pre-built Tailwind CSS (~32KB)
|   |   |   |-- tailwind-input.css  # Tailwind build input (@tailwind directives, 5 lines)
|   |   |-- js/
|   |   |   |-- utils.js            # sanitizeHTML(), togglePasswordVisibility() (33 lines)
|   |   |-- img/                    # Empty — no logo/image assets committed
|   |
|   |-- templates/
|       |-- base.html               # Root template: meta, fonts, CSS, CSRF (3.1KB)
|       |-- layout.html             # Authenticated layout: nav, sidebar, flash (5.5KB)
|       |-- errors/
|       |   |-- 403.html            # Forbidden error page (1.6KB)
|       |   |-- 404.html            # Not found error page (1.6KB)
|       |   |-- 429.html            # Rate limited error page (1.6KB)
|       |   |-- 500.html            # Internal server error page (1.7KB)
|       |-- auth/
|       |   |-- login.html          # Supabase Auth login: email + Google OAuth
|       |   |-- register.html       # Registration page
|       |   |-- callback_handler.html  # OAuth callback: JS extracts hash token, POSTs to /auth/callback
|       |-- dashboard/
|       |   |-- index.html          # Dashboard: charts, stats, recent scans (14.5KB)
|       |-- scan/
|       |   |-- new.html            # New scan form: URL, depth, modules, speed (9.4KB)
|       |   |-- progress.html       # Live scan progress: SSE + polling fallback (14KB)
|       |-- results/
|       |   |-- view.html           # Scan results: vulnerability cards, filters (10.7KB)
|       |-- history/
|       |   |-- index.html          # Scan history: search, filters, pagination (9.4KB)
|       |-- main/
|       |   |-- index.html          # Landing page (14.5KB)
|       |-- ml_admin/
|           |-- labeling.html       # ML training data labeling interface (9.2KB)
|           |-- stats.html          # ML model performance stats (7.3KB)
|
|-- data/
|   |-- portswigger_knowledge/      # PortSwigger Academy data (committed)
|   |   |-- portswigger_knowledge.json  # 1.91MB — 20+ vuln categories with descriptions + labs
|   |   |-- payloads_by_category.json   # 747KB — attack payloads by category with difficulty
|   |   |-- lab_index.json              # 75KB — index of 269 PortSwigger labs
|   |-- ml_models/                  # Trained ML models (committed)
|   |   |-- fp_classifier_v20260311_113925.joblib  # 472KB false-positive classifier
|   |-- database.db                 # SQLite database (~10.9MB, gitignored, auto-created)
|   |-- reports/                    # Generated PDF/HTML reports (gitignored)
|   |-- report_diagrams/            # Generated diagrams (gitignored)
|
|-- scripts/                        # Standalone dev/build scripts
|   |-- portswigger_scraper.py      # Scrape PortSwigger Academy labs (734 lines)
|   |-- portswigger_auto_trainer.py # Auto-train ML on PortSwigger data (573 lines)
|   |-- portswigger_complete_integration.py  # Integration orchestrator (94 lines)
|   |-- train_ml_models.py          # Train false-positive classifier (100 lines)
|   |-- generate_diagrams.py        # Generate architecture diagrams (689 lines)
|   |-- generate_report_p1/p2/p3.py # Generate project documentation (440/551/689 lines)
|
|-- tests/                          # Test suite (226 tests across 10 files)
|   |-- test_crawler.py             # 39 tests — URL normalization, validation, scoping, extraction (455 lines)
|   |-- test_crawler_scanner.py     # 33 tests — Crawler + 6 scanner integration (521 lines)
|   |-- test_integration.py         # 14 tests — Flask routes, ORM, scanner registry (323 lines)
|   |-- test_multi_tenancy.py       # 12 tests — Organizations, plan limits, GDPR (121 lines)
|   |-- test_new_scanners.py        # 22 tests — XXE, SSRF, Redirect, CORS, Clickjacking (439 lines)
|   |-- test_phase5_scanners.py     # 30 tests — NoSQL, Upload, Host, InfoDisc, Prototype, Deser (987 lines)
|   |-- test_routes.py              # 28 tests — All HTTP routes, API v2, auth, origin validation (442 lines)
|   |-- test_smart_engine_integration.py  # 19 tests — AI/ML SmartEngine, report writer (282 lines)
|   |-- test_stateless_scan_manager.py    # 10 tests — ScanManager: Redis/in-memory/DB fallback (278 lines)
|   |-- test_url_safety.py          # 19 tests — SSRF protection, cloud metadata blocking (233 lines)
|
|-- docs/
    |-- RUNNING.md                  # Deployment/running instructions (122 lines)
```

---

## Architecture

### Authentication Flow

1. User clicks Login/Register -> Supabase JS SDK (client-side)
2. Supabase handles email/password or Google OAuth
3. On success, Supabase redirects to `/auth/callback-handler`
4. `callback_handler.html` extracts the access token from URL hash fragment
5. Token is POSTed to `POST /auth/callback` (Flask backend)
6. Flask verifies token via Supabase GoTrue REST API (`/auth/v1/user`)
7. Flask upserts user in local DB, clears session (fixation protection), sets session fields
8. All subsequent requests use Flask session (8-hour expiry, permanent)

**Security hardening (v2.1):** Origin validation on CSRF-exempt callback, session fixation protection via `session.clear()`, rate limiting (10/min), login timestamp for auditing, generic error messages.

**Dev bypass:** When `SUDARSHAN_DEV_AUTH=1` and `app.debug=True`, token verification returns a stub user.

### Scan Execution Flow

1. User submits scan form -> `POST /scan/new`
2. `ScanManager.start_scan()` creates a thread (or Celery task if Redis available)
3. **Phase 1 — Crawling:** BFS crawler discovers URLs, forms, parameters
4. **Phase 1.5 — AI Reconnaissance:** Groq LLM analyzes target tech stack (server, framework, WAF)
5. **Phase 2 — Vulnerability Scanning:** Each scanner runs in a `ThreadPoolExecutor` thread (120s timeout per scanner)
6. **Phase 3 — AI Verification:** LLM verifies each finding with prompt injection defense (9 regex filters)
7. **Phase 4 — ML Classification:** False-positive classifier filters noise
8. **Phase 5 — Scoring:** Security score calculated (A–F letter grade), results saved to DB
9. Real-time updates via SSE (Server-Sent Events) with Redis pub/sub, fallback to in-memory queue polling

**Scan control:** Pause/resume/stop via Redis control keys with 30min auto-resume timeout.
**Deduplication:** Uses `(vuln_type, affected_url, parameter)` tuples to avoid duplicates.

### Scanner Registry

The `app/scanner/registry.py` module provides a centralized `SCANNER_MAP` dict that maps
config key names to `(ScannerClass, display_name)` tuples. Both `scan_manager.py` and
`tasks.py` import from the registry to avoid duplicated scanner lists.

**22 config keys → 24 scanner classes** (idor.py exports both `IDORScanner` and `DirectoryListingScanner`).

### Database Strategy

- **Primary:** PostgreSQL via Supabase (`DATABASE_URL` in `.env`)
- **Fallback:** SQLite at `data/database.db` (auto-detected on startup)
- The app probes PostgreSQL connectivity with a 5s timeout BEFORE initializing SQLAlchemy
- Auto-converts `postgres://` → `postgresql+psycopg://` for Supabase/Heroku compatibility
- If PostgreSQL is unreachable, pool options are cleared and SQLite is used
- SQLite pragma `foreign_keys=ON` enabled via event listener
- All models use SQLAlchemy ORM (no raw SQL)

### Database Models

| Model | Table | Key Fields |
|-------|-------|------------|
| `ScanModel` | `scans` | id, target_url, status, score, grade, scan_type, speed, user_id, org_id, created_at, completed_at, duration |
| `VulnerabilityModel` | `vulnerabilities` | id, scan_id (FK), vuln_type, severity, cvss_score, affected_url, parameter, payload, evidence, description, remediation, owasp_category, ai_analysis, ai_narrative, likely_false_positive, fp_confidence |
| `UserModel` | `users` | id, supabase_uid, username, email, is_admin, plan, created_at |
| `APIKeyModel` | `api_keys` | id, user_id, org_id, key_hash, name, scopes, last_used, is_active |
| `WebhookModel` | `webhooks` | id, user_id, org_id, url, events, secret, is_active |
| `OrganizationModel` | `organizations` | id, name, owner_id, plan, settings |
| `OrgMemberModel` | `org_members` | id, org_id, user_id, role (owner/admin/member/viewer) |
| `OrgSettingsModel` | `org_settings` | id, org_id, settings JSON |
| `ScanAttemptModel` | `scan_attempts` | id, scan_id, scanner_type, url, parameter, payload, request_data, response_data, detection_result, features, label, verified_by |

### AI / LLM Integration

- **Provider:** Groq API (fast inference on Qwen3 32B — configurable via `GROQ_MODEL`)
- **Multi-key rotation:** Supports multiple API keys (`GROQ_API_KEYS=key1,key2,...`)
  with round-robin rotation and automatic failover on rate limit (429)
- **Token-aware rate limiting:** Enforces both RPM and TPM budgets per key with concurrency control
- **Response caching:** TTL-based cache (1 hour) to avoid redundant API calls
- **SmartEngine** (`app/ai/smart_engine.py`, 635 lines) orchestrates:
  - PortSwigger knowledge base lookups (20+ vuln categories, 269 labs)
  - AI-powered vulnerability analysis and verification
  - Smart payload selection (used by 4 scanners: SQLi, XSS, Command Injection, SSTI)
  - AI reconnaissance (target tech stack: server, language, framework, WAF detection)
  - Executive summary generation
  - Remediation plan generation with PortSwigger lab references
  - Attack narrative generation
  - Risk score explanation
- **Report Writer** (`app/ai/report_writer.py`, 274 lines): 4 prompt templates + fallback generators
- **Graceful degradation:** All AI features are optional; app works without `GROQ_API_KEY`
- **Prompt injection defense:** 9 regex patterns filter malicious prompts from target responses before LLM verification

### ML Pipeline

- **Model:** Random Forest + Gradient Boosting ensemble (scikit-learn)
- **Purpose:** False-positive classification of scanner findings
- **Model integrity:** SHA-256 checksum verification before loading (`sign_model.py`)
- **Training pipeline:** Admin labels findings → `ScanAttempt` records → retrain via `/ml/retrain`
- **Minimum:** Requires ≥10 labeled samples for retraining
- **Storage:** `data/ml_models/fp_classifier_v{timestamp}.joblib`
- **Integration:** SmartEngine loads model on first use; admin can force-reload after retrain

### Multi-Tenancy

- Organizations with roles: `owner`, `admin`, `member`, `viewer`
- Scans are scoped to user or organization
- API keys can be org-scoped
- Webhooks fire on scan events (complete, error, vulnerability found)
- Plan-based resource limits (free/pro/enterprise) control scan quotas, team size, and AI access
- GDPR data purge support (`Organization.delete_all_data`)

### Frontend Design System

- **Theme:** Dark cybersecurity aesthetic with neon cyan (`#00E5FF`) primary accent
- **Fonts:** Space Grotesk (display), Inter (body), JetBrains Mono (monospace)
- **CSS architecture:** sudarshan.css (custom design system, 359 lines) + tailwind-built.css (pre-compiled)
- **CSS variables:** `--bg-main: #050816`, `--accent-primary: #00E5FF`, `--success: #00FF9D`, `--critical: #FF4D6D`
- **Animations:** fade-in-up, pulse-glow, slide-in, nav-shimmer, btn-shimmer
- **Components:** Glass cards, vulnerability detail toggles, neon buttons, sidebar nav

---

## Key Configuration (`.env`)

| Variable | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `SECRET_KEY` | Yes | Auto-generated | Flask session secret |
| `SUPABASE_URL` | Yes* | — | Supabase project URL |
| `SUPABASE_ANON_KEY` | Yes* | — | Supabase public anon key |
| `SUPABASE_SERVICE_KEY` | Yes* | — | Supabase service role key |
| `DATABASE_URL` | No | SQLite | PostgreSQL URI (falls back to SQLite) |
| `REDIS_URL` | No | localhost:6379 | Redis URI (falls back to threading) |
| `GROQ_API_KEY` | No | — | Single Groq API key for AI features |
| `GROQ_API_KEYS` | No | — | Comma-separated Groq keys for rotation |
| `GROQ_MODEL` | No | `qwen/qwen3-32b` | LLM model name |
| `PORT` | No | 5000 | Server port |
| `FLASK_DEBUG` | No | 1 | Debug mode |
| `ALLOW_LOCAL_TARGETS` | No | false | Allow scanning localhost/private IPs |
| `ALLOW_INSECURE_TARGETS` | No | false | Skip TLS verification for testing |
| `ALLOW_DESTRUCTIVE_PAYLOADS` | No | false | Allow DROP/INSERT SQL payloads (lab use only) |

*Required for login/register to work.

---

## API Endpoints (37 total)

### Web Routes (Server-Rendered)
- `GET /` — Landing page (redirects authenticated users to dashboard)
- `GET /health` — Liveness check
- `GET /readiness` — Readiness check (probes DB)
- `GET /login`, `GET /register` — Auth pages
- `POST /auth/callback` — Token verification (CSRF exempt, origin validated)
- `GET /auth/callback-handler` — OAuth redirect handler
- `GET /logout` — Session clear
- `GET /dashboard` — User dashboard
- `GET /scan/new`, `POST /scan/new` — New scan (rate limited 10/hr)
- `GET /scan/<id>/progress` — Live progress page (SSE + polling fallback)
- `GET /scan/<id>/status` — JSON status (polling, rate limit exempt)
- `GET /scan/<id>/stream` — SSE event stream (rate limit exempt)
- `POST /scan/<id>/pause` — Pause scan
- `POST /scan/<id>/resume` — Resume scan
- `POST /scan/<id>/stop` — Stop scan
- `GET /scan/<id>/results` — Results page with severity/type filters
- `GET /scan/<id>/report/pdf` — PDF report download (rate limited 10/hr)
- `GET /scan/<id>/report/html` — HTML report download (rate limited 10/hr)
- `GET /history` — Scan history with search, date filter, pagination
- `POST /history/<id>/delete` — Delete scan (form-based)
- `DELETE /api/scans/<id>` — Delete scan (AJAX, CSRF exempt)

### ML Admin Routes (admin-only)
- `GET /ml/labeling` — Labeling interface
- `POST /ml/label/<attempt_id>` — Label scan attempt
- `GET /ml/stats` — Model stats
- `GET /ml/export` — Export labeled data
- `GET /ml/findings` — Findings for labeling (paginated JSON)
- `POST /ml/label-vuln/<vuln_id>` — Label vulnerability + create ScanAttempt
- `POST /ml/retrain` — Retrain ML model (rate limited 3/hr)

### API v1 (Legacy, 60/min)
- `GET /api/scan/<id>/status` — Scan status
- `GET /api/stats` — Global stats
- `GET /api/health` — Health check
- `GET /api/metrics` — Prometheus metrics (CSRF exempt)

### API v2 (JSON, session auth, 30/min)
- `GET /api/v2/auth/session` — Current session info
- `GET /api/v2/dashboard` — Dashboard stats
- `GET /api/v2/scans` — List scans (paginated, filterable)
- `POST /api/v2/scans` — Start scan (CSRF exempt, rate limited 10/hr)
- `GET /api/v2/scans/<id>` — Scan details
- `DELETE /api/v2/scans/<id>` — Delete scan (CSRF exempt, rate limited 20/hr)
- `GET /api/v2/scans/<id>/status` — Live scan status
- `GET /api/v2/scans/<id>/results` — Vulnerabilities (severity/type filters)
- `POST /api/v2/scans/<id>/pause` — Pause scan (CSRF exempt)
- `POST /api/v2/scans/<id>/resume` — Resume scan (CSRF exempt)
- `POST /api/v2/scans/<id>/stop` — Stop scan (CSRF exempt)
- `GET /api/v2/scans/<id>/stream` — SSE event stream
- `GET /api/v2/scans/<id>/report/<fmt>` — Download PDF/HTML report (rate limited 20/hr)
- `GET /api/v2/checks` — List available vulnerability checks

---

## Vulnerability Scanners (22 modules, 24 classes)

| Scanner | File | Lines | Techniques | AI/ML |
|---------|------|-------|------------|-------|
| SQL Injection | `sql_injection.py` | 560 | Error-based, UNION, time-based blind, boolean, stacked | ✅ Smart payloads + ML |
| XSS | `xss.py` | 535 | Reflected, stored, DOM, event handlers, polyglots | ✅ Smart payloads + ML |
| Command Injection | `command_injection.py` | 364 | Linux/Windows, blind, IFS bypass | ✅ Smart payloads + ML |
| Directory Traversal | `directory_traversal.py` | 300 | Path traversal, null byte, PHP wrappers (38 payloads) | PayloadManager |
| XXE | `xxe.py` | 399 | File retrieval, SSRF via XXE, OOB, XInclude | ✅ Smart payloads + ML |
| SSRF | `ssrf.py` | 450 | AWS/GCP/Azure metadata, localhost, protocol handlers | PayloadManager |
| CSRF | `csrf.py` | 269 | Token validation, SameSite, origin checks | — |
| CORS | `cors.py` | 206 | Origin reflection, null origin, bypass (9 test payloads) | — |
| Clickjacking | `clickjacking.py` | 96 | X-Frame-Options, CSP frame-ancestors | — |
| Security Headers | `security_headers.py` | 323 | 9 headers, CSP strength, cookie flags, server disclosure | — |
| Open Redirect | `open_redirect.py` | 302 | Parameter/path-based, 16 bypass payloads | ML recording |
| SSTI | `ssti.py` | 259 | Jinja2, Twig, Freemarker, Velocity, ERB, Pebble | ✅ Smart payloads + ML |
| IDOR | `idor.py` | 219* | Sequential ID, UUID, parameter manipulation | — |
| Directory Listing | `idor.py` | (shared) | 16 common dirs, SPA canary detection | — |
| Broken Auth | `broken_auth.py` | 398 | Default creds (14 combos), lockout, cookie flags | — |
| JWT Attacks | `jwt_attacks.py` | 420 | Alg none (4 variants), weak secret (21 passwords), expired, claims | — |
| NoSQL Injection | `nosql_injection.py` | 314 | MongoDB $gt/$ne/$regex, JS injection, blind (18 payloads) | — |
| File Upload | `file_upload.py` | 288 | Dangerous ext, MIME bypass, double ext, null byte (10 extensions) | — |
| Host Header | `host_header.py` | 156 | Host injection, X-Forwarded-Host, reset poisoning (7 paths) | — |
| Info Disclosure | `info_disclosure.py` | 196 | 28 sensitive paths, 8 stack trace patterns | — |
| Prototype Pollution | `prototype_pollution.py` | 322 | __proto__, constructor.prototype, JSON body (11 payloads) | — |
| Insecure Deserialization | `insecure_deserialization.py` | 499 | Java/PHP/Python/ViewState cookies, parameter injection | — |

**All scanners:** Inherit from `BaseScanner`, implement `scan(target_url, injectable_points)`, return `self.findings` list of dicts. All include baseline comparison and false-positive mitigation.

**5 scanners with AI smart payloads:** SQLi, XSS, Command Injection, XXE, SSTI.
**6 scanners using PayloadManager:** SQLi, XSS, Command Injection, Dir Traversal, XXE, SSRF.
**Session fixation test in broken_auth.py:** Intentionally disabled (documented FP with wrong credentials).

---

## Test Suite (226 tests)

| Test File | Tests | Components Covered |
|-----------|-------|-------------------|
| `test_crawler.py` | 39 | URL normalization, validation, scoping, link extraction |
| `test_crawler_scanner.py` | 33 | Crawler + SQLi, XSS, IDOR, CmdInj, CSRF, DirTraversal |
| `test_integration.py` | 14 | Flask routes, ORM CRUD, cascade delete, scanner registry (22 scanners) |
| `test_multi_tenancy.py` | 12 | Organizations, plan limits, GDPR purge, org-scoped API keys |
| `test_new_scanners.py` | 22 | XXE, SSRF, Open Redirect, CORS, Clickjacking |
| `test_phase5_scanners.py` | 30 | NoSQLi, File Upload, Host Header, InfoDisc, Prototype, Deser |
| `test_routes.py` | 28 | All HTTP routes, API v2, auth, origin validation (BUG-008 regression) |
| `test_smart_engine_integration.py` | 19 | SmartEngine, ML prediction, singleton thread safety, report writer |
| `test_stateless_scan_manager.py` | 10 | ScanManager: Redis/in-memory/DB fallback, control signals |
| `test_url_safety.py` | 19 | SSRF protection, cloud metadata blocking (BUG-001 regression) |

**Key patterns:** All tests use `unittest.mock` (zero network calls), in-memory SQLite for integration tests, regression tests for BUG-001 and BUG-008.

---

## Known Issues & Technical Debt

### Minor Issues (from deep analysis)
1. **`connect_args={"connect_timeout": 5}`** in `__init__.py` may be silently ignored by psycopg3 (uses URI param instead)
2. **Thread safety in `tasks.py`**: `findings` list and `seen_vulns` set shared across threads without explicit lock (CPython GIL provides de facto safety but not guaranteed)
3. **Score calculation ignores low/info**: `_calculate_score()` in tasks.py only deducts for critical/high/medium
4. **In-memory filtering in `api_v2.scan_results()`** vs DB-level filtering in `results.view()` — performance concern for large result sets
5. **Logout via GET** in `auth.py` — minor CSRF logout risk (low impact)
6. **`pause/resume/stop` in scan.py** return `{"success": false}` without 403 HTTP status on auth failure
7. **SSE code duplication** between `_stream_redis()` and `_stream_threading()` (~60% shared logic)
8. **`retrain_model()`** directly manipulates `engine._ml_loaded` — should use a proper reload method
9. **Duplicate health endpoints**: `/health` (main.py) and `/api/health` (api.py)
10. **GROQ_MODEL comment mismatch**: `start.py` says "Llama 3.3 70B" but config uses `qwen/qwen3-32b`
11. **`ALLOW_DESTRUCTIVE_PAYLOADS`** missing `"YES"` in truthy values (inconsistent with `ALLOW_INSECURE_TARGETS`)
12. **No logo/image assets**: `static/img/` is empty; referenced only in CSS/templates as text
13. **Windows line endings** in `ml_admin.py` only — inconsistent with other files
14. **`api_delete` in history.py** overlaps conceptually with `api_v2.delete_scan()`

### All Production-Quality
- **No TODOs, stubs, or placeholder implementations found** in any source file
- All 87 Python files are complete and functional
- Every vulnerability scanner is fully implemented with false-positive mitigation

---

## Development

### Rebuild Tailwind CSS (after template changes)
```bash
npm run build:css       # One-time build (minified)
npm run watch:css       # Watch mode (auto-rebuild on save)
```

### Run Tests
```bash
.venv/Scripts/python -m pytest tests/ -v
```

### Celery Worker (optional, for async scans)
```bash
celery -A app.celery_app.celery worker --loglevel=info
```

### Sign ML Model (after retraining)
```bash
python -m app.ml.sign_model data/ml_models/fp_classifier_v{timestamp}.joblib
```

### Scan Speed Profiles
| Profile | Delay | Threads | Timeout | Max URLs |
|---------|-------|---------|---------|----------|
| Safe | 1.0s | 3 | 10s | 75 |
| Balanced | 0.15s | 6 | 8s | 200 |
| Aggressive | 0.05s | 10 | 5s | 500 |

### Plan Limits
| Plan | Scans/Month | Concurrent | Team Size | Max URLs | AI |
|------|-------------|------------|-----------|----------|----|
| Free | 5 | 1 | 3 | 100 | ❌ |
| Pro | 50 | 3 | 15 | 500 | ✅ |
| Enterprise | ∞ | 10 | ∞ | ∞ | ✅ |
