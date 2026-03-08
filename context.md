# 🛡️ Sudarshan — Web Vulnerability Scanner | Project Context

> **Last Updated:** 2026-03-06  
> **Language:** Python 3  
> **Framework:** Flask 3.0.0  
> **Database:** SQLite  
> **Entry Point:** `run.py` → `app/__init__.py` (factory pattern)  
> **Default Port:** 5000

---

## 1. Project Overview

Sudarshan is an **automated web vulnerability scanner** built with Python and Flask. It provides a full-featured web UI for launching security scans against target websites, monitoring progress in real time via Server-Sent Events (SSE), and viewing detailed vulnerability reports with security scoring.

### Core Capabilities
- **8 vulnerability check modules** (SQL Injection, XSS, CSRF, Security Headers, Directory Traversal, Command Injection, IDOR, Directory Listing)
- **Real-time scan monitoring** via SSE (Server-Sent Events)
- **Scan controls:** Pause / Resume / Stop
- **Security scoring** with A–F letter grades
- **HTML report download** with full PoC details
- **DVWA integration** for authenticated scanning (Low / Medium / High security levels)
- **Dark-themed UI** with live stats and charts
- **User authentication** with registration/login system

---

## 2. Tech Stack & Dependencies

| Component        | Technology                     |
|------------------|--------------------------------|
| Backend          | Flask 3.0.0, Werkzeug 3.0.1   |
| Database         | SQLite (via `sqlite3` stdlib)  |
| HTML Parsing     | BeautifulSoup4 4.12.2, lxml   |
| HTTP Client      | requests 2.31.0, urllib3 2.0.7 |
| Reports          | fpdf2 2.7.6 (PDF generation)  |
| Session          | Flask-Session 0.5.0            |
| Environment      | python-dotenv 1.0.0            |
| Testing          | pytest 7.4.3, pytest-cov 4.1.0|

---

## 3. Project Structure

```
sudarshan/
├── run.py                          # Entry point → create_app(), runs on 0.0.0.0:5000
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment variable template
├── .gitignore
│
├── app/                            # Main application package
│   ├── __init__.py                 # Flask app factory (create_app)
│   ├── config.py                   # Configuration classes (Dev/Prod)
│   │
│   ├── models/                     # Database layer (SQLite)
│   │   ├── database.py             # DB connection, init_db(), query_db(), execute_db()
│   │   ├── user.py                 # User model (auth, password hashing)
│   │   ├── scan.py                 # Scan model (CRUD, progress tracking)
│   │   └── vulnerability.py        # Vulnerability model (findings storage)
│   │
│   ├── scanner/                    # Scanner engine
│   │   ├── crawler.py              # Web crawler (concurrent BFS, form extraction)
│   │   ├── scan_manager.py         # Scan orchestrator (SSE, threading, lifecycle)
│   │   ├── dvwa_auth.py            # DVWA authentication helper
│   │   └── vulnerabilities/        # Vulnerability check modules
│   │       ├── base.py             # BaseScanner (abstract base class)
│   │       ├── sql_injection.py    # SQL Injection scanner (24.5 KB)
│   │       ├── xss.py              # XSS scanner (22.5 KB)
│   │       ├── csrf.py             # CSRF scanner (10.3 KB)
│   │       ├── security_headers.py # Security Headers scanner (15.5 KB)
│   │       ├── directory_traversal.py # Directory Traversal scanner (10.2 KB)
│   │       ├── command_injection.py   # Command Injection scanner (13.4 KB)
│   │       └── idor.py             # IDOR + Directory Listing scanner (8.2 KB)
│   │
│   ├── routes/                     # Flask Blueprints (7 total)
│   │   ├── main.py                 # Landing page (/)
│   │   ├── auth.py                 # Login / Register / Logout
│   │   ├── dashboard.py            # User dashboard with stats & charts
│   │   ├── scan.py                 # New scan, progress, SSE stream, controls
│   │   ├── results.py              # Scan results view + HTML/PDF report download
│   │   ├── history.py              # Scan history with search, filter, pagination
│   │   └── api.py                  # REST API (scan status, global stats)
│   │
│   ├── templates/                  # Jinja2 HTML templates
│   │   ├── base.html               # Base layout (dark theme, 14.8 KB)
│   │   ├── main/index.html         # Landing page
│   │   ├── auth/login.html         # Login form
│   │   ├── auth/register.html      # Registration form
│   │   ├── dashboard/index.html    # Dashboard with charts
│   │   ├── scan/new.html           # New scan form (15 KB)
│   │   ├── scan/progress.html      # Live scan progress (15 KB)
│   │   ├── results/view.html       # Scan results detail
│   │   └── history/index.html      # Scan history list
│   │
│   ├── static/                     # Static assets (CSS, JS, images)
│   └── utils/                      # Utility modules (currently empty __init__.py)
│
├── data/                           # SQLite database & reports directory
├── logs/                           # Application log files
├── tests/                          # Test suite
│   └── test_crawler_scanner.py     # Crawler & scanner tests (20 KB)
├── scripts/
│   └── init_db.py                  # Database initialization script
├── migrations/                     # DB migrations (placeholder, .gitkeep)
├── docs/                           # Documentation (empty)
│
├── COMPLETE_ANALYSIS_AND_SOLUTION.md
├── DVWA_FIX_GUIDE.md
├── IMPLEMENTATION_CHECKLIST.md
├── INTEGRATION_GUIDE (1).md
├── PROJECT_REORGANIZATION_PLAN.md
├── REORGANIZATION_COMPLETE_GUIDE.md
├── detailed saas_analysis.md
├── detailed_file_descriptions.md
├── integration_guide.md
├── saas_analysis.md
├── vulnerability_detection_enhancement.md
└── project_structure_visualization.txt
```

---

## 4. Architecture

### 4.1 Application Factory Pattern

```
run.py
  └── create_app() [app/__init__.py]
        ├── Load config (DevelopmentConfig / ProductionConfig)
        ├── Create data/reports & logs directories
        ├── Initialize SQLite database (init_db)
        └── Register 7 Blueprints:
              main_bp, auth_bp, dashboard_bp, scan_bp,
              results_bp, history_bp, api_bp
```

### 4.2 Request Flow

```
User Browser
    │
    ▼
Flask Routes (Blueprints)
    │
    ├── Auth routes → User model → SQLite
    ├── Dashboard → Scan model → SQLite (aggregated stats)
    ├── New Scan → ScanManager.start_scan()
    │                   │
    │                   ├── Crawler.crawl() → discover URLs & forms
    │                   ├── Run vulnerability scanners (ThreadPoolExecutor)
    │                   ├── Emit SSE events → client browser
    │                   └── Store findings → Vulnerability model → SQLite
    ├── Scan Progress → SSE stream endpoint (/scan/<id>/stream)
    ├── Results → Vulnerability model → HTML/PDF report generation
    └── History → Scan model → paginated list with filters
```

### 4.3 Scan Engine Architecture

```
ScanManager (Singleton)
    │
    ├── active_scans: dict[scan_id → scan context]
    ├── sse_queues: dict[scan_id → list[queue.Queue]]
    │
    └── _run_scan(ctx) [in background thread]
          │
          ├── Phase 1: DVWA Detection & Auth
          │     └── DVWAAuth.is_dvwa_target() → login() → set_security_level()
          │
          ├── Phase 2: Crawling
          │     └── Crawler.crawl(callback=crawl_callback)
          │           ├── BFS with concurrent ThreadPoolExecutor
          │           ├── robots.txt parsing & respect
          │           ├── Link extraction (HTML, forms, JS patterns)
          │           ├── Form extraction with action/method/inputs
          │           └── Returns (discovered_urls, injectable_points)
          │
          ├── Phase 3: Vulnerability Scanning (concurrent)
          │     └── ThreadPoolExecutor runs selected checks:
          │           ├── SQLInjectionScanner       → error-based, blind, time-based
          │           ├── XSSScanner                → reflected, DOM, stored detection
          │           ├── CSRFScanner               → token absence, weak tokens
          │           ├── SecurityHeadersScanner    → missing headers, misconfig
          │           ├── DirectoryTraversalScanner → path traversal payloads
          │           ├── CommandInjectionScanner   → OS command injection
          │           ├── IDORScanner               → insecure direct object references
          │           └── DirectoryListingScanner   → open directory listings
          │
          └── Phase 4: Finalization
                ├── Calculate security score (A–F)
                ├── Store results in SQLite
                └── Emit 'complete' SSE event
```

---

## 5. Database Schema (SQLite)

### 5 Tables

| Table             | Key Columns                                                              |
|-------------------|--------------------------------------------------------------------------|
| **users**         | `id`, `username`, `email`, `password_hash`, `created_at`                 |
| **scans**         | `id`, `user_id` (FK), `target_url`, `scan_mode`, `scan_speed`, `crawl_depth`, `status`, `score`, `total_urls`, `tested_urls`, `vuln_count`, `critical_count`, `high_count`, `medium_count`, `low_count`, `duration`, `started_at`, `completed_at` |
| **vulnerabilities** | `id`, `scan_id` (FK), `vuln_type`, `name`, `description`, `impact`, `severity`, `cvss_score`, `owasp_category`, `affected_url`, `parameter`, `payload`, `request_data`, `response_data`, `remediation`, `found_at` |
| **crawled_urls**  | `id`, `scan_id` (FK), `url`, `status_code`, `forms_found`, `params_found`, `crawled_at` |
| **scan_logs**     | `id`, `scan_id` (FK), `log_type`, `message`, `logged_at`                |

### Scan Statuses
`pending` → `running` → `paused` → `running` → `completed` | `stopped` | `error`

---

## 6. Key Components Detail

### 6.1 ScanManager (`app/scanner/scan_manager.py` — 436 lines)

**Singleton** pattern managing all active scans.

| Method                | Purpose                                              |
|-----------------------|------------------------------------------------------|
| `get_instance()`      | Get/create singleton instance                        |
| `start_scan()`        | Create scan context & launch background thread       |
| `pause_scan()`        | Set pause event flag                                 |
| `resume_scan()`       | Clear pause event flag                               |
| `stop_scan()`         | Set stop flag, cancel thread                         |
| `get_status()`        | Return current scan state as dict                    |
| `register_sse_client()` | Add SSE queue for real-time client                |
| `unregister_sse_client()` | Remove SSE queue                                |
| `_emit()`             | Push SSE event to all registered clients + DB log    |
| `_run_scan()`         | Main scan loop (crawl → scan → finalize)             |
| `_calculate_score()`  | Compute A–F grade from findings                      |
| `_finalize()`         | Persist results, update DB, emit complete event      |

### 6.2 Crawler (`app/scanner/crawler.py` — 440 lines)

Concurrent BFS web crawler with configurable depth, delay, threading.

| Feature                   | Detail                                           |
|---------------------------|--------------------------------------------------|
| **Concurrency**           | `ThreadPoolExecutor` with configurable thread count |
| **URL normalization**     | Strips fragments, trailing slashes, sorts params |
| **robots.txt**            | Parsed and respected (configurable)              |
| **Authentication**        | Cookie-based via optional `auth_config`          |
| **Link extraction**       | HTML `<a>`, `<form>`, `<script>` patterns         |
| **Form extraction**       | Action, method, input fields detection           |
| **Content filtering**     | HEAD request to skip binary/non-HTML content     |
| **Retry logic**           | Exponential backoff (2 retries max)              |
| **Deduplication**         | Normalized URL set                               |

### 6.3 BaseScanner (`app/scanner/vulnerabilities/base.py` — 83 lines)

Abstract base class for all vulnerability scanners.

| Feature                   | Detail                                           |
|---------------------------|--------------------------------------------------|
| **User-Agent**            | `Sudarshan-Scanner/1.0`                          |
| **SSL verification**      | Disabled (allows self-signed certs)              |
| **Rate limiting**         | Enforced delay between consecutive requests      |
| **Timed requests**        | `_timed_request()` for time-based blind detection|
| **Baseline caching**      | `_get_baseline_time()` with per-URL cache        |
| **Abstract method**       | `scan(target_url, injectable_points)` must implement |

### 6.4 Vulnerability Scanners

| Scanner                   | File Size | Techniques                                      |
|---------------------------|-----------|--------------------------------------------------|
| **SQLInjectionScanner**   | 24.5 KB   | Error-based, boolean-blind, time-based blind, UNION |
| **XSSScanner**            | 22.5 KB   | Reflected, DOM-based, stored XSS detection       |
| **CSRFScanner**           | 10.3 KB   | Missing tokens, weak/predictable tokens          |
| **SecurityHeadersScanner**| 15.5 KB   | CSP, HSTS, X-Frame, X-XSS, referrer, permissions|
| **DirectoryTraversalScanner** | 10.2 KB | Path traversal payloads (/etc/passwd, etc.)  |
| **CommandInjectionScanner** | 13.4 KB | OS command injection (`;`, `|`, `&&`, backticks)|
| **IDORScanner**           | 8.2 KB    | Insecure direct object reference detection       |
| **DirectoryListingScanner** | (in idor.py) | Open directory listing detection           |

### 6.5 DVWAAuth (`app/scanner/dvwa_auth.py` — 280 lines)

Helper for authenticated scanning of DVWA (Damn Vulnerable Web App).

| Method                    | Purpose                                          |
|---------------------------|--------------------------------------------------|
| `login()`                 | Authenticate to DVWA, return `requests.Session`  |
| `set_security_level()`    | Set DVWA security: low / medium / high           |
| `get_security_level()`    | Read current DVWA security level                 |
| `is_dvwa_target()`        | Auto-detect if target is a DVWA instance         |

---

## 7. Route Endpoints

### 7.1 Main (`main_bp`)
| Route | Method | Function | Description |
|-------|--------|----------|-------------|
| `/` | GET | `index()` | Landing page with global stats |

### 7.2 Auth (`auth_bp`)
| Route | Method | Function | Description |
|-------|--------|----------|-------------|
| `/login` | GET, POST | `login()` | User login |
| `/register` | GET, POST | `register()` | New user registration |
| `/logout` | GET | `logout()` | Clear session & logout |

### 7.3 Dashboard (`dashboard_bp`)
| Route | Method | Function | Description |
|-------|--------|----------|-------------|
| `/dashboard` | GET | `index()` | User dashboard with stats, charts, recent scans |

### 7.4 Scan (`scan_bp`)
| Route | Method | Function | Description |
|-------|--------|----------|-------------|
| `/scan/new` | GET, POST | `new_scan()` | Configure & launch new scan |
| `/scan/<id>/progress` | GET | `progress()` | Live scan progress page |
| `/scan/<id>/stream` | GET | `stream()` | SSE stream endpoint |
| `/scan/<id>/pause` | POST | `pause()` | Pause running scan |
| `/scan/<id>/resume` | POST | `resume()` | Resume paused scan |
| `/scan/<id>/stop` | POST | `stop()` | Stop running scan |

### 7.5 Results (`results_bp`)
| Route | Method | Function | Description |
|-------|--------|----------|-------------|
| `/results/<id>` | GET | `view()` | Detailed scan results |
| `/results/<id>/pdf` | GET | `generate_pdf()` | Download PDF report |

### 7.6 History (`history_bp`)
| Route | Method | Function | Description |
|-------|--------|----------|-------------|
| `/history` | GET | `index()` | Paginated scan history with filters |
| `/history/<id>/delete` | POST | `delete()` | Delete scan (form) |
| `/api/scans/<id>` | DELETE | `api_delete()` | Delete scan (AJAX) |

### 7.7 API (`api_bp`)
| Route | Method | Function | Description |
|-------|--------|----------|-------------|
| `/api/scan/<id>/status` | GET | `scan_status()` | Get scan status JSON |
| `/api/stats` | GET | `global_stats()` | Global vulnerability stats |

---

## 8. Configuration

### Scan Speeds

| Speed        | Delay  | Threads | Timeout | Max URLs |
|-------------|--------|---------|---------|----------|
| `safe`      | 1.0s   | 3       | 10s     | 75       |
| `balanced`  | 0.15s  | 6       | 8s      | 200      |
| `aggressive`| 0.05s  | 10      | 5s      | 500      |

### OWASP Top 10 Mapping

| Code | Category                              |
|------|---------------------------------------|
| A01  | Broken Access Control                 |
| A02  | Cryptographic Failures                |
| A03  | Injection                             |
| A04  | Insecure Design                       |
| A05  | Security Misconfiguration             |
| A06  | Vulnerable Components                 |
| A07  | Identification and Auth Failures      |
| A08  | Software and Data Integrity Failures  |
| A09  | Security Logging Failures             |
| A10  | Server-Side Request Forgery           |

### Severity Levels
`critical` > `high` > `medium` > `low` > `info`

---

## 9. Authentication System

- **Password hashing:** SHA-256 with random 16-byte salt (`salt:hash` format)
- **Session management:** Flask session with `user_id` and `username`
- **Route protection:** `login_required` decorator (defined per-blueprint)
- **Session cookies:** `HttpOnly=True`, `SameSite=Lax`

---

## 10. Real-Time Features (SSE)

The scan progress page uses **Server-Sent Events** for live updates:

| Event Type   | Data                                         |
|-------------|----------------------------------------------|
| `log`       | Log message with level (info/warning/error)   |
| `finding`   | New vulnerability found (name, severity, URL) |
| `progress`  | Scan progress (phase, total, tested, findings)|
| `complete`  | Scan finished (score, scan_id)                |
| `heartbeat` | Keep-alive ping (every 30s timeout)           |

**Reconnection support:** On SSE reconnect, existing DB logs and findings are replayed before streaming live events.

---

## 11. Report Generation

- **HTML Report:** Full styled report with vulnerability details, PoC payloads, request/response data, and remediation advice (`_generate_html_report()` in `results.py`)
- **PDF Report:** Generated via `fpdf2` library

---

## 12. Testing

- **Test file:** `tests/test_crawler_scanner.py` (20 KB)
- **Framework:** pytest with coverage support
- **Run tests:** `pytest tests/ --cov=app`

---

## 13. Environment Variables

```env
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-change-this-in-production
DATABASE_PATH=data/database.db
SCAN_SPEED=balanced
MAX_SCAN_DEPTH=3
DVWA_URL=http://localhost:8888
DVWA_USERNAME=admin
DVWA_PASSWORD=password
```

---

## 14. How to Run

```bash
# 1. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application
python run.py

# 4. Open browser
# http://localhost:5000
```

---

## 15. Known Issues & Future Considerations

Based on past analysis (SaaS readiness reviews, bug fixes):

- **Scan state reset on page refresh:** Refreshing during an active scan resets live stats (SSE reconnection replays from DB mitigates this)
- **Password hashing:** Uses SHA-256 instead of bcrypt/argon2 (not production-grade)
- **Single-tenant SQLite:** Not suitable for multi-user SaaS without migration to PostgreSQL/MySQL
- **No CSRF protection** on the application's own forms (ironic for a CSRF scanner)
- **`login_required`** decorator duplicated across multiple route files instead of being centralized
- **Secret key** hardcoded as fallback in config
- **No rate limiting** on auth endpoints
- **No input sanitization** on search queries in history (potential SQL injection in f-string query construction)

---

## 16. Documentation Files

| File                                    | Description                            |
|-----------------------------------------|----------------------------------------|
| `COMPLETE_ANALYSIS_AND_SOLUTION.md`     | Full analysis and solutions            |
| `DVWA_FIX_GUIDE.md`                     | Guide for fixing DVWA scanning issues  |
| `IMPLEMENTATION_CHECKLIST.md`           | Implementation task checklist          |
| `INTEGRATION_GUIDE (1).md`             | Integration guide                      |
| `PROJECT_REORGANIZATION_PLAN.md`        | Project restructuring plan             |
| `REORGANIZATION_COMPLETE_GUIDE.md`      | Complete reorganization guide          |
| `detailed saas_analysis.md`            | Detailed SaaS readiness analysis       |
| `detailed_file_descriptions.md`         | Per-file detailed descriptions         |
| `integration_guide.md`                  | Integration guide                      |
| `saas_analysis.md`                      | SaaS analysis summary                  |
| `vulnerability_detection_enhancement.md`| Vulnerability detection improvements   |
