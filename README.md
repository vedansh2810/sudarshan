# 🛡️ Sudarshan — Web Vulnerability Scanner
Note - **This project is under development. Frontend is fucked up, currently working on backend**
An automated web vulnerability scanner built with Python & Flask.

## Features
- **10 vulnerability checks**: SQLi, XSS, CSRF, Security Headers, Directory Traversal, Command Injection, IDOR, Directory Listing
- **Real-time scan monitoring** with SSE (Server-Sent Events)
- **Pause / Resume / Stop** scan controls
- **Security Score** (A–F grading)
- **HTML Report** download with full PoC details
- **Dark-themed UI** with live stats

## Setup

```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install flask requests beautifulsoup4 lxml

# 3. Run
python app.py

# 4. Open http://localhost:5000
```

## Project Structure
```
sudarshan/
├── app.py                  # Flask app factory
├── config.py               # Settings (speeds, checks, DB path)
├── models/                 # SQLite database layer
│   ├── database.py         # DB init & helpers
│   ├── scan.py             # Scan model
│   ├── user.py             # User model (auth)
│   └── vulnerability.py    # Vulnerability model
├── scanner/                # Scanner engine
│   ├── crawler.py          # Web crawler
│   ├── scan_manager.py     # SSE orchestrator
│   └── vulnerabilities/    # Individual checks
│       ├── sql_injection.py
│       ├── xss.py
│       ├── csrf.py
│       ├── security_headers.py
│       ├── directory_traversal.py
│       ├── command_injection.py
│       └── idor.py (+ DirectoryListing)
├── routes/                 # Flask blueprints
│   ├── auth.py
│   ├── dashboard.py
│   ├── scan.py
│   ├── results.py
│   ├── history.py
│   └── api.py
└── templates/              # Jinja2 HTML templates
    ├── base.html
    ├── auth/
    ├── dashboard/
    ├── scan/
    ├── results/
    └── history/
```

## ⚠️ Legal Notice
Only scan systems you own or have explicit written permission to test.
Unauthorized security testing is illegal.
