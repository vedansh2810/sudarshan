#!/usr/bin/env python3
"""
Sudarshan - One-Click Setup & Run Script
=========================================

Usage:
    python start.py              # Setup (if needed) + Run
    python start.py --setup      # Force re-run setup even if already done
    python start.py --run        # Skip setup, just run
    python start.py --check      # Check setup status without running

Works on Windows, macOS, and Linux.
"""

import os
import sys
import subprocess
import shutil
import platform
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent
VENV_DIR = PROJECT_ROOT / ".venv"
ENV_FILE = PROJECT_ROOT / ".env"
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"
REQUIREMENTS = PROJECT_ROOT / "requirements.txt"
PACKAGE_JSON = PROJECT_ROOT / "package.json"
NODE_MODULES = PROJECT_ROOT / "node_modules"
TAILWIND_CSS = PROJECT_ROOT / "app" / "static" / "css" / "tailwind-built.css"
DATA_DIR = PROJECT_ROOT / "data"
SETUP_MARKER = VENV_DIR / ".setup_complete"

IS_WINDOWS = platform.system() == "Windows"
PYTHON = sys.executable

# ── Pre-configured Supabase credentials (auto-written to .env) ───────────
# Embedded so testers can run `python start.py` without Supabase setup.
PRECONFIGURED_SUPABASE = {
    "DATABASE_URL": "postgresql+psycopg://postgres.wgllqlqsgecsijlkhhcw:SudarshanDB2026@aws-1-ap-northeast-1.pooler.supabase.com:5432/postgres",
    "SUPABASE_URL": "https://wgllqlqsgecsijlkhhcw.supabase.co",
    "SUPABASE_ANON_KEY": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndnbGxxbHFzZ2Vjc2lqbGtoaGN3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzMxMTYxMTcsImV4cCI6MjA4ODY5MjExN30.1tbyNnFwUUOC0z9UeC0ijGR8Ig_RfLEPAtO3jiCmeRc",
    "SUPABASE_SERVICE_KEY": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndnbGxxbHFzZ2Vjc2lqbGtoaGN3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MzExNjExNywiZXhwIjoyMDg4NjkyMTE3fQ.TkKAQcRhQp7ZiKGq5Z9_gqrzgvzCMFad5rVsuYMRoII",
}

# Colors (disabled on Windows cmd that doesn't support ANSI)
try:
    os.system("")  # Enable ANSI on Windows 10+
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
except Exception:
    GREEN = YELLOW = RED = CYAN = BOLD = DIM = RESET = ""

# ── Helpers ──────────────────────────────────────────────────────────────

def log(msg, color=GREEN):
    print(f"  {color}->{RESET} {msg}")

def log_header(msg):
    print(f"\n  {CYAN}{BOLD}{'-' * 50}{RESET}")
    print(f"  {CYAN}{BOLD}  {msg}{RESET}")
    print(f"  {CYAN}{BOLD}{'-' * 50}{RESET}\n")

def log_ok(msg):
    print(f"  {GREEN}[OK]{RESET} {msg}")

def log_warn(msg):
    print(f"  {YELLOW}[!!]{RESET} {msg}")

def log_err(msg):
    print(f"  {RED}[FAIL]{RESET} {msg}")

def log_skip(msg):
    print(f"  {DIM}  (skip) {msg}{RESET}")

def run(cmd, cwd=None, check=True, capture=False, env=None):
    """Run a shell command with real-time output."""
    merged_env = {**os.environ, **(env or {})}
    kwargs = {
        "cwd": cwd or PROJECT_ROOT,
        "shell": True,
        "env": merged_env,
    }
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
        kwargs["text"] = True
    result = subprocess.run(cmd, **kwargs)
    if check and result.returncode != 0:
        log_err(f"Command failed: {cmd}")
        if capture and result.stderr:
            print(f"    {result.stderr.strip()}")
        return None
    return result

def get_venv_python():
    """Get the path to the Python executable inside the venv."""
    if IS_WINDOWS:
        return str(VENV_DIR / "Scripts" / "python.exe")
    return str(VENV_DIR / "bin" / "python")

def get_venv_pip():
    """Get the path to pip inside the venv."""
    if IS_WINDOWS:
        return str(VENV_DIR / "Scripts" / "pip.exe")
    return str(VENV_DIR / "bin" / "pip")

def command_exists(cmd):
    """Check if a command exists on PATH."""
    return shutil.which(cmd) is not None


# ── Setup Steps ──────────────────────────────────────────────────────────

def check_python_version():
    """Verify Python 3.10+."""
    log("Checking Python version...")
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 10):
        log_err(f"Python 3.10+ required, but found {major}.{minor}")
        log_err("Download from: https://www.python.org/downloads/")
        sys.exit(1)
    log_ok(f"Python {major}.{minor}.{sys.version_info[2]}")

def setup_venv():
    """Create virtual environment if it doesn't exist."""
    log("Checking virtual environment...")
    venv_python = get_venv_python()

    if os.path.isfile(venv_python):
        log_ok(f".venv/ exists")
        return

    log("Creating virtual environment (.venv/)...")
    run(f'"{PYTHON}" -m venv .venv')

    if not os.path.isfile(venv_python):
        log_err("Failed to create virtual environment")
        sys.exit(1)
    log_ok("Virtual environment created")

def install_python_deps():
    """Install Python dependencies from requirements.txt."""
    log("Checking Python dependencies...")
    venv_pip = get_venv_pip()
    venv_python = get_venv_python()

    # Quick check: try importing Flask (the core dep)
    result = run(
        f'"{venv_python}" -c "import flask; print(flask.__version__)"',
        capture=True, check=False
    )
    if result and result.returncode == 0:
        log_ok(f"Dependencies installed (Flask {result.stdout.strip()})")
        return

    log("Installing Python dependencies (this may take a minute)...")

    # Upgrade pip first
    run(f'"{venv_python}" -m pip install --upgrade pip', check=False)

    # Install requirements
    result = run(f'"{venv_pip}" install -r requirements.txt')
    if result is None:
        log_err("Failed to install dependencies")
        log_warn("Try manually: .venv/Scripts/pip install -r requirements.txt")
        sys.exit(1)
    log_ok("Python dependencies installed")

def setup_env_file():
    """Auto-generate .env with pre-configured Supabase credentials.
    
    Supabase details are embedded in start.py so testers don't need to
    set up their own Supabase project. Groq API keys are optional and
    prompted interactively.
    """
    import secrets as _secrets
    log("Checking .env file...")

    if ENV_FILE.exists():
        content = ENV_FILE.read_text(encoding="utf-8")
        # Check if Supabase credentials are already real (not placeholders)
        has_placeholders = (
            "your-supabase-anon-key" in content
            or "your-project.supabase.co" in content
        )
        if not has_placeholders:
            log_ok(".env configured (Supabase credentials present)")
            return
        else:
            log_warn(".env has placeholder Supabase values -- overwriting with real credentials")

    # Generate a complete .env with Supabase pre-configured
    secret_key = _secrets.token_hex(32)

    env_content = f"""# Sudarshan v2 Environment Configuration
# Auto-generated by start.py -- Supabase credentials pre-configured

# ── Flask ────────────────────────────────────────────────────────────────
SECRET_KEY={secret_key}
FLASK_ENV=development

# Allow scanning localhost / private IP targets (e.g. DVWA on localhost:8888)
ALLOW_LOCAL_TARGETS=true

# ── Database (PostgreSQL via Supabase) ──────────────────────────────────
DATABASE_URL={PRECONFIGURED_SUPABASE["DATABASE_URL"]}

# ── Redis ───────────────────────────────────────────────────────────────
REDIS_PASSWORD=change-this-to-a-strong-password
REDIS_URL=redis://:change-this-to-a-strong-password@localhost:6379/0

# Celery (defaults to REDIS_URL if not set)
# CELERY_BROKER_URL=redis://:change-this-to-a-strong-password@localhost:6379/0
# CELERY_RESULT_BACKEND=redis://:change-this-to-a-strong-password@localhost:6379/0

# ── Supabase Auth (pre-configured) ─────────────────────────────────────
SUPABASE_URL={PRECONFIGURED_SUPABASE["SUPABASE_URL"]}
SUPABASE_ANON_KEY={PRECONFIGURED_SUPABASE["SUPABASE_ANON_KEY"]}
SUPABASE_SERVICE_KEY={PRECONFIGURED_SUPABASE["SUPABASE_SERVICE_KEY"]}

# ── AI / LLM (Groq — Llama 3.3 70B) ────────────────────────────────
# Add your Groq API key(s) below for AI features.
# Single key:
GROQ_API_KEY=
# Multiple keys (comma-separated, round-robin rotation for better rate limits):
# GROQ_API_KEYS=gsk_key1,gsk_key2,gsk_key3
GROQ_MODEL=llama-3.3-70b-versatile
"""

    ENV_FILE.write_text(env_content, encoding="utf-8")
    log_ok(".env created with Supabase credentials pre-configured")
    log_ok(f"SECRET_KEY auto-generated (secure random)")
    log_ok(f"Supabase URL: {PRECONFIGURED_SUPABASE['SUPABASE_URL']}")

    # Prompt for optional Groq API keys
    _prompt_groq_keys()


def _prompt_groq_keys():
    """Interactively prompt for Groq API keys (optional)."""
    print()
    print(f"  {CYAN}{BOLD}--- GROQ API KEY (optional, for AI features) ---{RESET}")
    print()
    print(f"  {DIM}  Groq API keys enable AI features (vulnerability analysis, smart payloads).{RESET}")
    print(f"  {DIM}  Get a free key at: https://console.groq.com{RESET}")
    print(f"  {DIM}  You can add multiple keys for rotation (one per line, or comma-separated).{RESET}")
    print(f"  {DIM}  Press Enter to skip (AI features will be disabled).{RESET}")
    print()

    content = ENV_FILE.read_text(encoding="utf-8")
    groq_keys = []
    first_key = _ask("  GROQ API KEY #1 (or comma-separated list): ").strip()
    if first_key:
        # Check if user pasted comma-separated keys
        if "," in first_key:
            groq_keys = [k.strip() for k in first_key.split(",") if k.strip()]
        else:
            groq_keys.append(first_key)
            # Prompt for more keys
            while True:
                next_key = _ask(f"  GROQ API KEY #{len(groq_keys) + 1} (Enter to finish): ").strip()
                if not next_key:
                    break
                groq_keys.append(next_key)

    if groq_keys:
        if len(groq_keys) == 1:
            content = _replace_env_value(content, "GROQ_API_KEY", groq_keys[0])
        else:
            content = _replace_env_value(content, "GROQ_API_KEYS", ",".join(groq_keys))
            content = _replace_env_value(content, "GROQ_API_KEY", "")
        ENV_FILE.write_text(content, encoding="utf-8")
        log_ok(f"{len(groq_keys)} Groq API key(s) configured")
    else:
        log_warn("No Groq keys entered -- AI features disabled. Edit .env later to add them.")


def _ask(prompt):
    """Prompt user for input, handling EOF gracefully."""
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def _replace_env_value(content, key, value):
    """Replace an env variable's value in .env content string."""
    import re
    # Match KEY=anything (including empty) up to end of line
    pattern = rf'^{re.escape(key)}=.*$'
    replacement = f'{key}={value}'
    new_content, count = re.subn(pattern, replacement, content, flags=re.MULTILINE)
    if count == 0:
        # Key not found, append it
        if not new_content.endswith('\n'):
            new_content += '\n'
        new_content += f'{replacement}\n'
    return new_content

def generate_secret_key():
    """Auto-generate SECRET_KEY if it's still the default."""
    if not ENV_FILE.exists():
        return

    content = ENV_FILE.read_text(encoding="utf-8")
    if "change-me-to-a-random-secret-key" in content or "SECRET_KEY=change-me" in content:
        import secrets
        new_key = secrets.token_hex(32)
        content = content.replace("change-me-to-a-random-secret-key", new_key)
        content = content.replace("SECRET_KEY=change-me", f"SECRET_KEY={new_key}")
        ENV_FILE.write_text(content, encoding="utf-8")
        log_ok("SECRET_KEY auto-generated (secure random)")

def create_data_dirs():
    """Create required data directories."""
    log("Checking data directories...")
    dirs = [
        DATA_DIR,
        DATA_DIR / "reports",
        DATA_DIR / "report_diagrams",
        DATA_DIR / "ml_models",
        DATA_DIR / "portswigger_knowledge",
        PROJECT_ROOT / "logs",
    ]
    created = 0
    for d in dirs:
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)
            created += 1

    if created:
        log_ok(f"Created {created} data directories")
    else:
        log_ok("Data directories exist")

def setup_tailwind():
    """Install Node dependencies and build Tailwind CSS."""
    log("Checking Tailwind CSS build...")

    # If pre-built CSS exists and is recent, skip
    if TAILWIND_CSS.exists() and TAILWIND_CSS.stat().st_size > 1000:
        log_ok(f"tailwind-built.css exists ({TAILWIND_CSS.stat().st_size:,} bytes)")
        return

    # Check if npm is available
    if not command_exists("npm"):
        log_warn("npm not found -- skipping Tailwind CSS build")
        log_warn("The app will still work but may have missing styles.")
        log_warn("Install Node.js from: https://nodejs.org/")
        return

    # Install node modules if needed
    if not NODE_MODULES.exists():
        log("Installing Node.js dependencies...")
        result = run("npm install", check=False)
        if result is None or result.returncode != 0:
            log_warn("npm install failed -- skipping Tailwind build")
            return
        log_ok("Node.js dependencies installed")

    # Build Tailwind
    log("Building Tailwind CSS...")
    result = run("npm run build:css", check=False)
    if result and result.returncode == 0 and TAILWIND_CSS.exists():
        log_ok(f"Tailwind CSS built ({TAILWIND_CSS.stat().st_size:,} bytes)")
    else:
        log_warn("Tailwind CSS build failed -- styles may be incomplete")

def mark_setup_complete():
    """Write a marker file so we know setup is done."""
    SETUP_MARKER.write_text(
        f"Setup completed at: {__import__('datetime').datetime.now().isoformat()}\n"
        f"Python: {sys.version}\n"
        f"Platform: {platform.platform()}\n",
        encoding="utf-8"
    )

def is_setup_complete():
    """Check if setup has been completed before."""
    if not SETUP_MARKER.exists():
        return False
    # Also verify critical files still exist
    venv_python = get_venv_python()
    return (
        os.path.isfile(venv_python)
        and ENV_FILE.exists()
        and REQUIREMENTS.exists()
    )


# ── Main Workflow ────────────────────────────────────────────────────────

def do_setup(force=False):
    """Run the full setup process."""
    if is_setup_complete() and not force:
        log_ok("Setup already complete -- skipping (use --setup to force)")
        return True

    log_header("SUDARSHAN - Project Setup")

    check_python_version()
    setup_venv()
    install_python_deps()
    setup_env_file()
    generate_secret_key()
    create_data_dirs()
    setup_tailwind()
    mark_setup_complete()

    print(f"\n  {GREEN}{BOLD}[OK] Setup complete!{RESET}\n")
    return True

def do_run():
    """Run the Flask development server."""
    log_header("SUDARSHAN - Starting Server")

    venv_python = get_venv_python()
    if not os.path.isfile(venv_python):
        log_err("Virtual environment not found. Run: python start.py --setup")
        sys.exit(1)

    # Check if .env has real Supabase creds
    if ENV_FILE.exists():
        content = ENV_FILE.read_text(encoding="utf-8")
        if "your-supabase-anon-key" in content:
            log_warn("Supabase credentials not configured -- auth pages won't work")
            log_warn("Edit .env to fix. Starting server anyway...\n")

    run_py = PROJECT_ROOT / "run.py"
    if not run_py.exists():
        log_err("run.py not found in project root!")
        sys.exit(1)

    log(f"Starting Flask server...")
    print()

    # On Windows, os.execv doesn't work reliably (leaves orphans).
    # Use subprocess.run instead for proper Ctrl+C handling.
    if IS_WINDOWS:
        try:
            subprocess.run([venv_python, str(run_py)])
        except KeyboardInterrupt:
            print(f"\n  {YELLOW}Server stopped.{RESET}")
    else:
        # On Unix, replace the current process for clean signal handling
        try:
            os.execv(venv_python, [venv_python, str(run_py)])
        except Exception:
            try:
                subprocess.run([venv_python, str(run_py)])
            except KeyboardInterrupt:
                print(f"\n  {YELLOW}Server stopped.{RESET}")

def do_check():
    """Print setup status without running."""
    log_header("SUDARSHAN - Setup Status")

    # Python
    major, minor = sys.version_info[:2]
    log_ok(f"Python: {major}.{minor}.{sys.version_info[2]}") if major >= 3 and minor >= 10 else log_err(f"Python: {major}.{minor} (need 3.10+)")

    # Venv
    venv_python = get_venv_python()
    log_ok(f".venv/: exists") if os.path.isfile(venv_python) else log_err(".venv/: missing")

    # Flask
    if os.path.isfile(venv_python):
        result = run(f'"{venv_python}" -c "import flask"', capture=True, check=False)
        log_ok("Dependencies: installed") if result and result.returncode == 0 else log_err("Dependencies: not installed")

    # .env
    if ENV_FILE.exists():
        content = ENV_FILE.read_text(encoding="utf-8")
        has_placeholders = (
            "your-supabase-anon-key" in content
            or "your-project.supabase.co" in content
        )
        if has_placeholders:
            log_warn(".env: exists but has PLACEHOLDER Supabase credentials")
        else:
            log_ok(".env: configured (Supabase pre-configured)")
            if PRECONFIGURED_SUPABASE["SUPABASE_URL"] in content:
                log_ok(f"  Supabase: {PRECONFIGURED_SUPABASE['SUPABASE_URL']}")
    else:
        log_warn(".env: missing (will be auto-created on setup)")

    # Tailwind
    if TAILWIND_CSS.exists() and TAILWIND_CSS.stat().st_size > 1000:
        log_ok(f"Tailwind CSS: built ({TAILWIND_CSS.stat().st_size:,} bytes)")
    else:
        log_warn("Tailwind CSS: not built")

    # Node
    log_ok("npm: available") if command_exists("npm") else log_warn("npm: not found (optional)")

    # Data dirs
    if (DATA_DIR / "portswigger_knowledge").exists() and any((DATA_DIR / "portswigger_knowledge").glob("*.json")):
        log_ok("Knowledge base: present")
    else:
        log_warn("Knowledge base: missing (data/portswigger_knowledge/)")

    if (DATA_DIR / "ml_models").exists() and any((DATA_DIR / "ml_models").glob("*.joblib")):
        log_ok("ML models: present")
    else:
        log_warn("ML models: missing (data/ml_models/)")

    # Database
    db_file = DATA_DIR / "database.db"
    if db_file.exists():
        log_ok(f"SQLite database: {db_file.stat().st_size / 1024 / 1024:.1f} MB")
    else:
        log_ok("SQLite database: will be created on first run")

    # Overall
    print()
    if is_setup_complete():
        log_ok(f"{BOLD}Ready to run!{RESET} Use: python start.py")
    else:
        log_warn(f"{BOLD}Setup needed.{RESET} Use: python start.py --setup")
    print()


def main():
    args = sys.argv[1:]

    if "--help" in args or "-h" in args:
        print(__doc__)
        sys.exit(0)

    if "--check" in args:
        do_check()
        sys.exit(0)

    if "--setup" in args:
        do_setup(force=True)
        if "--run" not in args:
            sys.exit(0)

    if "--run" in args:
        do_run()
        sys.exit(0)

    # Default: setup if needed, then run
    do_setup(force=False)
    do_run()


if __name__ == "__main__":
    main()
