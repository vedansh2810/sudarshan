#!/usr/bin/env python3
"""
Sudarshan - One-Click Setup & Run Script
=========================================

Usage:
    python start.py              # Setup (if needed) + Run
    python start.py --setup      # Force re-run setup even if already done
    python start.py --run        # Skip setup, just run
    python start.py --check      # Check setup status without running
    python start.py --setup-guide  # Show Supabase setup instructions

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
    """Copy .env.example to .env if .env doesn't exist."""
    log("Checking .env file...")

    if ENV_FILE.exists():
        # Check if it still has placeholder values
        content = ENV_FILE.read_text(encoding="utf-8")
        if "your-supabase-anon-key" in content or "your-project.supabase.co" in content:
            log_warn(".env exists but has PLACEHOLDER values -- login/register won't work!")
            log_warn("Edit .env and fill in your Supabase credentials.")
            log_warn("Run 'python start.py --setup-guide' for step-by-step instructions.")
        else:
            log_ok(".env configured")
        return

    if ENV_EXAMPLE.exists():
        shutil.copy2(ENV_EXAMPLE, ENV_FILE)
        log_ok(".env created from .env.example")
        print()
        _print_supabase_guide()
    else:
        log_warn(".env.example not found -- creating minimal .env")
        ENV_FILE.write_text(
            '# Generated by start.py -- fill in your values\n'
            'SECRET_KEY=change-me\n'
            'FLASK_ENV=development\n'
            'FLASK_DEBUG=1\n'
            'PORT=5000\n',
            encoding="utf-8"
        )

def _print_supabase_guide():
    """Print step-by-step Supabase setup guide to the terminal."""
    print(f"  {YELLOW}{BOLD}+{'=' * 62}+{RESET}")
    print(f"  {YELLOW}{BOLD}|  SUPABASE SETUP GUIDE (required for login/register)          |{RESET}")
    print(f"  {YELLOW}{BOLD}+{'=' * 62}+{RESET}")
    print()
    print(f"  {CYAN}Step 1: Create a free Supabase project{RESET}")
    print(f"    1. Go to https://supabase.com and click 'Start your project'")
    print(f"    2. Sign in with GitHub")
    print(f"    3. Click 'New Project'")
    print(f"    4. Set project name (e.g. 'sudarshan'), pick a region, click Create")
    print(f"    5. Wait ~2 minutes for it to provision")
    print()
    print(f"  {CYAN}Step 2: Copy your API credentials into .env{RESET}")
    print(f"    1. In Supabase dashboard: Settings (gear icon) -> API")
    print(f"    2. Copy these 3 values into your .env file:")
    print()
    print(f"       {GREEN}Project URL{RESET}                          -> SUPABASE_URL")
    print(f"       {GREEN}anon public key{RESET}                      -> SUPABASE_ANON_KEY")
    print(f"       {GREEN}service_role secret{RESET} (click 'Reveal') -> SUPABASE_SERVICE_KEY")
    print()
    print(f"  {CYAN}Step 3: Configure redirect URL{RESET}")
    print(f"    1. In Supabase: Authentication -> URL Configuration")
    print(f"    2. Under 'Redirect URLs', click 'Add URL'")
    print(f"    3. Add: {GREEN}http://localhost:5000/auth/callback-handler{RESET}")
    print(f"    4. Click Save")
    print()
    print(f"  {CYAN}Step 4: Enable email auth{RESET}")
    print(f"    - Email is enabled by default (no action needed)")
    print(f"    - (Optional) Turn OFF 'Confirm email' for faster testing:")
    print(f"      Authentication -> Providers -> Email -> Confirm email = OFF")
    print()
    print(f"  {YELLOW}+{'=' * 62}+{RESET}")
    print(f"  {YELLOW}|  SECURITY: Never share SUPABASE_SERVICE_KEY with anyone.     |{RESET}")
    print(f"  {YELLOW}|  Each tester should create their own Supabase project.       |{RESET}")
    print(f"  {YELLOW}+{'=' * 62}+{RESET}")
    print()

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
        if "your-supabase-anon-key" in content:
            log_warn(".env: exists but has PLACEHOLDER Supabase credentials")
        else:
            log_ok(".env: configured")
    else:
        log_err(".env: missing")

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

    if "--setup-guide" in args:
        _print_supabase_guide()
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
