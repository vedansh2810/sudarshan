#!/usr/bin/env python3
"""Sudarshan Web Vulnerability Scanner - Entry Point

Usage:  python run.py
"""
import os
import sys
import subprocess

# ── Auto-activate venv ────────────────────────────────────────────────────
# If we're NOT already inside the project venv, re-launch with the venv Python.
_project_dir = os.path.dirname(os.path.abspath(__file__))

# Detect venv Python (Windows or Linux/macOS)
_venv_python = os.path.join(_project_dir, 'venv', 'Scripts', 'python.exe')
if not os.path.exists(_venv_python):
    _venv_python = os.path.join(_project_dir, 'venv', 'bin', 'python')

if os.path.exists(_venv_python) and os.path.abspath(sys.executable) != os.path.abspath(_venv_python):
    # Re-run this script with the venv Python
    sys.exit(subprocess.call([_venv_python] + sys.argv))

# ── Normal startup (running inside venv) ──────────────────────────────────
from app import create_app

app = create_app()

if __name__ == '__main__':
    is_dev = os.environ.get('FLASK_ENV', 'production') == 'development'
    port = int(os.environ.get('PORT', 5000))
    print(f"\n  Sudarshan Web Vulnerability Scanner")
    print(f"  http://localhost:{port}\n")
    app.run(host='0.0.0.0', port=port, debug=is_dev, threaded=True)
