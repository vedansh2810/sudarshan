#!/usr/bin/env python3
"""Sudarshan Web Vulnerability Scanner — Entry Point

Usage:  python run.py
"""
import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'

    print(f"\n  🛡 Sudarshan Web Vulnerability Scanner")
    print(f"  →  http://localhost:{port}\n")

    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)
