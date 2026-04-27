#!/bin/bash
# ============================================================
# Sudarshan — Deployment / Update Script
# ============================================================
# Run this every time you push updates:
#   ./deploy/deploy.sh
# ============================================================

set -euo pipefail

echo "══════════════════════════════════════════════════════════"
echo "  🚀 Sudarshan — Deploying Update"
echo "══════════════════════════════════════════════════════════"

# ── Pull latest code ────────────────────────────────────────
echo "[1/4] Pulling latest code..."
git pull origin main

# ── Rebuild containers ──────────────────────────────────────
echo "[2/4] Rebuilding containers..."
docker compose -f docker-compose.prod.yml build --no-cache web worker

# ── Restart services (zero-ish downtime) ────────────────────
echo "[3/4] Restarting services..."
docker compose -f docker-compose.prod.yml up -d web worker

# ── Cleanup ─────────────────────────────────────────────────
echo "[4/4] Cleaning up old images..."
docker image prune -f

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  ✅ Deployment complete!"
echo ""
echo "  Check status:  docker compose -f docker-compose.prod.yml ps"
echo "  View logs:     docker compose -f docker-compose.prod.yml logs -f"
echo "══════════════════════════════════════════════════════════"
