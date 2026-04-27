#!/bin/bash
# ============================================================
# Sudarshan — Oracle Cloud VM Initial Setup Script
# ============================================================
# Run this ONCE on a fresh Ubuntu 22.04/24.04 VM:
#   chmod +x deploy/setup-server.sh
#   sudo ./deploy/setup-server.sh
# ============================================================

set -euo pipefail

echo "══════════════════════════════════════════════════════════"
echo "  🛡  Sudarshan — Server Setup"
echo "══════════════════════════════════════════════════════════"

# ── 1. System Update ────────────────────────────────────────
echo "[1/6] Updating system packages..."
apt-get update && apt-get upgrade -y

# ── 2. Install Docker ──────────────────────────────────────
echo "[2/6] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker ubuntu
    systemctl enable docker
    systemctl start docker
    echo "  ✓ Docker installed"
else
    echo "  ✓ Docker already installed"
fi

# ── 3. Install Docker Compose Plugin ────────────────────────
echo "[3/6] Installing Docker Compose..."
if ! docker compose version &> /dev/null; then
    apt-get install -y docker-compose-plugin
    echo "  ✓ Docker Compose installed"
else
    echo "  ✓ Docker Compose already installed"
fi

# ── 4. Configure Firewall (iptables) ───────────────────────
echo "[4/6] Configuring firewall..."
# Oracle Cloud uses iptables by default
iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
iptables -I INPUT 7 -m state --state NEW -p tcp --dport 443 -j ACCEPT
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4
echo "  ✓ Ports 80, 443 opened"

# ── 5. Create app directory ─────────────────────────────────
echo "[5/6] Setting up application directory..."
APP_DIR="/opt/sudarshan"
mkdir -p "$APP_DIR"
echo "  ✓ App directory: $APP_DIR"

# ── 6. Install useful tools ────────────────────────────────
echo "[6/6] Installing utilities..."
apt-get install -y \
    curl \
    git \
    htop \
    nano \
    fail2ban \
    unattended-upgrades

# Enable automatic security updates
dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true

# Enable fail2ban
systemctl enable fail2ban
systemctl start fail2ban

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  ✅ Server setup complete!"
echo ""
echo "  Next steps:"
echo "    1. Log out and back in (for docker group)"
echo "    2. Clone your repo:"
echo "       cd /opt/sudarshan"
echo "       git clone https://github.com/YOUR_USER/sudarshan.git ."
echo "    3. Configure environment:"
echo "       cp .env.production .env"
echo "       nano .env"
echo "    4. Start with HTTP first:"
echo "       cp deploy/nginx/nginx-nossl.conf deploy/nginx/nginx.conf.bak"
echo "       cp deploy/nginx/nginx-nossl.conf deploy/nginx/nginx.conf"
echo "       docker compose -f docker-compose.prod.yml up -d --build"
echo "    5. Then run SSL setup:"
echo "       sudo ./deploy/setup-ssl.sh your-domain.com your@email.com"
echo "══════════════════════════════════════════════════════════"
