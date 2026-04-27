#!/bin/bash
# ============================================================
# Sudarshan — Let's Encrypt SSL Setup
# ============================================================
# Usage:
#   sudo ./deploy/setup-ssl.sh yourdomain.com your@email.com
#
# Prerequisites:
#   - Domain pointing to this server's IP
#   - docker-compose.prod.yml already running with nginx-nossl.conf
# ============================================================

set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain> <email>}"
EMAIL="${2:?Usage: $0 <domain> <email>}"

echo "══════════════════════════════════════════════════════════"
echo "  🔐 Setting up SSL for: $DOMAIN"
echo "══════════════════════════════════════════════════════════"

# ── Step 1: Obtain certificate ──────────────────────────────
echo "[1/3] Obtaining Let's Encrypt certificate..."
docker compose -f docker-compose.prod.yml run --rm certbot \
    certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    -d "$DOMAIN"

# ── Step 2: Update Nginx config for SSL ─────────────────────
echo "[2/3] Switching Nginx to SSL config..."

# Update the server_name in the SSL config
sed -i "s/server_name _;/server_name $DOMAIN;/g" deploy/nginx/nginx.conf

# Backup the no-ssl config and copy SSL config
cp deploy/nginx/nginx.conf deploy/nginx/nginx.conf.ssl

# Update certbot cert path to match domain
sed -i "s|/etc/letsencrypt/live/sudarshan/|/etc/letsencrypt/live/$DOMAIN/|g" deploy/nginx/nginx.conf

# ── Step 3: Reload Nginx ────────────────────────────────────
echo "[3/3] Reloading Nginx..."
docker compose -f docker-compose.prod.yml restart nginx

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  ✅ SSL setup complete!"
echo ""
echo "  Your app is now live at: https://$DOMAIN"
echo ""
echo "  SSL auto-renewal is handled by the certbot container."
echo "══════════════════════════════════════════════════════════"
