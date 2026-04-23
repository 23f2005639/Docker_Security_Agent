#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=============================================="
echo " Container Sentinel - Production Setup"
echo "=============================================="
echo ""

# 0. Add swap if none exists (prevents OOM freeze under DoS attack load)
if [ "$(swapon --show | wc -l)" -le 1 ]; then
    echo "[0/3] Creating 2GB swap file (prevents freeze under load)..."
    fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null
    swapon /swapfile
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
    echo "      Swap enabled."
else
    echo "[0/3] Swap already exists, skipping."
fi
echo ""

# 1. Generate self-signed SSL certificate
mkdir -p "$SCRIPT_DIR/ssl"
if [ ! -f "$SCRIPT_DIR/ssl/cert.pem" ]; then
    echo "[1/3] Generating self-signed SSL certificate..."
    openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
        -keyout "$SCRIPT_DIR/ssl/key.pem" \
        -out "$SCRIPT_DIR/ssl/cert.pem" \
        -subj "/CN=container-sentinel/O=BCA-Project" 2>/dev/null
    echo "      Done."
else
    echo "[1/3] SSL certificate already exists, skipping."
fi

# 2. Create basic auth credentials
if [ ! -f "$SCRIPT_DIR/.htpasswd" ]; then
    echo "[2/3] Setting up basic auth..."
    read -rp "      Username: " AUTH_USER
    AUTH_PASS=$(openssl rand -base64 12)
    echo ""
    echo "      Generated password: $AUTH_PASS"
    echo "      >>> Save this password! Share it with your mentor. <<<"
    echo ""
    echo "$AUTH_USER:$(openssl passwd -apr1 "$AUTH_PASS")" > "$SCRIPT_DIR/.htpasswd"
    echo "      Credentials saved to deploy/.htpasswd"
else
    echo "[2/3] .htpasswd already exists, skipping."
fi

# 3. Validate .env
if [ ! -f "$PROJECT_DIR/.env" ]; then
    echo "[3/3] ERROR: .env file not found!"
    echo "      Run: cp .env.example .env && nano .env"
    echo "      Then add your OPENAI_API_KEY"
    exit 1
elif ! grep -q "OPENAI_API_KEY=." "$PROJECT_DIR/.env"; then
    echo "[3/3] WARNING: OPENAI_API_KEY appears empty in .env"
    echo "      AI agents will not work without a valid key."
else
    echo "[3/3] .env file validated."
fi

echo ""
echo "=============================================="
echo " Setup complete! Deploy with:"
echo ""
echo "   docker compose -f docker-compose.prod.yml up -d --build"
echo ""
echo " Dashboard: https://<your-droplet-ip>"
echo "=============================================="
