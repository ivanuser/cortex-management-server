#!/bin/bash
# CortexOS Management Server — Install Script
set -e

INSTALL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_NAME="cortex-management"

echo "╔═══════════════════════════════════════════════╗"
echo "║    CortexOS Management Server Installer        ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# ─── Check Node.js ───────────────────
if ! command -v node &>/dev/null; then
  echo "📦 Installing Node.js..."
  if command -v apt-get &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y nodejs
  elif command -v dnf &>/dev/null; then
    curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo bash -
    sudo dnf install -y nodejs
  else
    echo "❌ Cannot auto-install Node.js. Install it manually and re-run."
    exit 1
  fi
fi

NODE_VER=$(node -v)
echo "✅ Node.js ${NODE_VER}"

# ─── Install Dependencies ───────────
echo "📦 Installing dependencies..."
cd "$INSTALL_DIR"
npm install --production

# ─── Create Data Directory ───────────
mkdir -p "$INSTALL_DIR/data"

# ─── Systemd Service ────────────────
echo "🔧 Creating systemd service..."
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<EOF
[Unit]
Description=CortexOS Management Server
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(which node) src/server.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}
sudo systemctl start ${SERVICE_NAME}

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║  ✅ Installation Complete!                     ║"
echo "╠═══════════════════════════════════════════════╣"
echo "║  Dashboard: http://$(hostname -I | awk '{print $1}'):9443/dashboard/"
echo "║  Login:     admin / admin                     ║"
echo "║  Service:   sudo systemctl status ${SERVICE_NAME}"
echo "╚═══════════════════════════════════════════════╝"
echo ""
echo "⚠️  Change the default admin password after first login!"
