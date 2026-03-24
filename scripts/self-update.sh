#!/bin/bash
# CortexOS Management Server Self-Update
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
echo "🔄 Updating CortexOS Management Server at $INSTALL_DIR..."

cd "$INSTALL_DIR"

# Determine who owns the files (run git as that user)
OWNER=$(stat -c '%U' "$INSTALL_DIR" 2>/dev/null || echo "root")

# Pull latest from GitHub
if [ -d ".git" ]; then
    if [ "$OWNER" != "root" ] && [ "$(id -u)" = "0" ]; then
        su - "$OWNER" -c "cd $INSTALL_DIR && git pull origin main" 2>&1 || {
            echo "⚠️ git pull as $OWNER failed, trying download..."
            curl -sfL "https://github.com/ivanuser/cortex-management-server/archive/main.tar.gz" -o /tmp/mgmt-update.tar.gz
            tar xzf /tmp/mgmt-update.tar.gz --strip-components=1 -C "$INSTALL_DIR"
            rm -f /tmp/mgmt-update.tar.gz
        }
    else
        git pull origin main 2>&1 || {
            echo "⚠️ git pull failed, trying download..."
            curl -sfL "https://github.com/ivanuser/cortex-management-server/archive/main.tar.gz" -o /tmp/mgmt-update.tar.gz
            tar xzf /tmp/mgmt-update.tar.gz --strip-components=1 -C "$INSTALL_DIR"
            rm -f /tmp/mgmt-update.tar.gz
        }
    fi
    echo "✅ Code updated"
else
    echo "⚠️ Not a git repo — downloading..."
    curl -sfL "https://github.com/ivanuser/cortex-management-server/archive/main.tar.gz" -o /tmp/mgmt-update.tar.gz
    tar xzf /tmp/mgmt-update.tar.gz --strip-components=1 -C "$INSTALL_DIR"
    rm -f /tmp/mgmt-update.tar.gz
    echo "✅ Code downloaded"
fi

# Install dependencies
cd "$INSTALL_DIR"
npm install --production 2>&1 | tail -3
echo "✅ Dependencies updated"

# Restart service
systemctl restart cortex-management 2>/dev/null || true
echo "✅ Service restarted"
echo "🎉 Management Server updated!"
