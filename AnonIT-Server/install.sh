#!/bin/bash
# AnonIT Server Installation Script for Linux

set -e

echo "=== AnonIT Server Installation ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./install.sh)"
    exit 1
fi

# Create user
if ! id "anonit" &>/dev/null; then
    useradd -r -s /bin/false anonit
    echo "Created anonit user"
fi

# Create directories
mkdir -p /opt/anonit-server/data
cp -r ./* /opt/anonit-server/
chown -R anonit:anonit /opt/anonit-server

# Setup Python venv
cd /opt/anonit-server
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# Install systemd service
cp systemd/anonit.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable anonit
systemctl start anonit

echo ""
echo "=== Installation Complete ==="
echo "Server running on port 8765"
echo ""
echo "Commands:"
echo "  systemctl status anonit   - Check status"
echo "  systemctl restart anonit  - Restart server"
echo "  journalctl -u anonit -f   - View logs"
