#!/bin/bash
# Install ContextKeep V1.2 Services (Server + WebUI)

echo "=========================================="
echo "      ContextKeep V1.2 - Service Installer"
echo "=========================================="
echo ""

if [ -n "$SUDO_USER" ]; then
    if ! id "$SUDO_USER" >/dev/null 2>&1; then
        echo "[-] Error: SUDO_USER '$SUDO_USER' is not a valid user."
        exit 1
    fi
    CURRENT_USER="$SUDO_USER"
else
    CURRENT_USER=$(whoami)
fi

CURRENT_DIR=$(pwd)

echo "[*] Detected User: $CURRENT_USER"
echo "[*] Detected Directory: $CURRENT_DIR"
echo ""

mkdir -p "$CURRENT_DIR/logs"
chmod 700 "$CURRENT_DIR/logs"
chown -R "$CURRENT_USER" "$CURRENT_DIR/logs"

install_service() {
    TEMPLATE=$1
    SERVICE_NAME=$2

    echo "[*] Installing $SERVICE_NAME..."

    if [ ! -f "$TEMPLATE" ]; then
        echo "[-] Error: Template $TEMPLATE not found!"
        return
    fi

    TMPFILE=$(mktemp)
    sed -e "s|{{USER}}|$CURRENT_USER|g" \
        -e "s|{{WORKDIR}}|$CURRENT_DIR|g" \
        "$TEMPLATE" > "$TMPFILE"

    sudo mv "$TMPFILE" "/etc/systemd/system/$SERVICE_NAME"
    sudo systemctl enable "$SERVICE_NAME"
    sudo systemctl restart "$SERVICE_NAME"

    echo "[+] $SERVICE_NAME installed and started."
}

install_service "contextkeep-server.service" "contextkeep-server.service"
install_service "contextkeep-webui.service" "contextkeep-webui.service"

sudo systemctl daemon-reload

echo ""
echo "=========================================="
echo "      Installation Complete!"
echo "=========================================="
echo "WebUI: http://localhost:5000"
echo "MCP Server (SSE): http://localhost:5100/sse"
echo ""
