#!/bin/bash
# WOL game server setup.
# Installs all dependencies, generates TLS cert, builds the server,
# and installs/enables a systemd service for boot startup.
# Idempotent — safe to re-run.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOTNET_INSTALL_DIR="/usr/local/dotnet"
DOTNET="$DOTNET_INSTALL_DIR/dotnet"
DOTNET_CHANNEL="9.0"
TLS_DIR="$SCRIPT_DIR/data/tls"
TLS_CERT="$TLS_DIR/server.crt"
TLS_KEY="$TLS_DIR/server.key"
SERVICE_NAME="wol"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
BINARY="$SCRIPT_DIR/Wol.Server/bin/Release/net9.0/Wol.Server.dll"

# -------------------------------------------------------------------------
# 1. System dependencies
# -------------------------------------------------------------------------
echo "==> Checking system dependencies..."
MISSING=()
for pkg in openssl curl; do
  command -v "$pkg" >/dev/null 2>&1 || MISSING+=("$pkg")
done

if [ ${#MISSING[@]} -gt 0 ]; then
  echo "   Installing: ${MISSING[*]}"
  apt-get install -y -qq "${MISSING[@]}" 2>&1 | tail -1
fi
echo "   System dependencies OK."

# -------------------------------------------------------------------------
# 2. .NET SDK
# -------------------------------------------------------------------------
echo "==> Checking .NET SDK..."

need_dotnet=false
if [ ! -x "$DOTNET" ]; then
  need_dotnet=true
else
  installed_ver="$("$DOTNET" --version 2>/dev/null || true)"
  if [[ "$installed_ver" != 9.* ]]; then
    echo "   Found .NET $installed_ver — need 9.x."
    need_dotnet=true
  fi
fi

if $need_dotnet; then
  echo "   Installing .NET SDK $DOTNET_CHANNEL via dotnet-install.sh..."
  INSTALLER="$(mktemp)"
  curl -sSL https://dot.net/v1/dotnet-install.sh -o "$INSTALLER"
  chmod +x "$INSTALLER"
  "$INSTALLER" --channel "$DOTNET_CHANNEL" --install-dir "$DOTNET_INSTALL_DIR"
  rm "$INSTALLER"
fi

echo "   .NET SDK $("$DOTNET" --version) at $DOTNET_INSTALL_DIR"

# -------------------------------------------------------------------------
# 3. TLS certificate
# -------------------------------------------------------------------------
echo "==> Checking TLS certificate..."

generate_self_signed() {
  echo "   Generating self-signed TLS certificate (10-year validity)..."
  echo "   (Replace $TLS_CERT / $TLS_KEY with a CA-signed cert for production.)"
  mkdir -p "$TLS_DIR"
  openssl req -x509 -newkey rsa:4096 \
    -keyout "$TLS_KEY" \
    -out "$TLS_CERT" \
    -days 3650 \
    -nodes \
    -subj "/CN=localhost/O=WOL/C=US" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    2>/dev/null
  chmod 600 "$TLS_KEY"
  echo "   Self-signed certificate written to $TLS_CERT"
}

cert_ok() {
  [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ] || return 1
  openssl x509 -in "$TLS_CERT" -noout -checkend 2592000 >/dev/null 2>&1 || return 1
  cert_pub="$(openssl x509 -in "$TLS_CERT" -noout -pubkey 2>/dev/null | md5sum)"
  key_pub="$(openssl pkey -in "$TLS_KEY" -pubout 2>/dev/null | md5sum)"
  [ "$cert_pub" = "$key_pub" ]
}

# Try to fetch Let's Encrypt cert from the cert server first.
# Falls back to self-signed if SSH auth isn't set up or the copy fails.
COPY_SCRIPT="$SCRIPT_DIR/scripts/copy-letsencrypt-certs.sh"
if [ -x "$COPY_SCRIPT" ] && \
   ssh -o BatchMode=yes -o ConnectTimeout=5 root@192.168.1.113 true 2>/dev/null; then
  echo "   Fetching Let's Encrypt certificate from cert server..."
  "$COPY_SCRIPT" || echo "   WARNING: cert copy failed — will fall back to self-signed."
fi

if cert_ok; then
  echo "   TLS certificate OK ($(openssl x509 -in "$TLS_CERT" -noout -enddate 2>/dev/null | cut -d= -f2))"
else
  [ -f "$TLS_CERT" ] && echo "   Certificate missing or invalid — regenerating..."
  generate_self_signed
fi

# Install weekly cron job to refresh the cert from the cert server.
RENEWAL_SCRIPT="$SCRIPT_DIR/scripts/install-cert-renewal-cron.sh"
if [ -x "$RENEWAL_SCRIPT" ]; then
  "$RENEWAL_SCRIPT"
fi

# -------------------------------------------------------------------------
# 4. Restore NuGet packages
# -------------------------------------------------------------------------
echo "==> Restoring NuGet packages..."
"$DOTNET" restore "$SCRIPT_DIR/Wol.sln" -v quiet
echo "   Packages restored."

# -------------------------------------------------------------------------
# 5. Build (Release)
# -------------------------------------------------------------------------
echo "==> Building Wol.Server (Release)..."
"$DOTNET" build "$SCRIPT_DIR/Wol.sln" \
  --configuration Release \
  --no-restore \
  -v quiet
echo "   Build succeeded."

# -------------------------------------------------------------------------
# 6. Systemd service
# -------------------------------------------------------------------------
if ! command -v systemctl >/dev/null 2>&1; then
  echo "==> Skipping systemd setup (systemctl not found)."
else
  echo "==> Installing systemd service..."

  # Determine the user to run the service as.
  # If run as root, prefer the owner of the repo directory; fall back to root.
  if [ "$(id -u)" -eq 0 ]; then
    REPO_OWNER="$(stat -c '%U' "$SCRIPT_DIR")"
    RUN_AS="${REPO_OWNER:-root}"
  else
    RUN_AS="$(id -un)"
  fi

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=WOL MUD Game Server
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=$RUN_AS
WorkingDirectory=$SCRIPT_DIR
ExecStart=$DOTNET $BINARY
Restart=on-failure
RestartSec=5
# Make the .NET runtime discoverable without relying on PATH
Environment=DOTNET_ROOT=$DOTNET_INSTALL_DIR
Environment=PATH=$DOTNET_INSTALL_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Log to journald; view with: journalctl -u wol -f
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wol

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"

  if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "   Restarting $SERVICE_NAME..."
    systemctl restart "$SERVICE_NAME"
  else
    echo "   Starting $SERVICE_NAME..."
    systemctl start "$SERVICE_NAME"
  fi

  systemctl is-active --quiet "$SERVICE_NAME" && \
    echo "   Service is running." || \
    echo "   WARNING: service failed to start — check: journalctl -u $SERVICE_NAME -n 50"
fi

# -------------------------------------------------------------------------
# Done
# -------------------------------------------------------------------------
echo ""
echo "==> Setup complete."
echo ""
echo "   Service management:"
echo "     systemctl status $SERVICE_NAME"
echo "     systemctl restart $SERVICE_NAME"
echo "     journalctl -u $SERVICE_NAME -f"
echo ""
echo "   Listening on port 6969 (plain telnet, TLS telnet, ws://, wss://)."
echo "   TLS cert: $TLS_CERT"
