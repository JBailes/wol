#!/bin/bash
# WOL game server setup.
# Installs all dependencies, generates TLS cert, and builds the server.
# Idempotent — safe to re-run.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOTNET_INSTALL_DIR="/usr/local/dotnet"
DOTNET="$DOTNET_INSTALL_DIR/dotnet"
DOTNET_CHANNEL="9.0"
TLS_DIR="$SCRIPT_DIR/data/tls"
TLS_CERT="$TLS_DIR/server.crt"
TLS_KEY="$TLS_DIR/server.key"

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
  # Require 9.x
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

generate_cert() {
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
  echo "   TLS certificate written to $TLS_CERT"
}

if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then
  generate_cert
elif ! openssl x509 -in "$TLS_CERT" -noout -checkend 2592000 >/dev/null 2>&1; then
  echo "   Certificate expires within 30 days — regenerating..."
  generate_cert
else
  # Verify cert and key share the same public key
  cert_pub="$(openssl x509 -in "$TLS_CERT" -noout -pubkey 2>/dev/null | md5sum)"
  key_pub="$(openssl pkey -in "$TLS_KEY" -pubout 2>/dev/null | md5sum)"
  if [ "$cert_pub" != "$key_pub" ]; then
    echo "   Certificate/key mismatch — regenerating..."
    generate_cert
  else
    echo "   TLS certificate OK ($(openssl x509 -in "$TLS_CERT" -noout -enddate 2>/dev/null | cut -d= -f2))"
  fi
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
# Done
# -------------------------------------------------------------------------
echo ""
echo "==> Setup complete."
echo ""
echo "   Start the server:"
echo "     $DOTNET run --project $SCRIPT_DIR/Wol.Server --configuration Release"
echo ""
echo "   Or run the built binary directly:"
echo "     $SCRIPT_DIR/Wol.Server/bin/Release/net9.0/Wol.Server"
echo ""
echo "   Listening on port 6969 (plain telnet, TLS telnet, ws://, wss://)."
echo "   TLS cert: $TLS_CERT"
