#!/bin/sh
#
# copy-letsencrypt-certs.sh — pull Let's Encrypt certs from the cert server
#
# Run this on the GAME SERVER to copy the current Let's Encrypt certificates
# from the cert server (192.168.1.113) into data/tls/.
#
# After copying, the wol service is restarted so it picks up the new cert
# immediately.
#
# Usage:
#   scripts/copy-letsencrypt-certs.sh [--domain <domain>] [--cert-server <host>]
#
# Defaults:
#   domain:      ackmud.com
#   cert-server: 192.168.1.113
#   dest:        <repo-root>/data/tls/
#
# Requirements:
#   - SSH key-based auth must be set up: root@192.168.1.113 must accept the
#     game server's SSH public key without a password prompt.
#   - Run as root (needed to restart the wol service).
#     Set up SSH auth with:  ssh-copy-id root@192.168.1.113

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEST_DIR="$REPO_ROOT/data/tls"

DOMAIN="ackmud.com"
CERT_SERVER="192.168.1.113"
CERT_SERVER_USER="root"

while [ $# -gt 0 ]; do
    case "$1" in
        --domain)      DOMAIN="$2";      shift 2 ;;
        --cert-server) CERT_SERVER="$2"; shift 2 ;;
        *) echo "copy-letsencrypt-certs.sh: unknown argument: $1" >&2; exit 1 ;;
    esac
done

REMOTE_DIR="/etc/letsencrypt/live/$DOMAIN"
REMOTE="$CERT_SERVER_USER@$CERT_SERVER"

echo "copy-letsencrypt-certs: copying $DOMAIN certs from $CERT_SERVER..."

mkdir -p "$DEST_DIR"

scp "$REMOTE:$REMOTE_DIR/fullchain.pem" "$DEST_DIR/server.crt"
scp "$REMOTE:$REMOTE_DIR/privkey.pem"   "$DEST_DIR/server.key"
chmod 600 "$DEST_DIR/server.key"

echo "copy-letsencrypt-certs: cert -> $DEST_DIR/server.crt"
echo "copy-letsencrypt-certs: key  -> $DEST_DIR/server.key"

# Restart the service to pick up the new cert immediately
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wol 2>/dev/null; then
    systemctl restart wol
    echo "copy-letsencrypt-certs: wol service restarted"
else
    echo "copy-letsencrypt-certs: done (start/restart wol to apply the new cert)"
fi
