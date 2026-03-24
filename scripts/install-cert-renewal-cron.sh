#!/bin/sh
#
# install-cert-renewal-cron.sh — install a weekly cron job to pull
# Let's Encrypt certs from the cert server (192.168.1.113)
#
# Run this ONCE on the game server to set up automatic cert renewal.
# Certs are pulled every Sunday at 03:00 and the wol service is restarted
# to pick them up immediately.
#
# Usage (run from the repo root):
#   scripts/install-cert-renewal-cron.sh
#
# Requirements:
#   - SSH key-based auth must be set up between this machine and the cert
#     server.  Set it up with:  ssh-copy-id root@192.168.1.113
#
# To verify the cron job was installed:
#   crontab -l
#
# To remove the cron job:
#   crontab -l | grep -v copy-letsencrypt-certs | crontab -

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COPY_SCRIPT="$SCRIPT_DIR/copy-letsencrypt-certs.sh"

if [ ! -x "$COPY_SCRIPT" ]; then
    echo "install-cert-renewal-cron: $COPY_SCRIPT not found or not executable" >&2
    exit 1
fi

CRON_LINE="0 3 * * 0  $COPY_SCRIPT >> /tmp/copy-letsencrypt-certs.log 2>&1"

if crontab -l 2>/dev/null | grep -qF "copy-letsencrypt-certs"; then
    echo "install-cert-renewal-cron: cron job already installed — nothing to do"
    crontab -l | grep "copy-letsencrypt-certs"
    exit 0
fi

( crontab -l 2>/dev/null; echo "$CRON_LINE" ) | crontab -

echo "install-cert-renewal-cron: cron job installed"
echo "  schedule: every Sunday at 03:00"
echo "  command:  $COPY_SCRIPT"
echo "  log:      /tmp/copy-letsencrypt-certs.log"
echo ""
echo "Run 'crontab -l' to verify."
