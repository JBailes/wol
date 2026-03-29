#!/bin/bash
set -euo pipefail
export PATH="/usr/local/dotnet:$PATH"
TARGET="deploy@10.0.0.208"
SSH="ssh -o StrictHostKeyChecking=no"
dotnet publish Wol.Server/Wol.Server.csproj -c Release -o /tmp/wol-publish
rsync -a --delete --no-group -e "$SSH" /tmp/wol-publish/ "$TARGET":/usr/lib/wol/app/
rm -rf /tmp/wol-publish
$SSH "$TARGET" "sudo systemctl restart wol"
echo "Deployed to wol-a"
