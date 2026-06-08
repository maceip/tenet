#!/usr/bin/env bash
# Copy official release binaries into tenet-www/public/downloads for site deploy.
#
# Usage:
#   ./scripts/sync-www-binaries.sh              # latest GitHub release
#   ./scripts/sync-www-binaries.sh v0.1.1       # specific tag
#   TENET_WWW=~/tenet-www ./scripts/sync-www-binaries.sh
#
# Requires: gh, curl
set -euo pipefail

TAG="${1:-}"
WWW="${TENET_WWW:-$HOME/tenet-www}"
DEST="$WWW/public/downloads"
BASE="https://github.com/maceip/tenet/releases"

if [[ -z "$TAG" ]]; then
  TAG="$(gh release view -R maceip/tenet --json tagName -q .tagName)"
fi

mkdir -p "$DEST"
for name in tenet-macos-arm64 tenet-linux-x86_64 tenet-windows-x86_64.exe; do
  url="$BASE/download/$TAG/$name"
  echo "[sync] $name <- $url"
  curl -fsSL -o "$DEST/$name" "$url"
  chmod +x "$DEST/$name" 2>/dev/null || true
done

echo "[sync] done -> $DEST"
ls -lh "$DEST"/tenet-*
