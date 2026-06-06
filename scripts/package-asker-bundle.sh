#!/usr/bin/env bash
# Zip public asker files for a second human (no secrets).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/scripts/render-join-pack.sh"
OUT="$ROOT/dist/asker-bundle"
rm -rf "$OUT"
mkdir -p "$OUT"
cp "$ROOT/config/join-pack.json" "$OUT/"
cp "$ROOT/config/live-mailbox-client.json" "$OUT/"
mkdir -p "$OUT/bin"
if [[ -n "${TENET_BINARY:-}" && -x "${TENET_BINARY}" ]]; then
  cp "${TENET_BINARY}" "$OUT/bin/$(basename "${TENET_BINARY}")"
elif [[ -n "${POR_BINARY:-}" && -x "${POR_BINARY}" ]]; then
  cp "${POR_BINARY}" "$OUT/bin/$(basename "${POR_BINARY}")"
fi
for candidate in "$ROOT"/dist/tenet "$ROOT"/dist/tenet-*; do
  if [[ -x "$candidate" && ! -d "$candidate" ]]; then
    cp "$candidate" "$OUT/bin/$(basename "$candidate")"
  fi
done
cat > "$OUT/ask" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
system="$(uname -s | tr '[:upper:]' '[:lower:]')"
machine="$(uname -m | tr '[:upper:]' '[:lower:]')"
case "$system" in
  darwin) system="macos" ;;
  mingw*|msys*|cygwin*) system="windows" ;;
esac
case "$machine" in
  aarch64|arm64) machine="arm64" ;;
  x86_64|amd64) machine="x86_64" ;;
esac
candidate="$DIR/bin/tenet-${system}-${machine}"
[[ "$system" == "windows" ]] && candidate="${candidate}.exe"
if [[ -x "$candidate" ]]; then
  exec "$candidate" ask --join-pack "$DIR/join-pack.json" "$@"
fi
legacy="$DIR/bin/por-${system}-${machine}"
[[ "$system" == "windows" ]] && legacy="${legacy}.exe"
if [[ -x "$legacy" ]]; then
  exec "$legacy" ask --join-pack "$DIR/join-pack.json" "$@"
fi
if [[ -x "$DIR/bin/tenet" ]]; then
  exec "$DIR/bin/tenet" ask --join-pack "$DIR/join-pack.json" "$@"
fi
if [[ -x "$DIR/bin/por" ]]; then
  exec "$DIR/bin/por" ask --join-pack "$DIR/join-pack.json" "$@"
fi
exec python3 -m tenet ask --join-pack "$DIR/join-pack.json" "$@"
SH
chmod +x "$OUT/ask"
(
  cd "$ROOT/dist"
  rm -f asker-bundle.zip
  zip -r asker-bundle.zip asker-bundle
)
echo "[asker-bundle] dist/asker-bundle.zip"
echo "Ask: asker-bundle/ask --prompt '...'"
