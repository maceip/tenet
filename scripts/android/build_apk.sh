#!/usr/bin/env bash
# Build the tenet Android APK end-to-end: cross-compile the native wheels,
# build the pure-Python wheels, then package with Briefcase.
#
# Used both locally and in CI (.github/workflows/android-apk.yml). Requires:
#   - ANDROID_HOME with an installed NDK (ndk/<ver>) + platform + build-tools
#   - JAVA_HOME pointing at a JDK 17
#   - python3.13 on PATH (override with $PYTHON)
#
# Output: android/build/tenet/android/gradle/app/build/outputs/apk/debug/app-debug.apk
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/scripts/android"
WHEELS="$ROOT/dist/android-wheels"
PREFIX="${PREFIX:-/tmp/android-prefix}"
PY_TAG="${PY_TAG:-cp313}"
VENV="${VENV:-$ROOT/.venv-android-ci}"
: "${ANDROID_HOME:?ANDROID_HOME must point at an Android SDK with an NDK}"
rm -rf "$PREFIX"
mkdir -p "$WHEELS"

"${PYTHON:-python3.13}" -m venv "$VENV"
PIP="$VENV/bin/pip"; CW="$VENV/bin/cibuildwheel"; BF="$VENV/bin/briefcase"
"$PIP" install -q --upgrade pip cibuildwheel briefcase

export CIBW_PLATFORM=android CIBW_ARCHS=arm64_v8a CIBW_BUILD="${PY_TAG}-*"

_src() {  # download an sdist and echo its extracted dir
  local d; d="$(mktemp -d)"
  "$PIP" download "$1" --no-binary :all: --no-deps -d "$d" >/dev/null
  tar xzf "$d"/*.tar.gz -C "$d"
  find "$d" -maxdepth 1 -type d ! -path "$d" | head -1
}

echo "::group::wheel msgpack"
( cd "$(_src msgpack)" && "$CW" --platform android --output-dir "$WHEELS" )
echo "::endgroup::"

echo "::group::wheel cffi (+libffi)"
( cd "$(_src cffi)" && \
  CIBW_BEFORE_BUILD="bash $HERE/build_libffi.sh" \
  CIBW_ENVIRONMENT="CPATH=$PREFIX/include LIBRARY_PATH=$PREFIX/lib" \
  "$CW" --platform android --output-dir "$WHEELS" )
echo "::endgroup::"

echo "::group::wheel pynacl (+libsodium)"
( cd "$(_src pynacl)" && \
  CIBW_BEFORE_BUILD="bash $HERE/build_libsodium.sh" \
  CIBW_ENVIRONMENT="SODIUM_INSTALL=system CPATH=$PREFIX/include LIBRARY_PATH=$PREFIX/lib" \
  "$CW" --platform android --output-dir "$WHEELS" )
echo "::endgroup::"

echo "::group::pure-python wheels"
"$PIP" wheel pyaes dilithium-py --no-deps -w "$WHEELS"
echo "::endgroup::"

echo "::group::briefcase APK"
cd "$ROOT/android"
rm -rf build
"$BF" create android --no-input
# Restrict to the arm64-v8a wheels we built (Chaquopy otherwise also tries x86_64).
sed -i.bak 's/abiFilters "arm64-v8a", "x86_64"/abiFilters "arm64-v8a"/' \
  build/tenet/android/gradle/app/build.gradle
"$BF" build android --no-input
echo "::endgroup::"

APK="$(find "$ROOT/android/build" -name "app-debug.apk" | head -1)"
echo "APK: $APK"
test -f "$APK"
