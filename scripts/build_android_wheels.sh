#!/usr/bin/env bash
# Build the UDP-only Android (arm64-v8a, API 21, cp313) wheels for the tenet node.
#
# Status:
#   msgpack       OK  (cibuildwheel, pure C)
#   pycryptodome  OK  (cibuildwheel, pure C, abi3)
#   pqcrypto      OK  (cibuildwheel from github source @ 0.4.0 + PQClean submodule;
#                      the PyPI 0.4.0 is wheel-only, so build from source)
#   cffi          TODO needs libffi cross-compiled first (NDK has no libffi)
#   pynacl        TODO needs libsodium cross-compiled first (SODIUM_INSTALL=system)
#
# Requires: ANDROID_HOME (SDK + NDK), a venv with cibuildwheel installed.
# Output: $OUT (default /tmp/wheels-android).
set -euo pipefail

OUT="${OUT:-/tmp/wheels-android}"
CW="${CW:-cibuildwheel}"
PY="${PY:-cp313}"
export CIBW_PLATFORM=android
export CIBW_ARCHS=arm64_v8a
export CIBW_BUILD="${PY}-*"
mkdir -p "$OUT"

build_from_pypi_sdist() {  # $1 = pypi name
  local pkg="$1" src; src="$(mktemp -d)"
  pip download "$pkg" --no-binary :all: --no-deps -d "$src"
  tar xzf "$src"/*.tar.gz -C "$src"
  local d; d="$(find "$src" -maxdepth 1 -type d ! -path "$src" | head -1)"
  ( cd "$d" && "$CW" --platform android --output-dir "$OUT" )
}

build_pqcrypto_from_source() {  # 0.4.0 is wheel-only on PyPI; build from git
  local d; d="$(mktemp -d)/pqcrypto"
  git clone https://github.com/backbone-hq/pqcrypto "$d"
  ( cd "$d" && git submodule update --init --depth 1 pqclean \
      && "$CW" --platform android --output-dir "$OUT" )
}

HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${PREFIX:-/tmp/android-prefix}"   # libffi/libsodium install here

build_cffi() {            # needs libffi; build it inside cibuildwheel's toolchain
  local src; src="$(mktemp -d)"
  pip download cffi --no-binary :all: --no-deps -d "$src"
  tar xzf "$src"/*.tar.gz -C "$src"
  local d; d="$(find "$src" -maxdepth 1 -type d -name 'cffi*')"
  ( cd "$d" && \
    CIBW_BEFORE_BUILD="bash $HERE/android/build_libffi.sh" \
    CIBW_ENVIRONMENT="CPATH=$PREFIX/include LIBRARY_PATH=$PREFIX/lib" \
    "$CW" --platform android --output-dir "$OUT" )
}

build_pynacl() {          # needs libsodium; SODIUM_INSTALL=system links the prebuilt
  local src; src="$(mktemp -d)"
  pip download pynacl --no-binary :all: --no-deps -d "$src"
  tar xzf "$src"/*.tar.gz -C "$src"
  local d; d="$(find "$src" -maxdepth 1 -type d -iname 'pynacl*')"
  ( cd "$d" && \
    CIBW_BEFORE_BUILD="bash $HERE/android/build_libsodium.sh" \
    CIBW_ENVIRONMENT="SODIUM_INSTALL=system CPATH=$PREFIX/include LIBRARY_PATH=$PREFIX/lib" \
    "$CW" --platform android --output-dir "$OUT" )
}

build_from_pypi_sdist msgpack
build_from_pypi_sdist pycryptodome
build_pqcrypto_from_source
build_cffi
build_pynacl

# The cross-compile fix that unblocked cffi/pynacl: build the autotools C lib
# (libffi/libsodium) INSIDE cibuildwheel's android env with --host (skips the
# run-tests that fail under cross-compile), then expose it to the wheel build
# via CPATH + LIBRARY_PATH (clang reads these directly; setuptools LDFLAGS did
# not propagate to the extension link).

echo "Built wheels in $OUT:"
ls -1 "$OUT"
