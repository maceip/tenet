set -e
PREFIX=/tmp/android-prefix
[ -f "$PREFIX/include/sodium.h" ] && { echo "libsodium already built"; exit 0; }
: "${CC:=$(ls $ANDROID_HOME/ndk/*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android21-clang 2>/dev/null | sort -V | tail -1)}"
BIN=$(dirname "$CC")
export CC AR="$BIN/llvm-ar" RANLIB="$BIN/llvm-ranlib" AS="$CC" LD="$BIN/ld" STRIP="$BIN/llvm-strip"
echo "Using CC=$CC"
cd /tmp; rm -rf libsodium-build && mkdir libsodium-build && cd libsodium-build
curl -sL https://download.libsodium.org/libsodium/releases/libsodium-1.0.20-stable.tar.gz | tar xz
cd libsodium-stable
./configure --host=aarch64-linux-android --prefix="$PREFIX" --disable-shared --enable-static --with-pic >/tmp/sodium-conf.log 2>&1 || { echo "CONFIGURE FAILED"; tail -20 /tmp/sodium-conf.log; exit 1; }
make -j4 install >/tmp/sodium-make.log 2>&1 || { echo "MAKE FAILED"; tail -20 /tmp/sodium-make.log; exit 1; }
echo "libsodium installed:"; ls "$PREFIX/include/sodium.h" "$PREFIX/lib/libsodium.a"
