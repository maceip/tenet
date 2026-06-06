set -e
PREFIX=/tmp/android-prefix
[ -f "$PREFIX/include/ffi.h" ] && { echo "libffi already built"; exit 0; }
: "${CC:=$(ls $ANDROID_HOME/ndk/*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android21-clang 2>/dev/null | sort -V | tail -1)}"
BIN=$(dirname "$CC")
export CC AR="$BIN/llvm-ar" RANLIB="$BIN/llvm-ranlib" AS="$CC" LD="$BIN/ld"
echo "Using CC=$CC"
cd /tmp; rm -rf libffi-3.4.6
curl -sL https://github.com/libffi/libffi/releases/download/v3.4.6/libffi-3.4.6.tar.gz | tar xz
cd libffi-3.4.6
./configure --host=aarch64-linux-android --prefix="$PREFIX" --disable-shared --disable-docs >/tmp/ffi-conf.log 2>&1 || { echo "CONFIGURE FAILED"; tail -20 /tmp/ffi-conf.log; exit 1; }
make -j4 install >/tmp/ffi-make.log 2>&1 || { echo "MAKE FAILED"; tail -20 /tmp/ffi-make.log; exit 1; }
echo "libffi installed:"; ls "$PREFIX/include/ffi.h" "$PREFIX/lib/libffi.a"
