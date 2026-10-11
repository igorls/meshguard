#!/usr/bin/env bash
# Build distributable C ABI libraries for Linux, FreeBSD and Android with Zig.
#
# Usage: scripts/build-libraries.sh [output-directory]
#
# Writes, under the output directory (default zig-out/libraries):
#   meshguard-ffi-linux-amd64.tar.gz    shared and static library, header
#   meshguard-ffi-linux-arm64.tar.gz    shared and static library, header
#   meshguard-ffi-linux-armhf.tar.gz    shared and static library, header
#                                       (32-bit ARMv7-A with NEON, hard-float)
#   meshguard-ffi-freebsd-amd64.tar.gz  shared and static library, header
#   meshguard-ffi-android.zip           jniLibs/<abi>/libmeshguard-ffi.so, header
#                                       (arm64-v8a, armeabi-v7a and x86_64)
#
# Android needs only the NDK sysroot (Bionic headers and libc stubs). Set
# ANDROID_NDK_HOME or ANDROID_NDK_ROOT to the NDK. MESHGUARD_LIBRARY_PLATFORMS
# selects a subset, for example "linux freebsd" (default: all three).
set -euo pipefail
if [[ $# -gt 1 ]]; then
  echo 'Usage: scripts/build-libraries.sh [output-directory]' >&2
  exit 1
fi
if [[ "$(zig version)" != 0.16.0 ]]; then
  echo 'Library packaging requires Zig 0.16.0.' >&2
  exit 1
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${1:-$root/zig-out/libraries}"
output="$(cd "${1:-$root/zig-out/libraries}" && pwd)"
platforms="${MESHGUARD_LIBRARY_PLATFORMS:-linux freebsd android}"
# Oldest supported runtimes: glibc 2.28, FreeBSD 14.0 and Android 7.0 (API 24).
glibc=2.28
android_api=24
cd "$root"

wants() { [[ " $platforms " == *" $1 "* ]]; }

# Build one target into $output/build/<label>. The C ABI is the same everywhere;
# std.crypto keeps the libraries free of a libsodium runtime dependency.
build_target() {
  local label="$1" target="$2"
  shift 2
  rm -rf "$output/build/$label"
  zig build ffi -Dtarget="$target" -Doptimize=ReleaseFast -Dcrypto-backend=std \
    --prefix "$output/build/$label" "$@"
}

# Package a desktop target as <label>/{lib,include,LICENSE} in a tarball.
package_desktop() {
  local label="$1" target="$2" package="$output/$1"
  build_target "$label" "$target"
  rm -rf "$package"
  mkdir -p "$package/lib" "$package/include"
  cp "$output/build/$label/lib/libmeshguard-ffi."{so,a} "$package/lib/"
  cp include/meshguard.h "$package/include/"
  cp LICENSE "$package/"
  tar -czf "$output/meshguard-ffi-$label.tar.gz" -C "$output" "$label"
}

if wants linux; then
  package_desktop linux-amd64 "x86_64-linux-gnu.$glibc"
  package_desktop linux-arm64 "aarch64-linux-gnu.$glibc"
  package_desktop linux-armhf "arm-linux-gnueabihf.$glibc"
fi
if wants freebsd; then
  package_desktop freebsd-amd64 x86_64-freebsd.14.0
fi

if wants android; then
  ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${ANDROID_NDK_LATEST_HOME:-}}}"
  if [[ -z "$ndk" || ! -d "$ndk/toolchains/llvm/prebuilt" ]]; then
    echo 'Android libraries need the NDK: set ANDROID_NDK_HOME or ANDROID_NDK_ROOT.' >&2
    exit 1
  fi
  # The sysroot is the same for every NDK host; take whichever is installed.
  sysroot="$(find "$ndk/toolchains/llvm/prebuilt" -mindepth 2 -maxdepth 2 -name sysroot -type d | head -n 1)"
  if [[ -z "$sysroot" ]]; then
    echo "No NDK sysroot under $ndk/toolchains/llvm/prebuilt." >&2
    exit 1
  fi
  echo "Android NDK $(sed -n 's/^Pkg.Revision *= *//p' "$ndk/source.properties" 2>/dev/null), API $android_api"
  package="$output/android"
  rm -rf "$package"
  mkdir -p "$package/include"
  # <Android ABI> <Zig target> <NDK sysroot triple>
  while read -r abi target triple; do
    libc="$output/build/libc-$abi.conf"
    mkdir -p "$output/build"
    cat > "$libc" <<EOF
include_dir=$sysroot/usr/include
sys_include_dir=$sysroot/usr/include/$triple
crt_dir=$sysroot/usr/lib/$triple/$android_api
msvc_lib_dir=
kernel32_lib_dir=
gcc_dir=
EOF
    build_target "android-$abi" "$target.$android_api" --libc "$libc"
    mkdir -p "$package/jniLibs/$abi"
    cp "$output/build/android-$abi/lib/libmeshguard-ffi.so" "$package/jniLibs/$abi/"
  done <<'ABIS'
arm64-v8a aarch64-linux-android aarch64-linux-android
armeabi-v7a arm-linux-androideabi arm-linux-androideabi
x86_64 x86_64-linux-android x86_64-linux-android
ABIS
  cp include/meshguard.h "$package/include/"
  cp LICENSE "$package/"
  rm -f "$output/meshguard-ffi-android.zip"
  if command -v zip >/dev/null; then
    (cd "$output" && zip -qrX meshguard-ffi-android.zip android)
  else
    (cd "$output" && python3 -m zipfile -c meshguard-ffi-android.zip android)
  fi
fi
echo "Embedding libraries built in $output"
