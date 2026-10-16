#!/usr/bin/env bash
# Build distributable C ABI libraries with Zig and the selected Xcode tools.
set -euo pipefail
if [[ $# -gt 1 ]]; then
  echo 'Usage: scripts/build-apple.sh [output-directory]' >&2
  exit 1
fi
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'Apple packaging requires macOS and Xcode.' >&2
  exit 1
fi
if [[ "$(zig version)" != 0.17.0 ]]; then
  echo 'Apple packaging requires Zig 0.17.0.' >&2
  exit 1
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${1:-$root/zig-out/apple}"
output="$(cd "${1:-$root/zig-out/apple}" && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/meshguard-apple.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
cd "$root"

build_slice() {
  local label="$1" target="$2" prefix="$output/build/$1"
  zig build ffi -Dtarget="$target" -Doptimize=ReleaseFast -Dcrypto-backend=std --prefix "$prefix"
  # Apple's linker needs archive members aligned to eight bytes. Repack into
  # a fresh directory so no objects from a previous build enter the archive.
  mkdir -p "$scratch/$label"
  (cd "$scratch/$label" && zig ar x "$prefix/lib/libmeshguard-ffi.a")
  chmod 644 "$scratch/$label/"*.o
  xcrun libtool -static -o "$prefix/lib/libmeshguard-ffi.a" "$scratch/$label/"*.o
}

for arch in arm64 x86_64; do
  target=aarch64-macos.13.0
  [[ "$arch" == x86_64 ]] && target=x86_64-macos.13.0
  build_slice "macos-$arch" "$target"
  package="$output/macos-$arch"
  mkdir -p "$package/lib" "$package/include"
  cp "$output/build/macos-$arch/lib/libmeshguard-ffi."{a,dylib} "$package/lib/"
  cp include/meshguard.h include/module.modulemap "$package/include/"
  cp LICENSE "$package/"
  # Zig already emits this relocatable install name; rewriting load commands
  # can exceed the Intel dylib's header padding even when the name is unchanged.
  [[ "$(xcrun otool -D "$package/lib/libmeshguard-ffi.dylib" | tail -n 1)" == '@rpath/libmeshguard-ffi.dylib' ]]
  codesign --force --sign - "$package/lib/libmeshguard-ffi.dylib"
done

universal="$output/macos-universal"
mkdir -p "$universal/lib" "$universal/include"
for suffix in a dylib; do
  xcrun lipo -create "$output/macos-arm64/lib/libmeshguard-ffi.$suffix" \
    "$output/macos-x86_64/lib/libmeshguard-ffi.$suffix" -output "$universal/lib/libmeshguard-ffi.$suffix"
done
codesign --force --sign - "$universal/lib/libmeshguard-ffi.dylib"
codesign --verify --strict --all-architectures "$universal/lib/libmeshguard-ffi.dylib"
cp include/meshguard.h include/module.modulemap "$universal/include/"
cp LICENSE "$universal/"

build_slice ios-device aarch64-ios.15.0
build_slice ios-simulator aarch64-ios.15.0-simulator
# xcodebuild refuses to replace an existing bundle. Remove only this generated
# bundle, leaving the other build/install outputs alone.
rm -rf "$output/MeshGuardFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$output/build/ios-device/lib/libmeshguard-ffi.a" -headers "$root/include" \
  -library "$output/build/ios-simulator/lib/libmeshguard-ffi.a" -headers "$root/include" \
  -output "$output/MeshGuardFFI.xcframework"

for arch in arm64 x86_64 universal; do
  COPYFILE_DISABLE=1 tar -czf "$output/meshguard-ffi-macos-$arch.tar.gz" -C "$output" "macos-$arch"
done
cp LICENSE "$output/LICENSE"
rm -f "$output/meshguard-ffi-ios-xcframework.zip"
(cd "$output" && zip -qrX meshguard-ffi-ios-xcframework.zip MeshGuardFFI.xcframework LICENSE)
echo "Apple embedding artifacts built in $output"
