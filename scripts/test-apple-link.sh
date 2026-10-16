#!/usr/bin/env bash
# Compile real C and Swift hosts against the packaged C ABI, then run macOS.
set -euo pipefail
if [[ $# -gt 1 ]]; then
  echo 'Usage: scripts/test-apple-link.sh [output-directory]' >&2
  exit 1
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="$(cd "${1:-$root/zig-out/apple}" && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/meshguard-link.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
cat > "$scratch/host.c" <<'C'
#include <meshguard.h>
#include <assert.h>
int main(void) {
    meshguard_context *ctx = meshguard_init(NULL, 0);
    assert(ctx != NULL);
    assert(meshguard_get_bound_port(ctx) != 0);
    assert(!meshguard_is_running(ctx));
    uint8_t pubkey[32], wg[32], sender[32], data[1024], nonce[12], code;
    uint32_t len;
    meshguard_get_pubkey(ctx, pubkey);
    meshguard_get_wg_pubkey(ctx, wg);
    assert(meshguard_add_contact(ctx, pubkey, wg) == 0);
    assert(meshguard_contact_count(ctx) == 1);
    meshguard_set_contacts_only(ctx, true);
    assert(meshguard_recv(ctx, data, &len, sender) == 1);
    assert(meshguard_recv_delivery_status(ctx, sender, nonce, &code) == 1);
    meshguard_clear_contacts(ctx);
    assert(meshguard_contact_count(ctx) == 0);
    meshguard_destroy(ctx);
    return 0;
}
C
package="$output/macos-universal"
# Parse every thin dynamic library, including Intel builds that this host
# cannot necessarily execute, and link consumers for both universal slices.
for arch in arm64 x86_64; do
  xcrun nm -gU "$output/macos-$arch/lib/libmeshguard-ffi.dylib" > "$scratch/symbols-$arch"
  xcrun clang -arch "$arch" -mmacosx-version-min=13.0 -std=c11 -Wall -Wextra -Werror \
    -I "$package/include" "$scratch/host.c" -L "$package/lib" -lmeshguard-ffi \
    -Wl,-rpath,"$package/lib" -o "$scratch/dynamic-$arch-host"
done
xcrun clang -std=c11 -Wall -Wextra -Werror -I "$package/include" "$scratch/host.c" \
  "$package/lib/libmeshguard-ffi.a" -o "$scratch/static-host"
"$scratch/static-host"
xcrun clang -std=c11 -Wall -Wextra -Werror -I "$package/include" "$scratch/host.c" \
  -L "$package/lib" -lmeshguard-ffi -Wl,-rpath,"$package/lib" -o "$scratch/dynamic-host"
"$scratch/dynamic-host"

cat > "$scratch/host.swift" <<'SWIFT'
import MeshGuardFFI
guard let context = meshguard_init(nil, 0) else { fatalError("Initialization failed") }
precondition(meshguard_get_bound_port(context) != 0)
meshguard_destroy(context)
SWIFT
xcrun swiftc -I "$package/include" "$scratch/host.swift" \
  "$package/lib/libmeshguard-ffi.a" -o "$scratch/swift-host"
"$scratch/swift-host"
for variant in device simulator; do
  sdk=iphoneos
  target=arm64-apple-ios15.0
  slice=ios-arm64
  if [[ "$variant" == simulator ]]; then
    sdk=iphonesimulator
    target=arm64-apple-ios15.0-simulator
    slice=ios-arm64-simulator
  fi
  sdk_path="$(xcrun --sdk "$sdk" --show-sdk-path)"
  framework="$output/MeshGuardFFI.xcframework/$slice"
  xcrun --sdk "$sdk" swiftc -target "$target" -sdk "$sdk_path" \
    -I "$framework/Headers" "$scratch/host.swift" "$framework/libmeshguard-ffi.a" \
    -o "$scratch/ios-$variant-host"
done
echo 'Apple link checks passed: C static/dynamic and Swift hosts; iOS device/simulator links.'
