#!/usr/bin/env bash
# Check the packages from scripts/build-libraries.sh: every library exports
# exactly the `export fn` entry points of src/meshguard_ffi.zig, which the
# header declares; libraries depend only on the platform C library; Android
# libraries suit 16 KB page devices; C hosts compile and link against each
# desktop package, and run where the host can execute them.
#
# Usage: scripts/test-libraries.sh [output-directory]
# Needs binutils (readelf, nm) and Zig; runs the Linux x86_64 hosts with cc.
set -euo pipefail
if [[ $# -gt 1 ]]; then
  echo 'Usage: scripts/test-libraries.sh [output-directory]' >&2
  exit 1
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="$(cd "${1:-$root/zig-out/libraries}" && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/meshguard-libraries.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

grep -oE '^export fn meshguard_[a-z0-9_]+' "$root/src/meshguard_ffi.zig" | awk '{print $3}' | sort -u > "$scratch/expected"
grep -oE '\bmeshguard_[a-z0-9_]+\(' "$root/include/meshguard.h" | tr -d '(' | sort -u > "$scratch/header"
count=$(wc -l < "$scratch/expected")
echo "src/meshguard_ffi.zig exports $count functions"
diff -u "$scratch/expected" "$scratch/header" > "$scratch/header.diff" ||
  fail "include/meshguard.h declarations differ from the exports: $(cat "$scratch/header.diff")"

# check_shared <file> <readelf machine> <allowed NEEDED, extended regex> [min LOAD alignment]
check_shared() {
  local file="$1" machine="$2" needed="$3" align="${4:-0}" name
  [[ -f "$file" ]] || { fail "$file is missing"; return; }
  name="${file#"$output/"}"
  readelf -h "$file" | grep -q "Machine: *$machine\$" || fail "$name is not $machine"
  nm -D --defined-only "$file" | awk '{print $NF}' | sort -u > "$scratch/exports"
  diff -u "$scratch/expected" "$scratch/exports" > "$scratch/exports.diff" ||
    fail "$name exports differ: $(cat "$scratch/exports.diff")"
  while read -r lib; do
    [[ "$lib" =~ ^($needed)$ ]] || fail "$name needs unexpected library $lib"
  done < <(readelf -d "$file" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
  if ((align)); then
    while read -r load; do
      ((load >= align)) || fail "$name has a LOAD segment aligned to $load, below $align"
    done < <(readelf -lW "$file" | awk '$1 == "LOAD" {print $NF}')
  fi
  echo "ok $name ($machine, $(wc -l < "$scratch/exports") exports, needs: $(readelf -d "$file" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | tr '\n' ' '))"
}

check_static() {
  local file="$1" name="${1#"$output/"}"
  [[ -f "$file" ]] || { fail "$file is missing"; return; }
  nm -g --defined-only "$file" 2>/dev/null | awk '$2 == "T" {print $3}' | grep '^meshguard_' | sort -u > "$scratch/static"
  diff -u "$scratch/expected" "$scratch/static" > "$scratch/static.diff" ||
    fail "$name exports differ: $(cat "$scratch/static.diff")"
  echo "ok $name"
}

cat > "$scratch/host.c" <<'C'
#include <meshguard.h>
#include <assert.h>
#include <stdio.h>
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
    puts("host ok");
    return 0;
}
C

# link_hosts <package> <zig target> <run: yes|no>
link_hosts() {
  local package="$output/$1" target="$2" run="$3" kind
  for kind in dynamic static; do
    local exe="$scratch/$1-$kind" lib=(-L "$package/lib" -lmeshguard-ffi -Wl,-rpath,"$package/lib")
    [[ "$kind" == static ]] && lib=("$package/lib/libmeshguard-ffi.a")
    if ! zig cc -target "$target" -std=c11 -Wall -Wextra -Werror -I "$package/include" \
      "$scratch/host.c" "${lib[@]}" -o "$exe"; then
      fail "$1: C host did not link ($kind, $target)"
      continue
    fi
    if [[ "$run" == yes ]]; then
      "$exe" > /dev/null || fail "$1: $kind C host failed"
    fi
    echo "ok $1 $kind C host ($target$([[ "$run" == yes ]] && echo ', ran'))"
  done
}

native_amd64=no
[[ "$(uname -s)-$(uname -m)" == Linux-x86_64 ]] && native_amd64=yes

if [[ -d "$output/linux-amd64" || -d "$output/linux-arm64" ]]; then
  glibc='libc\.so\.6|libpthread\.so\.0|libdl\.so\.2|librt\.so\.1|libm\.so\.6|ld-linux-x86-64\.so\.2|ld-linux-aarch64\.so\.1'
  check_shared "$output/linux-amd64/lib/libmeshguard-ffi.so" 'Advanced Micro Devices X86-64' "$glibc"
  check_static "$output/linux-amd64/lib/libmeshguard-ffi.a"
  check_shared "$output/linux-arm64/lib/libmeshguard-ffi.so" AArch64 "$glibc"
  check_static "$output/linux-arm64/lib/libmeshguard-ffi.a"
  link_hosts linux-amd64 x86_64-linux-gnu.2.28 "$native_amd64"
  link_hosts linux-arm64 aarch64-linux-gnu.2.28 no
  # The packages are meant for the system toolchain too, not only zig cc.
  if [[ "$native_amd64" == yes ]] && command -v cc > /dev/null; then
    package="$output/linux-amd64"
    cc -std=c11 -Wall -Wextra -Werror -I "$package/include" "$scratch/host.c" \
      -L "$package/lib" -lmeshguard-ffi -Wl,-rpath,"$package/lib" -o "$scratch/cc-dynamic" &&
      "$scratch/cc-dynamic" > /dev/null && echo 'ok linux-amd64 dynamic C host (cc, ran)' ||
      fail 'linux-amd64: cc dynamic host'
    cc -std=c11 -Wall -Wextra -Werror -I "$package/include" "$scratch/host.c" \
      "$package/lib/libmeshguard-ffi.a" -lpthread -o "$scratch/cc-static" &&
      "$scratch/cc-static" > /dev/null && echo 'ok linux-amd64 static C host (cc, ran)' ||
      fail 'linux-amd64: cc static host'
  fi
fi

if [[ -d "$output/freebsd-amd64" ]]; then
  check_shared "$output/freebsd-amd64/lib/libmeshguard-ffi.so" 'Advanced Micro Devices X86-64' \
    'libc\.so\.7|libthr\.so\.3|libm\.so\.5|libsys\.so\.7'
  check_static "$output/freebsd-amd64/lib/libmeshguard-ffi.a"
  link_hosts freebsd-amd64 x86_64-freebsd.14.0 no
fi

if [[ -d "$output/android" ]]; then
  bionic='libc\.so|libdl\.so|libm\.so|liblog\.so'
  for abi in arm64-v8a:AArch64 'x86_64:Advanced Micro Devices X86-64'; do
    file="$output/android/jniLibs/${abi%%:*}/libmeshguard-ffi.so"
    check_shared "$file" "${abi#*:}" "$bionic" 16384
    # Every libc import must resolve against the NDK stubs of the minimum API.
    if nm -D --undefined-only "$file" | grep -v '@' | grep -q .; then
      fail "${abi%%:*}: unversioned undefined symbols: $(nm -D --undefined-only "$file" | grep -v '@' | tr '\n' ' ')"
    fi
  done
fi

if ((failures)); then
  echo "$failures library check(s) failed" >&2
  exit 1
fi
echo 'Library checks passed.'
