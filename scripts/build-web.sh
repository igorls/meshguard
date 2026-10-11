#!/usr/bin/env bash
# Build the MeshGuard browser runtime and the browser gateway as release packages.
#
# Usage: scripts/build-web.sh [output-directory]
#
# Writes, under the output directory (default zig-out/web):
#   meshguard-web-<version>.tgz      npm package @meshguard/web: meshguard.wasm (ReleaseSmall),
#                                    meshguard.mjs, relay-protocol.mjs, TypeScript declarations,
#                                    SHA256SUMS of the runtime files
#   meshguard-gateway-<version>.tgz  npm package @meshguard/gateway: gateway/server.mjs,
#                                    gateway/pass.mjs, web/relay-protocol.mjs, example
#                                    configuration, systemd and nginx templates, SHA256SUMS
#   web/, gateway/                   the staged package directories
#
# <version> comes from build.zig.zon. Both tarballs are `npm pack` output (contents under
# package/), installable with `npm install ./meshguard-web-<version>.tgz`. Nothing is published.
#
# The script then unpacks both tarballs and runs the WASM and browser/gateway tests against the
# unpacked packages rather than the source tree. Those need Node.js (22 or newer) and Bun.
# Optional environment:
#   MESHGUARD_BINARY           native meshguard binary, to run the gateway-to-relay end-to-end test
#   MESHGUARD_NATIVE_LIBRARY   native FFI library, to run the WASM/native interoperability test
#   MESHGUARD_SKIP_TYPECHECK=1 skip checking the TypeScript declarations (which uses npx typescript)
set -euo pipefail
if [[ $# -gt 1 ]]; then
  echo 'Usage: scripts/build-web.sh [output-directory]' >&2
  exit 1
fi
if [[ "$(zig version)" != 0.16.0 ]]; then
  echo 'Web packaging requires Zig 0.16.0.' >&2
  exit 1
fi
for tool in node npm bun; do
  command -v "$tool" >/dev/null || { echo "Web packaging requires $tool." >&2; exit 1; }
done
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
output="${1:-zig-out/web}"
version="$(sed -n 's/^[[:space:]]*\.version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' build.zig.zon)"
if [[ -z "$version" ]]; then
  echo 'Could not read the version from build.zig.zon.' >&2
  exit 1
fi
web="$output/web"
gateway="$output/gateway"
rm -rf "$web" "$gateway" "$output/test" "$output"/meshguard-web-*.tgz "$output"/meshguard-gateway-*.tgz
mkdir -p "$web" "$gateway/gateway" "$gateway/web" "$output/test"

echo "==> Building meshguard.wasm (ReleaseSmall)"
zig build wasm -Doptimize=ReleaseSmall

# Writes "<sha256>  <file>" lines (sha256sum format) for the given files, relative to a directory.
checksums() {
  local dir="$1"
  shift
  (cd "$dir" && node -e '
    const { createHash } = require("node:crypto");
    const { readFileSync } = require("node:fs");
    for (const file of process.argv.slice(1)) {
      console.log(`${createHash("sha256").update(readFileSync(file)).digest("hex")}  ${file}`);
    }' "$@" > SHA256SUMS)
}

# Copies a package.json template with the release version.
stamp() {
  node -e '
    const fs = require("node:fs");
    const [from, to, version] = process.argv.slice(1);
    const manifest = JSON.parse(fs.readFileSync(from, "utf8"));
    manifest.version = version;
    fs.writeFileSync(to, JSON.stringify(manifest, null, 2) + "\n");' "$1" "$2" "$version"
}

echo "==> Assembling @meshguard/web $version"
cp zig-out/bin/meshguard.wasm "$web/"
cp web/meshguard.mjs web/meshguard.d.mts web/relay-protocol.mjs web/relay-protocol.d.mts "$web/"
cp packages/web/README.md LICENSE "$web/"
stamp packages/web/package.json "$web/package.json"
checksums "$web" meshguard.wasm meshguard.mjs relay-protocol.mjs

echo "==> Assembling @meshguard/gateway $version"
cp gateway/server.mjs gateway/pass.mjs gateway/meshguard-web.service gateway/nginx-location.conf "$gateway/gateway/"
cp web/relay-protocol.mjs "$gateway/web/"
cp packages/gateway/README.md packages/gateway/config.example.json LICENSE "$gateway/"
stamp packages/gateway/package.json "$gateway/package.json"
checksums "$gateway" gateway/server.mjs gateway/pass.mjs web/relay-protocol.mjs

echo "==> Checking the runtime"
# The wrapper refuses a module with another ABI version; check here so a mismatch fails the
# build instead of an embedder. Also: no imports, and every export has a declaration.
node --input-type=module -e '
  import { readFileSync } from "node:fs";
  import { resolve } from "node:path";
  import { pathToFileURL } from "node:url";
  const dir = resolve(process.argv[1]);
  const url = file => pathToFileURL(resolve(dir, file)).href;
  const wrapper = await import(url("meshguard.mjs"));
  const module = await WebAssembly.compile(readFileSync(resolve(dir, "meshguard.wasm")));
  const imports = WebAssembly.Module.imports(module);
  if (imports.length) throw new Error(`meshguard.wasm has imports: ${JSON.stringify(imports)}`);
  const instance = await WebAssembly.instantiate(module, {});
  const abi = instance.exports.mg_abi_version();
  if (abi !== wrapper.ABI_VERSION) throw new Error(`meshguard.wasm has ABI ${abi}, meshguard.mjs expects ${wrapper.ABI_VERSION}`);
  for (const name of ["meshguard", "relay-protocol"]) {
    const declared = readFileSync(resolve(dir, `${name}.d.mts`), "utf8");
    for (const key of Object.keys(await import(url(`${name}.mjs`)))) {
      if (!new RegExp(`export (declare )?(const|function|class) ${key}\\b`).test(declared)) {
        throw new Error(`${name}.d.mts does not declare ${key}`);
      }
    }
  }
  console.log(`ABI ${abi}, no imports, ${readFileSync(resolve(dir, "meshguard.wasm")).length} bytes, declarations complete`);
' "$web"

echo "==> Packing"
# npm reads "a/b" as a GitHub repository; a directory needs a leading ./ or /.
local_path() { if [[ "$1" == /* ]]; then echo "$1"; else echo "./$1"; fi; }
npm pack "$(local_path "$web")" --pack-destination "$output" --silent >/dev/null
npm pack "$(local_path "$gateway")" --pack-destination "$output" --silent >/dev/null
for name in web gateway; do
  [[ -f "$output/meshguard-$name-$version.tgz" ]] || { echo "npm pack did not write meshguard-$name-$version.tgz" >&2; exit 1; }
  mkdir -p "$output/test/$name"
  (cd "$output/test/$name" && tar -xzf "../../meshguard-$name-$version.tgz")
done
installed_web="$output/test/web/package"
installed_gateway="$output/test/gateway/package"

echo "==> Verifying package checksums"
for dir in "$installed_web" "$installed_gateway"; do
  (cd "$dir" && node -e '
    const { createHash } = require("node:crypto");
    const { readFileSync } = require("node:fs");
    for (const line of readFileSync("SHA256SUMS", "utf8").trim().split("\n")) {
      const [sum, file] = line.split(/\s+/);
      if (createHash("sha256").update(readFileSync(file)).digest("hex") !== sum) throw new Error(`Checksum mismatch: ${file}`);
    }')
done

echo "==> Testing the packaged runtime"
export MESHGUARD_WEB_DIR="$installed_web" MESHGUARD_GATEWAY_DIR="$installed_gateway"
node tests/wasm/smoke.mjs
bun test tests/web
if [[ -n "${MESHGUARD_NATIVE_LIBRARY:-}" ]]; then
  node tests/wasm/native-interop.mjs
else
  echo 'MESHGUARD_NATIVE_LIBRARY is not set; skipping the WASM/native interoperability test.'
fi
unset MESHGUARD_WEB_DIR MESHGUARD_GATEWAY_DIR

if [[ "${MESHGUARD_SKIP_TYPECHECK:-}" != 1 ]]; then
  echo "==> Type-checking a consumer against the packaged declarations"
  consumer="$output/test/consumer"
  mkdir -p "$consumer/node_modules/@meshguard"
  cp -R "$installed_web" "$consumer/node_modules/@meshguard/web"
  cp tests/web/consumer.mts "$consumer/"
  (cd "$consumer" && npx --yes --package typescript@5.9.3 -- tsc --noEmit --strict \
    --target es2022 --module nodenext --moduleResolution nodenext --lib es2022,dom consumer.mts)
fi

echo "==> Wrote $output/meshguard-web-$version.tgz and $output/meshguard-gateway-$version.tgz"
