// Where the tests load the browser runtime and the gateway from. By default that is the source
// tree; scripts/build-web.sh points these at the assembled packages instead:
//   MESHGUARD_WEB_DIR      a directory holding meshguard.mjs, relay-protocol.mjs and meshguard.wasm
//   MESHGUARD_GATEWAY_DIR  a directory holding gateway/server.mjs, gateway/pass.mjs and web/relay-protocol.mjs
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = new URL('../', import.meta.url);
const directory = name => process.env[name] ? pathToFileURL(resolve(process.env[name]) + '/') : root;

export const webDir = process.env.MESHGUARD_WEB_DIR ? directory('MESHGUARD_WEB_DIR') : new URL('web/', root);
export const gatewayDir = directory('MESHGUARD_GATEWAY_DIR');

/** The WASM module: the package's copy, or the build output in the source tree. */
export const wasmPath = process.env.MESHGUARD_WEB_DIR
  ? resolve(process.env.MESHGUARD_WEB_DIR, 'meshguard.wasm')
  : 'zig-out/bin/meshguard.wasm';
export const wasmBytes = () => readFileSync(wasmPath);

export const loadWeb = async () => ({
  ...await import(new URL('meshguard.mjs', webDir).href),
  ...await import(new URL('relay-protocol.mjs', webDir).href),
});
export const loadGateway = async () => ({
  ...await import(new URL('gateway/server.mjs', gatewayDir).href),
  ...await import(new URL('gateway/pass.mjs', gatewayDir).href),
});
