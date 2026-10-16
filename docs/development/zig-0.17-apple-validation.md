# Zig 0.17.0 Apple validation

## Baseline reproduction

The starting revision was `45f6489` (`build: migrate codebase and CI to
Zig 0.17.0`). Reproduced on macOS 27.2 arm64 with Xcode 27.0 and the official
Zig 0.17.0 aarch64 macOS binary distribution. Its archive SHA-256 was verified:
`b607e9b9234790a008116ae5bdb71c6243b84b9fb42a53a9e70fde41c06c536a`.

Both commands exited with status 1:

```sh
zig build ffi -Dtarget=aarch64-ios -Doptimize=ReleaseFast -Dcrypto-backend=std
zig build ffi -Dtarget=aarch64-ios-simulator -Doptimize=ReleaseFast -Dcrypto-backend=std
```

Both produced the same standard-library diagnostic (toolchain prefix omitted):

```text
std/Io/Threaded.zig:15486:25: error: no field named 'fd' in struct 'Io.Threaded.NullFile__struct_13'
        if (t.null_file.fd != -1) return t.null_file.fd;
                        ^~
std/Io/Threaded.zig:357:48: note: struct declared here
    .wasi, .ios, .tvos, .visionos, .watchos => struct {
                                               ^~~~~~
referenced by:
    spawnDarwin: std/Io/Threaded.zig:17468:59
    processReplace: std/Io/Threaded.zig:15217:37
```

Constructing the `Threaded` I/O table pulls in `processReplace`, even when
an application only asks for a clock. `std.process.can_replace` is true for
iOS, while `processSpawn` is explicitly unsupported there. `spawnDarwin`
references `getDevNullFd`, but iOS `NullFile` has no `fd` member.

## Workaround investigation and packaging decision

Two standalone experiments still failed with the same `NullFile.fd` diagnostic:

- Copy `Threaded.io().vtable.*` at compile time and replace `processReplace`
  with the public `std.Io.failingProcessReplace` before exposing the copy.
- Select only `Threaded.io().vtable.now` and call that clock function directly.

Both require the original table, which still instantiates `processReplace`.
The implementation functions behind that table are private. A replacement I/O
backend would also have to preserve clocks, sleep, secure randomness, file I/O
and contended locks throughout the FFI's dependencies; it is not a narrow
workaround for this compiler upgrade. No working scoped workaround was found.

The Apple scripts therefore omit iOS device/simulator builds, the XCFramework
and its zip, remove stale generated iOS artifacts, and explicitly report skipped
iOS links. CI and release packaging advertise only the macOS outputs. The Zig
standard library remains unmodified. Direct iOS FFI builds remain blocked.

## Local Apple CI results

All four requested CI steps completed with exit status 0 using Zig 0.17.0.
The final step's native build and relay test are shown separately below.
Output prefixes and test-runner cache identifiers have been omitted; all other
output is retained. The unit runner prints a `failed command:` label after
captured warning output even though the build exits 0; the follow-up build
summary confirms all six steps succeeded. The warning messages exercise
revocation rejection paths.

### Unit and FFI tests

Command (exit 0):

```sh
zig build test -Dcrypto-backend=std
```

```text
test
+- run test w
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): org revoke rejected: invalid or untrusted org signature
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): org revoke rejected: invalid or untrusted org signature
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): node revoked by org (reason=2)
failed command: <test runner invocation omitted>

test
+- run test w
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): org revoke rejected: invalid or untrusted org signature
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): org revoke rejected: invalid or untrusted org signature
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): node revoked by org (reason=2)
[swim] (warn): node revoked by org (reason=2)
failed command: <test runner invocation omitted>
```

### Unit and FFI build summary

Command (exit 0):

```sh
zig build test -Dcrypto-backend=std --summary all
```

```text
Build Summary: 6/6 steps succeeded
test success
+- run test cached
|  +- compile test debug native cached
|     +- options cached
+- run test cached
   +- compile test debug native cached
      +- options (reused)
```

### Apple packaging

Command (exit 0):

```sh
./scripts/build-apple.sh
```

```text
zig-out/apple/macos-arm64/lib/libmeshguard-ffi.dylib: replacing existing signature
zig-out/apple/macos-universal/lib/libmeshguard-ffi.dylib: replacing existing signature
Skipping iOS device/simulator and XCFramework: Zig 0.17.0 Threaded NullFile.fd regression.
Apple embedding artifacts built in zig-out/apple
```

### Apple consumer linking

Command (exit 0):

```sh
./scripts/test-apple-link.sh
```

```text
Apple link checks passed: C static/dynamic and Swift hosts; both macOS architectures linked.
iOS device/simulator links skipped: Zig 0.17.0 Threaded NullFile.fd regression.
```

### Native ReleaseFast build

Command (exit 0):

```sh
zig build -Doptimize=ReleaseFast -Dcrypto-backend=std
```

```text
(no output)
```

### Relay integration

Command (exit 0):

```sh
python3 scripts/test-relay.py zig-out/bin/meshguard zig-out/apple/macos-universal/lib/libmeshguard-ffi.dylib -v
```

```text
test_every_export_resolves (__main__.ExportedSymbols.test_every_export_resolves) ... ok
test_contacts_reach_each_other_and_absent_contacts_report_offline (__main__.OpaqueRelay.test_contacts_reach_each_other_and_absent_contacts_report_offline) ...   🔑 WG handshake complete (slot 0), tunnel ready
  🔑 WG handshake complete (slot 0), tunnel ready
ok
test_authenticated_relay_forwards_between_proven_clients_only (__main__.RelayForwarding.test_authenticated_relay_forwards_between_proven_clients_only) ...   🔑 WG handshake complete (slot 0), tunnel ready
  🔑 WG handshake complete (slot 0), tunnel ready
ok
test_clients_that_met_through_a_relay_open_a_tunnel (__main__.RelayForwarding.test_clients_that_met_through_a_relay_open_a_tunnel) ...   🔑 WG handshake complete (slot 0), tunnel ready
  🔑 WG handshake complete (slot 0), tunnel ready
  🔑 Tunnel handshake sent to 5e21...
  🔑 WG handshake init handled via relay (slot 1)
  🔑 WG handshake complete via relay (slot 1), tunnel ready
ok
test_default_daemon_still_relays_for_known_clients (__main__.RelayForwarding.test_default_daemon_still_relays_for_known_clients) ...   🔑 WG handshake complete (slot 0), tunnel ready
  🔑 WG handshake complete (slot 0), tunnel ready
ok
test_closed_relay_admits_pass_holders_after_reload (__main__.RelayPasses.test_closed_relay_admits_pass_holders_after_reload) ...   🔑 WG handshake complete (slot 0), tunnel ready
  🔑 WG handshake complete (slot 0), tunnel ready
ok
test_contexts_per_relay_and_switching (__main__.SeveralRelays.test_contexts_per_relay_and_switching) ...   🔑 WG handshake complete (slot 0), tunnel ready
  🔑 WG handshake complete (slot 0), tunnel ready
  🔑 WG handshake complete (slot 0), tunnel ready
  🔑 WG handshake complete (slot 0), tunnel ready
  🔑 WG handshake complete (slot 0), tunnel ready
  🔑 WG handshake complete (slot 0), tunnel ready
ok

----------------------------------------------------------------------
Ran 7 tests in 18.493s

OK
```

### Packaged artifact inspection

Both universal libraries report `x86_64 arm64` with `lipo -archs`.
`codesign --verify --strict --all-architectures` succeeds for the universal
dylib. All three macOS tarballs contain no AppleDouble entries. Both generated
iOS build directories, the XCFramework directory and its zip are absent.

These checks prove local macOS builds, consumer linking and relay integration.
iOS runtime and links remain unverified because iOS compilation is blocked.
