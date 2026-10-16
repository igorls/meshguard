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
