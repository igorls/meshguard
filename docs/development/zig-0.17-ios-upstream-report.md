# Draft upstream Zig bug report

Not filed. The following text is ready to copy into an upstream issue.

## Title

0.17.0: Threaded.io() fails to compile for iOS because processReplace accesses NullFile.fd

## Zig version and environment

- Zig 0.17.0, official aarch64 macOS binary distribution, unmodified standard library.
- Host: macOS 27.2 arm64, Xcode 27.0.
- Reproduces for `aarch64-ios` and `aarch64-ios-simulator`.
- The same source compiles for `aarch64-macos`.

## Minimal reproduction

Save as `repro.zig` (no build file or other dependencies):

```zig
const std = @import("std");

export fn seconds() i64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return @intCast(std.Io.Timestamp.now(io, .real).toSeconds());
}
```

Run either command:

```sh
zig build-lib repro.zig -target aarch64-ios -OReleaseFast -lc -fno-emit-bin
zig build-lib repro.zig -target aarch64-ios-simulator -OReleaseFast -lc -fno-emit-bin
```

Both exit 1. The control command exits 0:

```sh
zig build-lib repro.zig -target aarch64-macos -OReleaseFast -lc -fno-emit-bin
```

## Actual result

Diagnostic with the toolchain prefix omitted:

```text
std/Io/Threaded.zig:15486:25: error: no field named 'fd' in struct 'Io.Threaded.NullFile__struct_10'
        if (t.null_file.fd != -1) return t.null_file.fd;
                        ^~
std/Io/Threaded.zig:357:48: note: struct declared here
    .wasi, .ios, .tvos, .visionos, .watchos => struct {
                                               ^~~~~~
referenced by:
    spawnDarwin: std/Io/Threaded.zig:17468:59
    processReplace: std/Io/Threaded.zig:15217:37
```

## Expected result

Constructing Threaded I/O and reading a clock should compile for both iOS
targets. Unsupported process operations should return `error.OperationUnsupported`
without preventing unrelated I/O operations from compiling.

## Investigation

`Threaded.io()` includes `processReplace` in its vtable. That implementation
checks `std.process.can_replace`, which is true for iOS in 0.17.0, then reaches
`spawnDarwin` and `getDevNullFd`. iOS `Threaded.NullFile` has no `fd` field.

By comparison, the `processSpawn` switch explicitly selects the unsupported
implementation for `.ios`, `.tvos`, `.watchos` and `.visionos`. Those other
Apple platforms also use the empty `NullFile` type; they have not been tested
here. It may be appropriate to align `can_replace` and/or the `processReplace`
implementation with the unsupported process-spawn targets.

Copying the public I/O vtable at compile time and substituting
`std.Io.failingProcessReplace` still instantiates the original broken table.
Even selecting only `Threaded.io().vtable.now` reproduces the error. No process
spawn or replace operation is called by the reproducer.
