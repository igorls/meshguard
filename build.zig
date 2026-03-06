const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Detect target OS — works for both native and cross-compilation.
    // target.query.os_tag is null for native builds, so fall back to the
    // resolved target's os.tag.
    const resolved_os = if (target.query.os_tag) |os| os else target.result.os.tag;
    const resolved_abi = if (target.query.abi) |abi| abi else target.result.abi;
    const is_android = resolved_os == .linux and resolved_abi == .android;
    const is_windows = resolved_os == .windows;

    // ─── FFI module (for mobile embedding — not built on Windows) ───
    if (!is_windows) {
        const ffi_mod = b.createModule(.{
            .root_source_file = b.path("src/meshguard_ffi.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .strip = if (is_android) true else null,
        });

        const ffi_lib = b.addLibrary(.{
            .name = "meshguard-ffi",
            .root_module = ffi_mod,
            .linkage = .dynamic,
        });

        // Link libsodium on desktop targets for AVX2-accelerated crypto.
        // On Android, the Zig std.crypto software fallback is used.
        if (!is_android) {
            ffi_lib.linkSystemLibrary("sodium");
        }

        b.installArtifact(ffi_lib);
    }

    // ─── Targets below only build for native (not Android) ───
    if (!is_android) {
        // ─── Root modules ───
        const exe_mod = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        const lib_mod = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        // ─── Main executable ───
        const exe = b.addExecutable(.{
            .name = "meshguard",
            .root_module = exe_mod,
        });
        if (!is_windows) {
            exe.linkSystemLibrary("sodium"); // AVX2 ChaCha20-Poly1305 assembly
        }
        // On Windows, link ws2_32 for Winsock2 sockets
        if (is_windows) {
            exe.linkSystemLibrary("ws2_32");
        }
        b.installArtifact(exe);

        // On Windows, bundle wintun.dll alongside meshguard.exe
        if (is_windows) {
            b.installBinFile("deps/wintun/wintun.dll", "wintun.dll");
        }

        // ─── WG interop test binary (Linux only — requires kernel WG) ───
        if (!is_windows) {
            const interop_mod = b.createModule(.{
                .root_source_file = b.path("src/wg_interop.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            });
            const interop_exe = b.addExecutable(.{
                .name = "wg-interop-test",
                .root_module = interop_mod,
            });
            interop_exe.linkSystemLibrary("sodium");
            b.installArtifact(interop_exe);
        }

        // ─── Run step ───
        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }
        const run_step = b.step("run", "Run meshguard");
        run_step.dependOn(&run_cmd.step);

        // ─── Static library (for embedding) ───
        const lib = b.addLibrary(.{
            .name = "meshguard",
            .root_module = lib_mod,
            .linkage = .static,
        });
        b.installArtifact(lib);

        // ─── Unit tests ───
        const test_mod = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,

        });

        const unit_tests = b.addTest(.{
            .root_module = test_mod,
        });
        if (!is_windows) {
            unit_tests.linkSystemLibrary("sodium");
        }
        if (is_windows) {
            unit_tests.linkSystemLibrary("ws2_32");
        }
        const run_unit_tests = b.addRunArtifact(unit_tests);
        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_unit_tests.step);
    }
}

