const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Detect if we're cross-compiling for Android
    const is_android = if (target.query.os_tag) |os| os == .linux and
        (target.query.abi == .android) else false;

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

    // ─── FFI module (for mobile embedding) ───
    // Does NOT link libsodium — uses only std.crypto
    const ffi_mod = b.createModule(.{
        .root_source_file = b.path("src/meshguard_ffi.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true, // Always link libc — Android needs Bionic for TLS (__tls_get_addr)
    });

    // ─── Shared library (for Android JNI / mobile FFI) ───
    // Always built — this is the primary output for mobile embedding
    const ffi_lib = b.addLibrary(.{
        .name = "meshguard-ffi",
        .root_module = ffi_mod,
        .linkage = .dynamic,
    });

    b.installArtifact(ffi_lib);

    // ─── Targets below only build for native (not Android) ───
    if (!is_android) {
        // ─── Main executable ───
        const exe = b.addExecutable(.{
            .name = "meshguard",
            .root_module = exe_mod,
        });
        exe.linkSystemLibrary("sodium"); // AVX2 ChaCha20-Poly1305 assembly
        b.installArtifact(exe);

        // ─── WG interop test binary ───
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
        unit_tests.linkSystemLibrary("sodium");
        const run_unit_tests = b.addRunArtifact(unit_tests);
        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_unit_tests.step);
    }
}
