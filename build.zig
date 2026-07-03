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
    const is_ios = resolved_os == .ios;
    const is_windows = resolved_os == .windows;
    const is_macos = resolved_os == .macos;
    const is_freebsd = resolved_os == .freebsd;
    var ffi_tests_step: ?*std.Build.Step = null;

    // ─── Crypto backend selection (meshguard#102) ───
    // libsodium is an OPTIONAL accelerator (AVX2 ChaCha20-Poly1305 on Linux),
    // not a required dependency. std.crypto is the portable fallback.
    //   auto   → libsodium on Linux desktop (non-Android), std.crypto elsewhere
    //   std    → std.crypto everywhere (no libsodium link)
    //   sodium → force libsodium (link must be available for the target)
    const CryptoBackend = enum { auto, std, sodium };
    const crypto_backend_opt = b.option(CryptoBackend, "crypto-backend", "Crypto backend: auto|std|sodium (default auto)");
    // Back-compat alias: -Dno-sodium=true is equivalent to -Dcrypto-backend=std.
    const no_sodium = b.option(bool, "no-sodium", "Alias for -Dcrypto-backend=std") orelse false;

    // Fail fast on contradictory flags rather than silently letting one win.
    if (no_sodium and (crypto_backend_opt orelse .std) == .sodium) {
        std.debug.print("error: -Dno-sodium=true conflicts with -Dcrypto-backend=sodium\n" ++
            "  (-Dno-sodium is an alias for -Dcrypto-backend=std)\n", .{});
        std.process.exit(1);
    }
    const crypto_backend = crypto_backend_opt orelse .auto;

    // libsodium is only auto-selected on Linux desktop (non-Android), where the
    // vendored/system .so provides the AVX2 assembly. Everywhere else → std.crypto.
    const auto_libsodium = (resolved_os == .linux and resolved_abi != .android);
    const use_libsodium = if (no_sodium) false else switch (crypto_backend) {
        .std => false,
        .sodium => true,
        .auto => auto_libsodium,
    };

    // Exposed to source via @import("build_options") so tunnel.zig / main.zig
    // select the same backend the linker is wired for. Without this the source
    // chose the backend from builtin.os.tag alone and ignored the build option.
    const build_options = b.addOptions();
    build_options.addOption(bool, "use_libsodium", use_libsodium);
    const build_options_mod = build_options.createModule();

    // ─── FFI module (for mobile embedding — not built on Windows) ───
    if (!is_windows) {
        const ffi_mod = b.createModule(.{
            .root_source_file = b.path("src/meshguard_ffi.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .strip = if (is_android) true else null,
        });
        ffi_mod.addImport("build_options", build_options_mod);

        const ffi_lib = b.addLibrary(.{
            .name = "meshguard-ffi",
            .root_module = ffi_mod,
            // iOS requires static linking — apps cannot dlopen user dylibs.
            .linkage = if (is_ios) .static else .dynamic,
        });

        // Link libsodium only when the resolved backend uses it (Linux desktop).
        // Otherwise the Zig std.crypto software path is used (no link needed).
        if (use_libsodium) {
            ffi_mod.linkSystemLibrary("sodium", .{});
        }

        b.installArtifact(ffi_lib);

        if (!is_android and !is_ios) {
            const ffi_test_mod = b.createModule(.{
                .root_source_file = b.path("src/meshguard_ffi.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            });
            ffi_test_mod.addImport("build_options", build_options_mod);

            const ffi_tests = b.addTest(.{
                .root_module = ffi_test_mod,
            });
            if (use_libsodium) {
                ffi_test_mod.linkSystemLibrary("sodium", .{});
            }

            const run_ffi_tests = b.addRunArtifact(ffi_tests);
            ffi_tests_step = &run_ffi_tests.step;
        }
    }

    // ─── Targets below only build for native (not Android/iOS) ───
    if (!is_android and !is_ios) {
        // ─── Root modules ───
        const exe_mod = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        exe_mod.addImport("build_options", build_options_mod);

        const lib_mod = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        lib_mod.addImport("build_options", build_options_mod);

        // ─── Main executable ───
        const exe = b.addExecutable(.{
            .name = "meshguard",
            .root_module = exe_mod,
        });
        // Link libsodium only when the resolved backend uses it (Linux desktop,
        // AVX2 ChaCha20-Poly1305 assembly). std.crypto everywhere else.
        if (use_libsodium) {
            exe_mod.linkSystemLibrary("sodium", .{});
        }
        // On Windows, link ws2_32 for Winsock2 sockets
        if (is_windows) {
            exe_mod.linkSystemLibrary("ws2_32", .{});
        }
        b.installArtifact(exe);

        // On Windows, bundle wintun.dll alongside meshguard.exe
        if (is_windows) {
            b.installBinFile("deps/wintun/wintun.dll", "wintun.dll");
        }

        // ─── WG interop test binary (Linux only — requires kernel WG) ───
        if (!is_windows and !is_macos and !is_freebsd) {
            const interop_mod = b.createModule(.{
                .root_source_file = b.path("src/wg_interop.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            });
            interop_mod.addImport("build_options", build_options_mod);
            const interop_exe = b.addExecutable(.{
                .name = "wg-interop-test",
                .root_module = interop_mod,
            });
            if (use_libsodium) {
                interop_mod.linkSystemLibrary("sodium", .{});
            }
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
        test_mod.addImport("build_options", build_options_mod);

        const unit_tests = b.addTest(.{
            .root_module = test_mod,
        });
        if (use_libsodium) {
            test_mod.linkSystemLibrary("sodium", .{});
        }
        if (is_windows) {
            test_mod.linkSystemLibrary("ws2_32", .{});
        }
        const run_unit_tests = b.addRunArtifact(unit_tests);
        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_unit_tests.step);
        if (ffi_tests_step) |step| {
            test_step.dependOn(step);
        }
    }
}
