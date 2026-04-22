//! Configuration management for meshguard.

const std = @import("std");

pub const Config = struct {

/// Returns a blocking Io instance for synchronous operations.
fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn getEnvVarOwned(allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag == .windows) {
        return std.process.Environ.getAlloc(.{ .block = .global }, allocator, key) catch |err| switch (err) {
            error.EnvironmentVariableMissing => null,
            else => |other| return other,
        };
    }

    const key_z = try allocator.dupeZ(u8, key);
    defer allocator.free(key_z);

    const value = std.c.getenv(key_z) orelse return null;
    return try allocator.dupe(u8, std.mem.span(value));
}

    // Identity
    name: []const u8 = "meshguard-node",

    // Mesh
    interface: []const u8 = "mg0",
    wg_port: u16 = 51830,
    gossip_port: u16 = 51821,
    mesh_cidr: []const u8 = "10.99.0.0/16",

    // Discovery
    seed_peers: []const []const u8 = &.{},
    seed_dns: []const u8 = "",
    mdns: bool = false,
    gossip_interval_ms: u32 = 5000,
    suspicion_timeout_ms: u32 = 30_000, // 30s — generous for WAN

    // NAT
    stun_servers: []const []const u8 = &.{
        "stun.l.google.com:19302",
        "stun.cloudflare.com:3478",
    },
    relay_enabled: bool = true,
    relay_max_peers: u16 = 10,

    // Trust
    authorized_keys_dir: []const u8 = "./authorized_keys/",
    watch_interval_s: u32 = 30,

    /// Get the default config directory path.
    /// - If MESHGUARD_CONFIG_DIR is set, use that.
    /// - Windows: %APPDATA%\meshguard
    /// - Linux as root (uid 0): /etc/meshguard/  (system-wide, for systemd)
    /// - Linux otherwise: ~/.config/meshguard/  (per-user)
    pub fn defaultConfigDir(allocator: std.mem.Allocator) ![]const u8 {
        // Check for override env var (cross-platform)
        if (try getEnvVarOwned(allocator, "MESHGUARD_CONFIG_DIR")) |dir| {
            return dir;
        }

        const builtin = @import("builtin");
        if (comptime builtin.os.tag == .windows) {
            // Windows: %APPDATA%\meshguard (e.g. C:\Users\user\AppData\Roaming\meshguard)
            if (try getEnvVarOwned(allocator, "APPDATA")) |appdata| {
                defer allocator.free(appdata);
                return std.fs.path.join(allocator, &.{ appdata, "meshguard" });
            }
            // Fallback to USERPROFILE
            if (try getEnvVarOwned(allocator, "USERPROFILE")) |home| {
                defer allocator.free(home);
                return std.fs.path.join(allocator, &.{ home, ".meshguard" });
            }
            return error.HomeNotFound;
        }

        // System-wide config when running as root (systemd, sudo, launchd)
        // Use POSIX getuid() — works on Linux, macOS, and other POSIX systems
        const uid = std.posix.system.getuid();
        if (uid == 0) {
            return allocator.dupe(u8, "/etc/meshguard");
        }

        if (try getEnvVarOwned(allocator, "XDG_CONFIG_HOME")) |xdg| {
            defer allocator.free(xdg);
            return std.fs.path.join(allocator, &.{ xdg, "meshguard" });
        }

        if (try getEnvVarOwned(allocator, "HOME")) |home| {
            defer allocator.free(home);
            return std.fs.path.join(allocator, &.{ home, ".config", "meshguard" });
        }

        return error.HomeNotFound;
    }


    /// Ensure the config directory exists and return its path.
    pub fn ensureConfigDir(allocator: std.mem.Allocator) ![]const u8 {
        const dir = try defaultConfigDir(allocator);
        std.Io.Dir.cwd().createDirPath(zio(), dir) catch |err| {
            if (err != error.PathAlreadyExists) {
                // Try creating parent directories
                const parent = std.fs.path.dirname(dir) orelse return err;
                std.Io.Dir.cwd().createDirPath(zio(), parent) catch |e| {
                    if (e != error.PathAlreadyExists) return e;
                };
                std.Io.Dir.cwd().createDirPath(zio(), dir) catch |e| {
                    if (e != error.PathAlreadyExists) return e;
                };
            }
        };
        return dir;
    }
};
