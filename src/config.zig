//! Configuration management for meshguard.

const std = @import("std");

pub const Config = struct {
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

    /// Get the default config directory path: ~/.config/meshguard/
    pub fn defaultConfigDir(allocator: std.mem.Allocator) ![]const u8 {
        if (std.posix.getenv("MESHGUARD_CONFIG_DIR")) |dir| {
            return allocator.dupe(u8, dir);
        }

        if (std.posix.getenv("XDG_CONFIG_HOME")) |xdg| {
            return std.fs.path.join(allocator, &.{ xdg, "meshguard" });
        }

        if (std.posix.getenv("HOME")) |home| {
            return std.fs.path.join(allocator, &.{ home, ".config", "meshguard" });
        }

        return error.HomeNotFound;
    }

    /// Ensure the config directory exists and return its path.
    pub fn ensureConfigDir(allocator: std.mem.Allocator) ![]const u8 {
        const dir = try defaultConfigDir(allocator);
        std.fs.makeDirAbsolute(dir) catch |err| {
            if (err != error.PathAlreadyExists) {
                // Try creating parent directories
                const parent = std.fs.path.dirname(dir) orelse return err;
                std.fs.makeDirAbsolute(parent) catch |e| {
                    if (e != error.PathAlreadyExists) return e;
                };
                std.fs.makeDirAbsolute(dir) catch |e| {
                    if (e != error.PathAlreadyExists) return e;
                };
            }
        };
        return dir;
    }
};
