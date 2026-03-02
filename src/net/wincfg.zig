//! Windows network interface configuration for meshguard.
//!
//! Configures the Wintun adapter (IP address, routes, MTU) via netsh commands.
//! This is the Windows equivalent of Linux rtnetlink operations.

const std = @import("std");

/// Set a static IP address on a named network adapter.
/// Equivalent of Linux: ip addr add {ip}/{prefix} dev {name}
pub fn setAdapterIp(allocator: std.mem.Allocator, name: []const u8, ip: [4]u8, prefix: u8) !void {
    // Calculate subnet mask from prefix length
    var mask_buf: [16]u8 = undefined;
    const mask = prefixToMask(prefix);
    const mask_str = std.fmt.bufPrint(&mask_buf, "{d}.{d}.{d}.{d}", .{
        mask[0], mask[1], mask[2], mask[3],
    }) catch return error.FormatFailed;

    var ip_buf: [16]u8 = undefined;
    const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
        ip[0], ip[1], ip[2], ip[3],
    }) catch return error.FormatFailed;

    // netsh interface ip set address "name" static ip mask
    const argv = [_][]const u8{
        "netsh", "interface", "ip", "set", "address",
        name, "static", ip_str, mask_str,
    };
    try runCommand(allocator, &argv);
}

/// Add a route to the mesh subnet via the named adapter.
/// Equivalent of Linux: ip route add {dest}/{prefix} dev {name}
pub fn addRoute(allocator: std.mem.Allocator, name: []const u8, dest: [4]u8, prefix: u8) !void {
    var dest_buf: [20]u8 = undefined;
    const dest_str = std.fmt.bufPrint(&dest_buf, "{d}.{d}.{d}.{d}/{d}", .{
        dest[0], dest[1], dest[2], dest[3], prefix,
    }) catch return error.FormatFailed;

    // netsh interface ipv4 add route dest/prefix "name"
    const argv = [_][]const u8{
        "netsh", "interface", "ipv4", "add", "route",
        dest_str, name,
    };
    // Route might already exist — that's OK
    runCommand(allocator, &argv) catch {};
}

/// Set the MTU on a named network interface.
/// Equivalent of Linux: ip link set dev {name} mtu {mtu}
pub fn setMtu(allocator: std.mem.Allocator, name: []const u8, mtu: u32) !void {
    var mtu_buf: [16]u8 = undefined;
    const mtu_str = std.fmt.bufPrint(&mtu_buf, "mtu={d}", .{mtu}) catch return error.FormatFailed;

    // netsh interface ipv4 set subinterface "name" mtu=1420
    const argv = [_][]const u8{
        "netsh", "interface", "ipv4", "set", "subinterface",
        name, mtu_str,
    };
    try runCommand(allocator, &argv);
}

// ─── Helpers ───

fn runCommand(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    var child = std.process.Child.init(argv, allocator);
    child.spawn() catch return error.CommandFailed;
    const term = child.wait() catch return error.CommandFailed;
    if (term.Exited != 0) return error.CommandFailed;
}

fn prefixToMask(prefix: u8) [4]u8 {
    if (prefix >= 32) return .{ 255, 255, 255, 255 };
    const mask: u32 = if (prefix == 0) 0 else (~@as(u32, 0)) << @intCast(32 - prefix);
    return .{
        @intCast((mask >> 24) & 0xFF),
        @intCast((mask >> 16) & 0xFF),
        @intCast((mask >> 8) & 0xFF),
        @intCast(mask & 0xFF),
    };
}
