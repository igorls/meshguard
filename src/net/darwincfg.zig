///! macOS network interface configuration for meshguard.
///!
///! Uses ifconfig/route shell commands via std.process.Child to configure
///! utun interfaces. Analogous to wincfg.zig for Windows.
const std = @import("std");

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn runCommand(argv: []const []const u8) !std.process.Child.Term {
    var child = try std.process.spawn(zio(), .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(zio());
    return child.wait(zio());
}

/// Set the IP address on a utun interface.
/// Runs: ifconfig <iface> inet <ip> <ip> netmask 255.255.0.0
pub fn setInterfaceIp(allocator: std.mem.Allocator, iface_name: []const u8, mesh_ip: [4]u8, prefix_len: u8) !void {
    var ip_buf: [15]u8 = undefined;
    const ip_str = formatIp(mesh_ip, &ip_buf);

    var mask_buf: [15]u8 = undefined;
    const mask_str = formatNetmask(prefix_len, &mask_buf);

    _ = allocator;
    const term = try runCommand(&.{ "ifconfig", iface_name, "inet", ip_str, ip_str, "netmask", mask_str });
    if (term != .exited or term.exited != 0) return error.ConfigFailed;
}

/// Bring the interface up.
/// Runs: ifconfig <iface> up
pub fn setInterfaceUp(allocator: std.mem.Allocator, iface_name: []const u8) !void {
    _ = allocator;
    const term = try runCommand(&.{ "ifconfig", iface_name, "up" });
    if (term != .exited or term.exited != 0) return error.ConfigFailed;
}

/// Set the MTU on an interface.
/// Runs: ifconfig <iface> mtu <mtu>
pub fn setMtu(allocator: std.mem.Allocator, iface_name: []const u8, mtu: u32) !void {
    var mtu_buf: [10]u8 = undefined;
    const mtu_str = std.fmt.bufPrint(&mtu_buf, "{d}", .{mtu}) catch return error.ConfigFailed;

    _ = allocator;
    const term = try runCommand(&.{ "ifconfig", iface_name, "mtu", mtu_str });
    if (term != .exited or term.exited != 0) return error.ConfigFailed;
}

/// Add a route for the mesh subnet via the interface.
/// Runs: route add -net <network>/<prefix> -interface <iface>
pub fn addRoute(allocator: std.mem.Allocator, iface_name: []const u8, network: [4]u8, prefix_len: u8) !void {
    var net_buf: [18]u8 = undefined; // "255.255.255.255/32"
    var ip_buf: [15]u8 = undefined;
    const ip_str = formatIp(network, &ip_buf);
    const net_str = std.fmt.bufPrint(&net_buf, "{s}/{d}", .{ ip_str, prefix_len }) catch return error.ConfigFailed;

    _ = allocator;
    const term = try runCommand(&.{ "route", "add", "-net", net_str, "-interface", iface_name });
    // Route may already exist — don't fail
    _ = term;
}

/// Bring the interface down.
/// Runs: ifconfig <iface> down
pub fn setInterfaceDown(allocator: std.mem.Allocator, iface_name: []const u8) !void {
    _ = allocator;
    _ = try runCommand(&.{ "ifconfig", iface_name, "down" });
}

// ─── Helpers ───

fn formatIp(ip: [4]u8, buf: *[15]u8) []const u8 {
    const result = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch return "0.0.0.0";
    return result;
}

fn formatNetmask(prefix_len: u8, buf: *[15]u8) []const u8 {
    const mask: u32 = if (prefix_len >= 32) 0xFFFFFFFF else (@as(u32, 0xFFFFFFFF) << @intCast(32 - @as(u6, @intCast(prefix_len))));
    const result = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        @as(u8, @truncate(mask >> 24)),
        @as(u8, @truncate(mask >> 16)),
        @as(u8, @truncate(mask >> 8)),
        @as(u8, @truncate(mask)),
    }) catch return "255.255.0.0";
    return result;
}
