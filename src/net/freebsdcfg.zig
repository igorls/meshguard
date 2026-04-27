//! FreeBSD network interface configuration for meshguard.
//!
//! Uses ifconfig/route commands to configure cloned tun(4) interfaces.
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

pub fn setInterfaceIp(allocator: std.mem.Allocator, iface_name: []const u8, mesh_ip: [4]u8, prefix_len: u8) !void {
    var ip_buf: [15]u8 = undefined;
    const ip_str = formatIp(mesh_ip, &ip_buf);

    var mask_buf: [15]u8 = undefined;
    const mask_str = formatNetmask(prefix_len, &mask_buf);

    _ = allocator;
    const term = try runCommand(&.{ "ifconfig", iface_name, "inet", ip_str, ip_str, "netmask", mask_str });
    if (term != .exited or term.exited != 0) return error.ConfigFailed;
}

pub fn setInterfaceUp(allocator: std.mem.Allocator, iface_name: []const u8) !void {
    _ = allocator;
    const term = try runCommand(&.{ "ifconfig", iface_name, "up" });
    if (term != .exited or term.exited != 0) return error.ConfigFailed;
}

pub fn setMtu(allocator: std.mem.Allocator, iface_name: []const u8, mtu: u32) !void {
    var mtu_buf: [10]u8 = undefined;
    const mtu_str = std.fmt.bufPrint(&mtu_buf, "{d}", .{mtu}) catch return error.ConfigFailed;

    _ = allocator;
    const term = try runCommand(&.{ "ifconfig", iface_name, "mtu", mtu_str });
    if (term != .exited or term.exited != 0) return error.ConfigFailed;
}

pub fn addRoute(allocator: std.mem.Allocator, iface_name: []const u8, network: [4]u8, prefix_len: u8) !void {
    var net_buf: [18]u8 = undefined;
    var ip_buf: [15]u8 = undefined;
    const ip_str = formatIp(network, &ip_buf);
    const net_str = std.fmt.bufPrint(&net_buf, "{s}/{d}", .{ ip_str, prefix_len }) catch return error.ConfigFailed;

    _ = allocator;
    _ = try runCommand(&.{ "route", "add", "-net", net_str, "-interface", iface_name });
}

pub fn setInterfaceDown(allocator: std.mem.Allocator, iface_name: []const u8) !void {
    _ = allocator;
    _ = try runCommand(&.{ "ifconfig", iface_name, "down" });
}

fn formatIp(ip: [4]u8, buf: *[15]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "0.0.0.0";
}

fn formatNetmask(prefix_len: u8, buf: *[15]u8) []const u8 {
    const mask: u32 = if (prefix_len >= 32) 0xFFFFFFFF else (@as(u32, 0xFFFFFFFF) << @intCast(32 - @as(u6, @intCast(prefix_len))));
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        @as(u8, @truncate(mask >> 24)),
        @as(u8, @truncate(mask >> 16)),
        @as(u8, @truncate(mask >> 8)),
        @as(u8, @truncate(mask)),
    }) catch "255.255.0.0";
}
