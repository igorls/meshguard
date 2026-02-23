//! Seed peer resolution for mesh bootstrap.
//!
//! Supports three discovery methods:
//!   1. Static seeds: `--seed ip:port` or `--seed hostname:port`
//!   2. DNS TXT records: `--dns domain` → queries `_meshguard._udp.domain`
//!   3. mDNS LAN discovery: `--mdns` → multicast query for `_meshguard._udp.local`

const std = @import("std");
const messages = @import("../protocol/messages.zig");
const dns = @import("../net/dns.zig");

/// Resolve seed peers from all configured sources.
pub fn resolveSeeds(
    allocator: std.mem.Allocator,
    static_seeds: []const []const u8,
    dns_domain: []const u8,
    use_mdns: bool,
) ![]messages.Endpoint {
    var endpoints: std.ArrayList(messages.Endpoint) = .empty;

    // 1. Parse static seed addresses (ip:port or hostname:port)
    for (static_seeds) |seed| {
        if (parseEndpoint(seed)) |ep| {
            try endpoints.append(allocator, ep);
        } else if (resolveHostSeed(seed)) |ep| {
            try endpoints.append(allocator, ep);
        }
    }

    // 2. DNS TXT record lookup
    if (dns_domain.len > 0) {
        // Query _meshguard._udp.{domain} for TXT records
        var srv_name_buf: [256]u8 = undefined;
        const srv_name = std.fmt.bufPrint(&srv_name_buf, "_meshguard._udp.{s}", .{dns_domain}) catch dns_domain;

        const txt_records = dns.queryTXT(allocator, srv_name) catch &.{};
        defer {
            for (txt_records) |txt| allocator.free(txt);
            if (txt_records.len > 0) allocator.free(txt_records);
        }

        for (txt_records) |txt| {
            if (dns.parseMeshguardTXT(txt)) |parsed| {
                try endpoints.append(allocator, .{ .addr = parsed.addr, .port = parsed.port });
            }
        }
    }

    // 3. mDNS LAN discovery
    if (use_mdns) {
        const mdns_records = dns.queryMDNS(allocator, "_meshguard._udp.local") catch &.{};
        defer {
            for (mdns_records) |txt| allocator.free(txt);
            if (mdns_records.len > 0) allocator.free(mdns_records);
        }

        for (mdns_records) |txt| {
            if (dns.parseMeshguardTXT(txt)) |parsed| {
                try endpoints.append(allocator, .{ .addr = parsed.addr, .port = parsed.port });
            }
        }
    }

    return endpoints.toOwnedSlice(allocator);
}

/// Parse an "ip:port" string into an Endpoint.
pub fn parseEndpoint(s: []const u8) ?messages.Endpoint {
    const colon_idx = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    const ip_str = s[0..colon_idx];
    const port_str = s[colon_idx + 1 ..];

    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;

    // Parse IPv4 dotted-quad
    var addr: [4]u8 = undefined;
    var octets = std.mem.splitScalar(u8, ip_str, '.');
    var i: usize = 0;
    while (octets.next()) |octet| {
        if (i >= 4) return null;
        addr[i] = std.fmt.parseInt(u8, octet, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;

    return .{ .addr = addr, .port = port };
}

/// Resolve a "hostname:port" seed by looking up the hostname via DNS A record.
fn resolveHostSeed(s: []const u8) ?messages.Endpoint {
    const colon_idx = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    const hostname = s[0..colon_idx];
    const port_str = s[colon_idx + 1 ..];

    // Must have a non-numeric hostname (IP-based seeds go through parseEndpoint)
    if (hostname.len == 0) return null;
    // Quick check: if all chars are digits or dots, it's an IP (already tried in parseEndpoint)
    var is_ip = true;
    for (hostname) |c| {
        if (c != '.' and (c < '0' or c > '9')) {
            is_ip = false;
            break;
        }
    }
    if (is_ip) return null;

    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
    const addr = dns.resolveA(hostname) orelse return null;

    return .{ .addr = addr, .port = port };
}

test "parse endpoint" {
    const ep = parseEndpoint("1.2.3.4:51821").?;
    try std.testing.expectEqual(ep.addr, [4]u8{ 1, 2, 3, 4 });
    try std.testing.expectEqual(ep.port, 51821);
}

test "parse invalid endpoint" {
    try std.testing.expect(parseEndpoint("not-an-ip") == null);
    try std.testing.expect(parseEndpoint("1.2.3.4") == null);
    try std.testing.expect(parseEndpoint("") == null);
}

test "resolve host seed with numeric IP falls through" {
    // Numeric IPs should return null (handled by parseEndpoint instead)
    try std.testing.expect(resolveHostSeed("1.2.3.4:51821") == null);
}
