//! Seed peer resolution for mesh bootstrap.
//! TODO: Phase 2 — implement DNS TXT and mDNS discovery.

const std = @import("std");
const messages = @import("../protocol/messages.zig");

/// Resolve seed peers from various sources.
pub fn resolveSeeds(
    allocator: std.mem.Allocator,
    static_seeds: []const []const u8,
    dns_domain: []const u8,
    use_mdns: bool,
) ![]messages.Endpoint {
    var endpoints = std.ArrayList(messages.Endpoint).init(allocator);

    // Parse static seed addresses (ip:port format)
    for (static_seeds) |seed| {
        if (parseEndpoint(seed)) |ep| {
            try endpoints.append(ep);
        }
    }

    // TODO: DNS TXT record lookup
    _ = dns_domain;

    // TODO: mDNS discovery
    _ = use_mdns;

    return endpoints.toOwnedSlice();
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
