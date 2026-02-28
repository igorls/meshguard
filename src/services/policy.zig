//! Service access control — port-level allow/deny filtering per peer, org, or global.
//!
//! Policy files live in `$CONFIG_DIR/services/` alongside `authorized_keys/`.
//! Evaluation order: peer-specific → org-specific → global → default.
//!
//! File format (one rule per line):
//!   allow tcp 22
//!   allow tcp 8080-8089
//!   deny udp all
//!   deny all
//!   # comments and blank lines are ignored

const std = @import("std");

// ─── Rule types ───

pub const Action = enum(u1) { allow = 0, deny = 1 };

pub const Proto = enum(u2) {
    tcp = 0,
    udp = 1,
    all = 2, // matches both tcp and udp
};

pub const Rule = struct {
    action: Action,
    proto: Proto,
    port_min: u16, // 0 = "all ports"
    port_max: u16, // 0 = "all ports" (when both min and max are 0)

    /// Check if this rule matches the given protocol and port.
    pub fn matches(self: Rule, proto: Proto, port: u16) bool {
        // Protocol check: rule.proto == all matches everything,
        // otherwise must match exactly
        if (self.proto != .all and self.proto != proto) return false;

        // Port check: 0/0 means "all ports"
        if (self.port_min == 0 and self.port_max == 0) return true;

        return port >= self.port_min and port <= self.port_max;
    }
};

// ─── Policy (fixed-size rule set) ───

pub const MAX_RULES: usize = 64;

pub const Policy = struct {
    rules: [MAX_RULES]Rule = undefined,
    count: u8 = 0,

    /// Evaluate this policy. Returns the action of the first matching rule,
    /// or null if no rule matches (fall through to next policy level).
    pub fn evaluate(self: *const Policy, proto: Proto, port: u16) ?Action {
        for (self.rules[0..self.count]) |rule| {
            if (rule.matches(proto, port)) return rule.action;
        }
        return null; // no match — fall through
    }
};

// ─── Policy parsing ───

pub const ParseError = error{
    InvalidAction,
    InvalidProto,
    InvalidPort,
    TooManyRules,
};

/// Parse a single rule line like "allow tcp 22" or "deny all".
/// Returns null for comments and blank lines.
pub fn parseRule(line: []const u8) ParseError!?Rule {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return null;
    if (trimmed[0] == '#') return null;

    var it = std.mem.tokenizeAny(u8, trimmed, " \t");

    // Action
    const action_str = it.next() orelse return null;
    const action: Action = if (std.mem.eql(u8, action_str, "allow"))
        .allow
    else if (std.mem.eql(u8, action_str, "deny"))
        .deny
    else
        return ParseError.InvalidAction;

    // Proto or "all" shorthand (deny all = deny all all)
    const proto_str = it.next() orelse return ParseError.InvalidProto;

    // Shorthand: "deny all" or "allow all" — matches everything
    if (std.mem.eql(u8, proto_str, "all") and it.peek() == null) {
        return Rule{
            .action = action,
            .proto = .all,
            .port_min = 0,
            .port_max = 0,
        };
    }

    const proto: Proto = if (std.mem.eql(u8, proto_str, "tcp"))
        .tcp
    else if (std.mem.eql(u8, proto_str, "udp"))
        .udp
    else if (std.mem.eql(u8, proto_str, "all"))
        .all
    else
        return ParseError.InvalidProto;

    // Port spec
    const port_str = it.next() orelse return ParseError.InvalidPort;

    // "all" keyword for ports
    if (std.mem.eql(u8, port_str, "all")) {
        return Rule{
            .action = action,
            .proto = proto,
            .port_min = 0,
            .port_max = 0,
        };
    }

    // Check for range: "8080-8089"
    if (std.mem.indexOfScalar(u8, port_str, '-')) |dash_pos| {
        const min_str = port_str[0..dash_pos];
        const max_str = port_str[dash_pos + 1 ..];
        const min = std.fmt.parseInt(u16, min_str, 10) catch return ParseError.InvalidPort;
        const max = std.fmt.parseInt(u16, max_str, 10) catch return ParseError.InvalidPort;
        if (min > max) return ParseError.InvalidPort;
        return Rule{
            .action = action,
            .proto = proto,
            .port_min = min,
            .port_max = max,
        };
    }

    // Single port
    const port = std.fmt.parseInt(u16, port_str, 10) catch return ParseError.InvalidPort;
    return Rule{
        .action = action,
        .proto = proto,
        .port_min = port,
        .port_max = port,
    };
}

/// Parse a full policy file content into a Policy struct.
pub fn parsePolicy(content: []const u8) ParseError!Policy {
    var policy = Policy{};
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (try parseRule(line)) |rule| {
            if (policy.count >= MAX_RULES) return ParseError.TooManyRules;
            policy.rules[policy.count] = rule;
            policy.count += 1;
        }
    }
    return policy;
}

// ─── ServiceFilter — the main filter engine ───

pub const MAX_PEER_POLICIES: usize = 64;
pub const MAX_ORG_POLICIES: usize = 16;

const PeerPolicy = struct {
    pubkey: [32]u8,
    policy: Policy,
};

const OrgPolicy = struct {
    org_pubkey: [32]u8,
    policy: Policy,
};

pub const ServiceFilter = struct {
    default_action: Action = .allow,
    global: ?Policy = null,

    peer_policies: [MAX_PEER_POLICIES]PeerPolicy = undefined,
    peer_count: u8 = 0,

    org_policies: [MAX_ORG_POLICIES]OrgPolicy = undefined,
    org_count: u8 = 0,

    /// Check if a packet should be allowed through.
    ///
    /// Evaluation chain:
    ///   1. Peer-specific policy (by pubkey)
    ///   2. Org-specific policy (by peer's org pubkey)
    ///   3. Global policy
    ///   4. Default action
    pub fn check(
        self: *const ServiceFilter,
        peer_pubkey: [32]u8,
        peer_org_pubkey: ?[32]u8,
        proto: Proto,
        dst_port: u16,
    ) bool {
        // 1. Peer-specific
        for (self.peer_policies[0..self.peer_count]) |pp| {
            if (std.mem.eql(u8, &pp.pubkey, &peer_pubkey)) {
                if (pp.policy.evaluate(proto, dst_port)) |action| {
                    return action == .allow;
                }
                break; // peer policy exists but no match — fall through
            }
        }

        // 2. Org-specific
        if (peer_org_pubkey) |org_pk| {
            for (self.org_policies[0..self.org_count]) |op| {
                if (std.mem.eql(u8, &op.org_pubkey, &org_pk)) {
                    if (op.policy.evaluate(proto, dst_port)) |action| {
                        return action == .allow;
                    }
                    break; // org policy exists but no match — fall through
                }
            }
        }

        // 3. Global
        if (self.global) |*global| {
            if (global.evaluate(proto, dst_port)) |action| {
                return action == .allow;
            }
        }

        // 4. Default
        return self.default_action == .allow;
    }

    /// Load all service policies from the config directory.
    /// Expects: config_dir/services/{default, global.policy, peer/*.policy, org/*.policy}
    /// If the services/ directory doesn't exist, returns a default allow-all filter.
    pub fn loadFromDir(config_dir: []const u8) ServiceFilter {
        var filter = ServiceFilter{};

        // Build services path: config_dir + "/services"
        var services_path_buf: [512]u8 = undefined;
        const services_path = std.fmt.bufPrint(&services_path_buf, "{s}/services", .{config_dir}) catch return filter;

        // Check if services/ directory exists
        std.fs.accessAbsolute(services_path, .{}) catch return filter; // no dir = allow-all

        // Load default action
        var default_path_buf: [512]u8 = undefined;
        const default_path = std.fmt.bufPrint(&default_path_buf, "{s}/default", .{services_path}) catch return filter;
        if (readSmallFile(default_path)) |content| {
            const trimmed = std.mem.trim(u8, content.slice(), " \t\r\n");
            if (std.mem.eql(u8, trimmed, "deny")) {
                filter.default_action = .deny;
            }
        }

        // Load global policy
        var global_path_buf: [512]u8 = undefined;
        const global_path = std.fmt.bufPrint(&global_path_buf, "{s}/global.policy", .{services_path}) catch return filter;
        if (readSmallFile(global_path)) |content| {
            filter.global = parsePolicy(content.slice()) catch null;
        }

        // Load peer policies
        var peer_dir_buf: [512]u8 = undefined;
        const peer_dir_path = std.fmt.bufPrint(&peer_dir_buf, "{s}/peer", .{services_path}) catch return filter;
        filter.loadPeerPolicies(peer_dir_path);

        // Load org policies
        var org_dir_buf: [512]u8 = undefined;
        const org_dir_path = std.fmt.bufPrint(&org_dir_buf, "{s}/org", .{services_path}) catch return filter;
        filter.loadOrgPolicies(org_dir_path);

        return filter;
    }

    fn loadPeerPolicies(self: *ServiceFilter, dir_path: []const u8) void {
        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".policy")) continue;
            if (self.peer_count >= MAX_PEER_POLICIES) break;

            // Read policy file
            var file_path_buf: [512]u8 = undefined;
            const file_path = std.fmt.bufPrint(&file_path_buf, "{s}/{s}", .{ dir_path, entry.name }) catch continue;
            const content = readSmallFile(file_path) orelse continue;
            const policy = parsePolicy(content.slice()) catch continue;

            // Extract name (strip .policy extension)
            const name = entry.name[0 .. entry.name.len - 7];

            // Try to decode as base64 pubkey (44 chars)
            if (name.len == 44) {
                var pubkey: [32]u8 = undefined;
                if (std.base64.standard.Decoder.decode(&pubkey, name) catch null) |_| {
                    // This is unused, the decode writes to pubkey directly
                }
                // Try base64 decode — if it works, use as pubkey
                const decoded = std.base64.standard.Decoder.decode(&pubkey, name) catch {
                    // Not valid base64 — treat as alias (handled via authorized_keys lookup)
                    // For now, skip non-base64 peer policies (alias resolution requires allocator)
                    continue;
                };
                _ = decoded;
                self.peer_policies[self.peer_count] = .{
                    .pubkey = pubkey,
                    .policy = policy,
                };
                self.peer_count += 1;
            }
            // Alias-based peer policies would require looking up the pubkey from
            // authorized_keys/<alias>.pub — done at a higher level during init
        }
    }

    fn loadOrgPolicies(self: *ServiceFilter, dir_path: []const u8) void {
        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".policy")) continue;
            if (self.org_count >= MAX_ORG_POLICIES) break;

            var file_path_buf: [512]u8 = undefined;
            const file_path = std.fmt.bufPrint(&file_path_buf, "{s}/{s}", .{ dir_path, entry.name }) catch continue;
            const content = readSmallFile(file_path) orelse continue;
            const policy = parsePolicy(content.slice()) catch continue;

            // Org policy filename = org name. We need the org pubkey.
            // Load from trusted_orgs/<name>.org which contains the base64 pubkey.
            // For now, the org name is the filename stem — the caller maps name→pubkey
            // by loading trusted_orgs/ at startup.
            //
            // We store the name hash temporarily; the caller resolves it.
            // Alternative: use base64 pubkey as filename (same as peer policies).
            const org_name = entry.name[0 .. entry.name.len - 7];

            // Try base64 decode first (if 44 chars)
            if (org_name.len == 44) {
                var org_pubkey: [32]u8 = undefined;
                _ = std.base64.standard.Decoder.decode(&org_pubkey, org_name) catch continue;
                self.org_policies[self.org_count] = .{
                    .org_pubkey = org_pubkey,
                    .policy = policy,
                };
                self.org_count += 1;
            }
        }
    }

    /// Resolve alias-based peer policies using the authorized_keys directory.
    /// Call after loadFromDir to convert peer/<alias>.policy files to pubkey-indexed entries.
    pub fn resolveAliases(self: *ServiceFilter, config_dir: []const u8) void {
        // Re-scan the peer policy directory looking for non-base64 names
        var peer_dir_buf: [512]u8 = undefined;
        const peer_dir_path = std.fmt.bufPrint(&peer_dir_buf, "{s}/services/peer", .{config_dir}) catch return;

        var dir = std.fs.openDirAbsolute(peer_dir_path, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".policy")) continue;
            if (self.peer_count >= MAX_PEER_POLICIES) break;

            const name = entry.name[0 .. entry.name.len - 7];

            // Skip base64 names (already loaded)
            if (name.len == 44) {
                var tmp: [32]u8 = undefined;
                if ((std.base64.standard.Decoder.decode(&tmp, name) catch null) != null) continue;
            }

            // This is an alias — look up pubkey from authorized_keys/<name>.pub
            var ak_path_buf: [512]u8 = undefined;
            const ak_path = std.fmt.bufPrint(&ak_path_buf, "{s}/authorized_keys/{s}.pub", .{ config_dir, name }) catch continue;
            const ak_content = readSmallFile(ak_path) orelse continue;
            const trimmed = std.mem.trim(u8, ak_content.slice(), " \t\r\n");

            var pubkey: [32]u8 = undefined;
            _ = std.base64.standard.Decoder.decode(&pubkey, trimmed) catch continue;

            // Read and parse the policy file
            var file_path_buf: [512]u8 = undefined;
            const file_path = std.fmt.bufPrint(&file_path_buf, "{s}/{s}", .{ peer_dir_path, entry.name }) catch continue;
            const content = readSmallFile(file_path) orelse continue;
            const policy = parsePolicy(content.slice()) catch continue;

            self.peer_policies[self.peer_count] = .{
                .pubkey = pubkey,
                .policy = policy,
            };
            self.peer_count += 1;
        }
    }

    /// Resolve org policies by name (maps org name to pubkey via trusted_orgs/).
    pub fn resolveOrgNames(self: *ServiceFilter, config_dir: []const u8) void {
        var org_dir_buf: [512]u8 = undefined;
        const org_policy_dir = std.fmt.bufPrint(&org_dir_buf, "{s}/services/org", .{config_dir}) catch return;

        var dir = std.fs.openDirAbsolute(org_policy_dir, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".policy")) continue;
            if (self.org_count >= MAX_ORG_POLICIES) break;

            const org_name = entry.name[0 .. entry.name.len - 7];

            // Skip base64 names (already loaded)
            if (org_name.len == 44) {
                var tmp: [32]u8 = undefined;
                if ((std.base64.standard.Decoder.decode(&tmp, org_name) catch null) != null) continue;
            }

            // Look up org pubkey from trusted_orgs/<name>.org
            var to_path_buf: [512]u8 = undefined;
            const to_path = std.fmt.bufPrint(&to_path_buf, "{s}/trusted_orgs/{s}.org", .{ config_dir, org_name }) catch continue;
            const to_content = readSmallFile(to_path) orelse continue;
            const trimmed = std.mem.trim(u8, to_content.slice(), " \t\r\n");

            var org_pubkey: [32]u8 = undefined;
            _ = std.base64.standard.Decoder.decode(&org_pubkey, trimmed) catch continue;

            var file_path_buf: [512]u8 = undefined;
            const file_path = std.fmt.bufPrint(&file_path_buf, "{s}/{s}", .{ org_policy_dir, entry.name }) catch continue;
            const content = readSmallFile(file_path) orelse continue;
            const policy = parsePolicy(content.slice()) catch continue;

            self.org_policies[self.org_count] = .{
                .org_pubkey = org_pubkey,
                .policy = policy,
            };
            self.org_count += 1;
        }
    }
};

// ─── IP header parsing (for the filter hot path) ───

pub const TransportInfo = struct {
    proto: Proto,
    dst_port: u16,
};

/// Extract protocol and destination port from a decrypted IPv4 packet.
/// Returns null for non-TCP/UDP packets (ICMP, etc.) — they pass unfiltered.
pub fn parseTransportHeader(ip_packet: []const u8) ?TransportInfo {
    if (ip_packet.len < 20) return null;

    // IPv4 header: IHL = lower nibble of byte 0, in 32-bit words
    const ihl: usize = @as(usize, ip_packet[0] & 0x0F) * 4;
    const protocol = ip_packet[9];

    // Only filter TCP (6) and UDP (17)
    const proto: Proto = switch (protocol) {
        6 => .tcp,
        17 => .udp,
        else => return null, // ICMP, IGMP, etc. — pass unfiltered
    };

    // TCP/UDP header: dst_port at byte offset 2 (big-endian u16)
    if (ip_packet.len < ihl + 4) return null;
    const dst_port = std.mem.readInt(u16, ip_packet[ihl + 2 ..][0..2], .big);

    return .{ .proto = proto, .dst_port = dst_port };
}

// ─── Small file reader (no allocator) ───

const SmallFile = struct {
    buf: [4096]u8,
    len: usize,

    pub fn slice(self: *const SmallFile) []const u8 {
        return self.buf[0..self.len];
    }
};

fn readSmallFile(path: []const u8) ?SmallFile {
    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();
    var result = SmallFile{ .buf = undefined, .len = 0 };
    result.len = file.readAll(&result.buf) catch return null;
    return result;
}

// ─── Tests ───

test "parseRule: basic rules" {
    const r1 = (try parseRule("allow tcp 22")).?;
    try std.testing.expectEqual(r1.action, .allow);
    try std.testing.expectEqual(r1.proto, .tcp);
    try std.testing.expectEqual(r1.port_min, 22);
    try std.testing.expectEqual(r1.port_max, 22);

    const r2 = (try parseRule("deny udp 53")).?;
    try std.testing.expectEqual(r2.action, .deny);
    try std.testing.expectEqual(r2.proto, .udp);

    const r3 = (try parseRule("allow tcp 8080-8089")).?;
    try std.testing.expectEqual(r3.port_min, 8080);
    try std.testing.expectEqual(r3.port_max, 8089);
}

test "parseRule: deny all shorthand" {
    const r = (try parseRule("deny all")).?;
    try std.testing.expectEqual(r.action, .deny);
    try std.testing.expectEqual(r.proto, .all);
    try std.testing.expectEqual(r.port_min, 0);
    try std.testing.expectEqual(r.port_max, 0);
}

test "parseRule: comments and blanks" {
    try std.testing.expectEqual(try parseRule("# this is a comment"), null);
    try std.testing.expectEqual(try parseRule("   "), null);
    try std.testing.expectEqual(try parseRule(""), null);
}

test "parseRule: all proto with port" {
    const r = (try parseRule("allow all 443")).?;
    try std.testing.expectEqual(r.proto, .all);
    try std.testing.expectEqual(r.port_min, 443);
    try std.testing.expectEqual(r.port_max, 443);
}

test "Rule.matches" {
    const rule_tcp_22 = Rule{ .action = .allow, .proto = .tcp, .port_min = 22, .port_max = 22 };
    try std.testing.expect(rule_tcp_22.matches(.tcp, 22));
    try std.testing.expect(!rule_tcp_22.matches(.tcp, 80));
    try std.testing.expect(!rule_tcp_22.matches(.udp, 22));

    const rule_range = Rule{ .action = .allow, .proto = .tcp, .port_min = 8080, .port_max = 8089 };
    try std.testing.expect(rule_range.matches(.tcp, 8080));
    try std.testing.expect(rule_range.matches(.tcp, 8085));
    try std.testing.expect(rule_range.matches(.tcp, 8089));
    try std.testing.expect(!rule_range.matches(.tcp, 8090));
    try std.testing.expect(!rule_range.matches(.tcp, 8079));

    const rule_all = Rule{ .action = .deny, .proto = .all, .port_min = 0, .port_max = 0 };
    try std.testing.expect(rule_all.matches(.tcp, 22));
    try std.testing.expect(rule_all.matches(.udp, 53));
    try std.testing.expect(rule_all.matches(.tcp, 443));
}

test "Policy.evaluate: allowlist pattern" {
    const policy = try parsePolicy(
        \\allow tcp 22
        \\allow tcp 443
        \\deny all
    );

    // Allowed ports
    try std.testing.expectEqual(policy.evaluate(.tcp, 22), .allow);
    try std.testing.expectEqual(policy.evaluate(.tcp, 443), .allow);

    // Denied by catch-all
    try std.testing.expectEqual(policy.evaluate(.tcp, 80), .deny);
    try std.testing.expectEqual(policy.evaluate(.udp, 53), .deny);
}

test "Policy.evaluate: no match returns null" {
    const policy = try parsePolicy(
        \\allow tcp 22
    );

    try std.testing.expectEqual(policy.evaluate(.tcp, 22), .allow);
    try std.testing.expectEqual(policy.evaluate(.tcp, 80), null); // no match
}

test "ServiceFilter.check: evaluation chain" {
    var filter = ServiceFilter{};
    filter.default_action = .deny;

    // Global: allow SSH
    filter.global = try parsePolicy(
        \\allow tcp 22
        \\deny all
    );

    const peer_pubkey = [_]u8{0xAA} ** 32;
    const other_pubkey = [_]u8{0xBB} ** 32;

    // Peer-specific: allow SSH + Postgres
    filter.peer_policies[0] = .{
        .pubkey = peer_pubkey,
        .policy = try parsePolicy(
            \\allow tcp 22
            \\allow tcp 5432
            \\deny all
        ),
    };
    filter.peer_count = 1;

    // Peer AA: SSH allowed (peer policy)
    try std.testing.expect(filter.check(peer_pubkey, null, .tcp, 22));
    // Peer AA: Postgres allowed (peer policy)
    try std.testing.expect(filter.check(peer_pubkey, null, .tcp, 5432));
    // Peer AA: HTTP denied (peer deny all)
    try std.testing.expect(!filter.check(peer_pubkey, null, .tcp, 80));

    // Peer BB: SSH allowed (global)
    try std.testing.expect(filter.check(other_pubkey, null, .tcp, 22));
    // Peer BB: Postgres denied (global deny all)
    try std.testing.expect(!filter.check(other_pubkey, null, .tcp, 5432));
}

test "ServiceFilter.check: default allow-all when no policies" {
    const filter = ServiceFilter{};
    const pk = [_]u8{0x42} ** 32;

    try std.testing.expect(filter.check(pk, null, .tcp, 22));
    try std.testing.expect(filter.check(pk, null, .tcp, 5432));
    try std.testing.expect(filter.check(pk, null, .udp, 53));
}

test "parseTransportHeader: TCP" {
    // Minimal IPv4 TCP packet (20B IP + 20B TCP)
    var pkt = std.mem.zeroes([40]u8);
    pkt[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    pkt[9] = 6; // TCP
    // TCP dst_port at offset 22 (IHL=20, dst_port at +2), big-endian
    std.mem.writeInt(u16, pkt[22..24], 443, .big);

    const info = parseTransportHeader(&pkt).?;
    try std.testing.expectEqual(info.proto, .tcp);
    try std.testing.expectEqual(info.dst_port, 443);
}

test "parseTransportHeader: UDP" {
    var pkt = std.mem.zeroes([28]u8);
    pkt[0] = 0x45; // Version 4, IHL 5
    pkt[9] = 17; // UDP
    std.mem.writeInt(u16, pkt[22..24], 53, .big);

    const info = parseTransportHeader(&pkt).?;
    try std.testing.expectEqual(info.proto, .udp);
    try std.testing.expectEqual(info.dst_port, 53);
}

test "parseTransportHeader: ICMP returns null" {
    var pkt = std.mem.zeroes([20]u8);
    pkt[0] = 0x45;
    pkt[9] = 1; // ICMP

    try std.testing.expectEqual(parseTransportHeader(&pkt), null);
}
