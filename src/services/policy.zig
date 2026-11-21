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

/// Fixed size of every path buffer built from the config directory.
const PATH_BUF_LEN: usize = 512;

/// Read all available bytes from an Io.File into buf. Returns bytes read.
/// A file that does not fit is an error: truncating a policy would silently
/// drop its trailing rules (e.g. the final `deny all`).
fn readFileBytes(f: std.Io.File, buf: []u8) ReadError!usize {
    var reader = f.reader(zio(), &.{});
    var total: usize = 0;
    while (total < buf.len) {
        const n = reader.interface.readSliceShort(buf[total..]) catch return ReadError.Unreadable;
        if (n == 0) break;
        total += n;
    }
    if (total == buf.len) {
        var probe: [1]u8 = undefined;
        const n = reader.interface.readSliceShort(&probe) catch return ReadError.Unreadable;
        if (n != 0) return ReadError.FileTooLarge;
    }
    return total;
}

/// Returns a blocking Io instance for synchronous operations.
fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn openDirAbsolute(path: []const u8) !std.Io.Dir {
    return std.Io.Dir.openDirAbsolute(zio(), path, .{ .iterate = true });
}

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
    return parsePolicyLines(content, null);
}

/// parsePolicy that also reports the 1-based line of the first bad rule.
fn parsePolicyLines(content: []const u8, bad_line: ?*usize) ParseError!Policy {
    var policy = Policy{};
    var lines = std.mem.splitScalar(u8, content, '\n');
    var line_no: usize = 0;
    while (lines.next()) |line| {
        line_no += 1;
        const parsed = parseRule(line) catch |err| {
            if (bad_line) |p| p.* = line_no;
            return err;
        };
        if (parsed) |rule| {
            if (policy.count >= MAX_RULES) {
                if (bad_line) |p| p.* = line_no;
                return ParseError.TooManyRules;
            }
            policy.rules[policy.count] = rule;
            policy.count += 1;
        }
    }
    return policy;
}

/// Parse the `services/default` file: exactly one value line reading `allow`
/// or `deny` (any case, surrounding whitespace ignored), with blank lines and
/// `#` comments skipped. Anything else is an error, so a typo such as `Deny `
/// or `dny` can never silently mean allow.
pub fn parseDefaultAction(content: []const u8) error{InvalidDefault}!Action {
    var action: ?Action = null;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw| {
        const code = if (std.mem.indexOfScalar(u8, raw, '#')) |hash| raw[0..hash] else raw;
        const word = std.mem.trim(u8, code, " \t\r");
        if (word.len == 0) continue;
        if (action != null) return error.InvalidDefault; // a second value line
        if (std.ascii.eqlIgnoreCase(word, "allow")) {
            action = .allow;
        } else if (std.ascii.eqlIgnoreCase(word, "deny")) {
            action = .deny;
        } else {
            return error.InvalidDefault;
        }
    }
    return action orelse error.InvalidDefault;
}

// ─── Policy loading errors ───

/// Why a policy file could not be read into the fixed buffer.
const ReadError = error{
    /// The file exists but could not be opened or read.
    Unreadable,
    /// The file is larger than the fixed read buffer.
    FileTooLarge,
};

/// Why loadFromDir refused the services/ directory. Every variant must fail
/// closed: the caller refuses to start instead of running allow-all.
pub const LoadError = ParseError || ReadError || error{
    /// A path built from config_dir does not fit the fixed path buffer.
    PathTooLong,
    /// services/default holds something other than allow/deny.
    InvalidDefault,
    /// More .policy files than the filter can hold.
    TooManyPolicies,
};

/// Where a load failure came from, for the caller's error message.
pub const LoadDiagnostics = struct {
    path_buf: [PATH_BUF_LEN]u8 = undefined,
    path_len: usize = 0,
    /// 1-based line of the offending rule; 0 when the whole file (or the
    /// directory) is at fault.
    line: usize = 0,

    /// The offending file or directory (the config dir for PathTooLong).
    pub fn path(self: *const LoadDiagnostics) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    /// `{f}` prints `path` or `path:line`.
    pub fn format(self: *const LoadDiagnostics, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(self.path());
        if (self.line != 0) try w.print(":{d}", .{self.line});
    }

    fn note(self: *LoadDiagnostics, p: []const u8, line: usize) void {
        const n = @min(p.len, self.path_buf.len);
        @memcpy(self.path_buf[0..n], p[0..n]);
        self.path_len = n;
        self.line = line;
    }
};

fn noteDiag(diag: ?*LoadDiagnostics, path: []const u8, line: usize) void {
    if (diag) |d| d.note(path, line);
}

/// Build `dir/name` into buf; PathTooLong (recorded against dir) on overflow.
fn joinPath(buf: []u8, dir: []const u8, name: []const u8, diag: ?*LoadDiagnostics) LoadError![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ dir, name }) catch {
        noteDiag(diag, dir, 0);
        return LoadError.PathTooLong;
    };
}

/// Read a policy file. Null when it does not exist; read failures are
/// recorded against the path and returned.
fn readPolicyFile(path: []const u8, diag: ?*LoadDiagnostics) LoadError!?SmallFile {
    return readSmallFile(path) catch |err| {
        noteDiag(diag, path, 0);
        return err;
    };
}

/// Parse a policy file's content, recording path and line on failure.
fn parsePolicyFile(content: []const u8, path: []const u8, diag: ?*LoadDiagnostics) LoadError!Policy {
    var line: usize = 0;
    return parsePolicyLines(content, &line) catch |err| {
        noteDiag(diag, path, line);
        return err;
    };
}

/// Open a policy sub-directory for iteration. Null when it does not exist.
fn openPolicyDir(dir_path: []const u8, diag: ?*LoadDiagnostics) LoadError!?std.Io.Dir {
    return openDirAbsolute(dir_path) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => null,
        else => {
            noteDiag(diag, dir_path, 0);
            return LoadError.Unreadable;
        },
    };
}

/// Next `.policy` entry of a policy directory, or null at the end. An
/// iteration failure is an error: ending early would drop policies.
fn nextPolicyEntry(iter: *std.Io.Dir.Iterator, dir_path: []const u8, diag: ?*LoadDiagnostics) LoadError!?std.Io.Dir.Entry {
    while (true) {
        const next = iter.next(zio()) catch {
            noteDiag(diag, dir_path, 0);
            return LoadError.Unreadable;
        };
        const entry = next orelse return null;
        if (std.mem.endsWith(u8, entry.name, ".policy")) return entry;
    }
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

    /// Decide whether a decrypted inner IP packet is allowed, parsing both IPv4
    /// and IPv6. TCP/UDP are matched against policy; ICMP/ICMPv6 pass as control
    /// traffic; anything we cannot classify falls back to the default action.
    ///
    /// SECURITY (M5): IPv6 packets previously returned null from
    /// parseTransportHeader and were written to TUN with NO filtering, leaking
    /// all IPv6 under a default-deny policy. This path classifies IPv6 and FAILS
    /// CLOSED on anything unclassifiable when the default action is deny.
    pub fn allowPacket(
        self: *const ServiceFilter,
        peer_pubkey: [32]u8,
        peer_org_pubkey: ?[32]u8,
        ip_packet: []const u8,
    ) bool {
        return switch (classifyPacket(ip_packet)) {
            .transport => |ti| self.check(peer_pubkey, peer_org_pubkey, ti.proto, ti.dst_port),
            .pass => true,
            .unclassified => self.default_action == .allow,
        };
    }

    /// Load all service policies from the config directory.
    /// Expects: config_dir/services/{default, global.policy, peer/*.policy, org/*.policy}
    /// If the services/ directory doesn't exist, returns a default allow-all filter.
    ///
    /// SECURITY: this loader fails closed. Any malformed input — an oversized
    /// path, a `default` file that is not allow/deny, an unreadable, oversized
    /// or unparsable policy file, or more policy files than fit — is an error;
    /// `diag` (optional) then names the offending file and line. The caller
    /// must refuse to start rather than fall back to an allow-all filter.
    pub fn loadFromDir(config_dir: []const u8, diag: ?*LoadDiagnostics) LoadError!ServiceFilter {
        var filter = ServiceFilter{};

        // Build services path: config_dir + "/services"
        var services_path_buf: [PATH_BUF_LEN]u8 = undefined;
        const services_path = try joinPath(&services_path_buf, config_dir, "services", diag);

        // No services/ directory = unconfigured = allow-all (documented).
        std.Io.Dir.accessAbsolute(zio(), services_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return filter,
            else => {
                noteDiag(diag, services_path, 0);
                return LoadError.Unreadable;
            },
        };

        // Load default action
        var default_path_buf: [PATH_BUF_LEN]u8 = undefined;
        const default_path = try joinPath(&default_path_buf, services_path, "default", diag);
        if (try readPolicyFile(default_path, diag)) |content| {
            filter.default_action = parseDefaultAction(content.slice()) catch {
                noteDiag(diag, default_path, 0);
                return LoadError.InvalidDefault;
            };
        }

        // Load global policy
        var global_path_buf: [PATH_BUF_LEN]u8 = undefined;
        const global_path = try joinPath(&global_path_buf, services_path, "global.policy", diag);
        if (try readPolicyFile(global_path, diag)) |content| {
            filter.global = try parsePolicyFile(content.slice(), global_path, diag);
        }

        // Load peer policies
        var peer_dir_buf: [PATH_BUF_LEN]u8 = undefined;
        const peer_dir_path = try joinPath(&peer_dir_buf, services_path, "peer", diag);
        try filter.loadPeerPolicies(peer_dir_path, diag);

        // Load org policies
        var org_dir_buf: [PATH_BUF_LEN]u8 = undefined;
        const org_dir_path = try joinPath(&org_dir_buf, services_path, "org", diag);
        try filter.loadOrgPolicies(org_dir_path, diag);

        return filter;
    }

    /// Validate every peer/*.policy file and index the base64-named ones by
    /// pubkey. Alias-named files are validated here too and indexed later by
    /// resolveAliases (which needs authorized_keys/).
    fn loadPeerPolicies(self: *ServiceFilter, dir_path: []const u8, diag: ?*LoadDiagnostics) LoadError!void {
        const dir = (try openPolicyDir(dir_path, diag)) orelse return;
        defer dir.close(zio());

        var seen: usize = 0;
        var iter = dir.iterate();
        while (try nextPolicyEntry(&iter, dir_path, diag)) |entry| {
            // Count every file: aliases are added later and must fit too.
            seen += 1;
            if (seen > MAX_PEER_POLICIES) {
                noteDiag(diag, dir_path, 0);
                return LoadError.TooManyPolicies;
            }

            // Read and validate the policy file
            var file_path_buf: [PATH_BUF_LEN]u8 = undefined;
            const file_path = try joinPath(&file_path_buf, dir_path, entry.name, diag);
            const content = (try readPolicyFile(file_path, diag)) orelse continue; // vanished since listing
            const policy = try parsePolicyFile(content.slice(), file_path, diag);

            // Extract name (strip .policy extension)
            const name = entry.name[0 .. entry.name.len - 7];

            // A 44-char base64 name is a pubkey; anything else is an alias
            // resolved by resolveAliases.
            if (name.len == 44) {
                var pubkey: [32]u8 = undefined;
                std.base64.standard.Decoder.decode(&pubkey, name) catch continue;
                self.peer_policies[self.peer_count] = .{
                    .pubkey = pubkey,
                    .policy = policy,
                };
                self.peer_count += 1;
            }
        }
    }

    /// Validate every org/*.policy file and index the base64-named ones by
    /// org pubkey. Name-based files are indexed later by resolveOrgNames.
    fn loadOrgPolicies(self: *ServiceFilter, dir_path: []const u8, diag: ?*LoadDiagnostics) LoadError!void {
        const dir = (try openPolicyDir(dir_path, diag)) orelse return;
        defer dir.close(zio());

        var seen: usize = 0;
        var iter = dir.iterate();
        while (try nextPolicyEntry(&iter, dir_path, diag)) |entry| {
            seen += 1;
            if (seen > MAX_ORG_POLICIES) {
                noteDiag(diag, dir_path, 0);
                return LoadError.TooManyPolicies;
            }

            var file_path_buf: [PATH_BUF_LEN]u8 = undefined;
            const file_path = try joinPath(&file_path_buf, dir_path, entry.name, diag);
            const content = (try readPolicyFile(file_path, diag)) orelse continue;
            const policy = try parsePolicyFile(content.slice(), file_path, diag);

            // Org policy filename = org name or base64 org pubkey. Names are
            // mapped to pubkeys via trusted_orgs/<name>.org in resolveOrgNames.
            const org_name = entry.name[0 .. entry.name.len - 7];

            if (org_name.len == 44) {
                var org_pubkey: [32]u8 = undefined;
                std.base64.standard.Decoder.decode(&org_pubkey, org_name) catch continue;
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
        var peer_dir_buf: [PATH_BUF_LEN]u8 = undefined;
        const peer_dir_path = std.fmt.bufPrint(&peer_dir_buf, "{s}/services/peer", .{config_dir}) catch return;

        const dir = openDirAbsolute(peer_dir_path) catch return;
        defer dir.close(zio());

        var iter = dir.iterate();
        while (iter.next(zio()) catch null) |entry| {
            if (!std.mem.endsWith(u8, entry.name, ".policy")) continue;
            if (self.peer_count >= MAX_PEER_POLICIES) break;

            const name = entry.name[0 .. entry.name.len - 7];

            // Skip base64 names (already loaded)
            if (name.len == 44) {
                var tmp: [32]u8 = undefined;
                if ((std.base64.standard.Decoder.decode(&tmp, name) catch null) != null) continue;
            }

            // This is an alias — look up pubkey from authorized_keys/<name>.pub
            var ak_path_buf: [PATH_BUF_LEN]u8 = undefined;
            const ak_path = std.fmt.bufPrint(&ak_path_buf, "{s}/authorized_keys/{s}.pub", .{ config_dir, name }) catch continue;
            const ak_content = (readSmallFile(ak_path) catch continue) orelse continue;
            const trimmed = std.mem.trim(u8, ak_content.slice(), " \t\r\n");

            var pubkey: [32]u8 = undefined;
            _ = std.base64.standard.Decoder.decode(&pubkey, trimmed) catch continue;

            // Read and parse the policy file
            var file_path_buf: [PATH_BUF_LEN]u8 = undefined;
            const file_path = std.fmt.bufPrint(&file_path_buf, "{s}/{s}", .{ peer_dir_path, entry.name }) catch continue;
            const content = (readSmallFile(file_path) catch continue) orelse continue;
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
        var org_dir_buf: [PATH_BUF_LEN]u8 = undefined;
        const org_policy_dir = std.fmt.bufPrint(&org_dir_buf, "{s}/services/org", .{config_dir}) catch return;

        const dir = openDirAbsolute(org_policy_dir) catch return;
        defer dir.close(zio());

        var iter = dir.iterate();
        while (iter.next(zio()) catch null) |entry| {
            if (!std.mem.endsWith(u8, entry.name, ".policy")) continue;
            if (self.org_count >= MAX_ORG_POLICIES) break;

            const org_name = entry.name[0 .. entry.name.len - 7];

            // Skip base64 names (already loaded)
            if (org_name.len == 44) {
                var tmp: [32]u8 = undefined;
                if ((std.base64.standard.Decoder.decode(&tmp, org_name) catch null) != null) continue;
            }

            // Look up org pubkey from trusted_orgs/<name>.org
            var to_path_buf: [PATH_BUF_LEN]u8 = undefined;
            const to_path = std.fmt.bufPrint(&to_path_buf, "{s}/trusted_orgs/{s}.org", .{ config_dir, org_name }) catch continue;
            const to_content = (readSmallFile(to_path) catch continue) orelse continue;
            const trimmed = std.mem.trim(u8, to_content.slice(), " \t\r\n");

            var org_pubkey: [32]u8 = undefined;
            _ = std.base64.standard.Decoder.decode(&org_pubkey, trimmed) catch continue;

            var file_path_buf: [PATH_BUF_LEN]u8 = undefined;
            const file_path = std.fmt.bufPrint(&file_path_buf, "{s}/{s}", .{ org_policy_dir, entry.name }) catch continue;
            const content = (readSmallFile(file_path) catch continue) orelse continue;
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
///
/// Legacy, IPv4-only and kept for its tests: it cannot express "unclassified"
/// and does not understand fragments. The filter uses classifyPacket.
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

/// Classification of a decrypted inner IP packet for the service filter.
pub const FilterClass = union(enum) {
    /// TCP/UDP with a destination port to match against policy.
    transport: TransportInfo,
    /// ICMP / ICMPv6 control traffic — always passed.
    pass,
    /// Could not determine proto/port (IPv6 extension headers, truncated,
    /// non-IP). Callers apply the default action — i.e. fail closed under deny.
    unclassified,
};

fn classifyL4(protocol: u8, ip_packet: []const u8, l4_off: usize) FilterClass {
    switch (protocol) {
        6, 17 => {
            if (ip_packet.len < l4_off + 4) return .unclassified;
            const dp = std.mem.readInt(u16, ip_packet[l4_off + 2 ..][0..2], .big);
            return .{ .transport = .{ .proto = if (protocol == 6) .tcp else .udp, .dst_port = dp } };
        },
        1, 58 => return .pass, // ICMP / ICMPv6
        else => return .unclassified,
    }
}

/// Upper bound on IPv6 extension headers walked before giving up.
pub const MAX_IPV6_EXT_HEADERS: usize = 8;

/// Parse an inner IP packet (IPv4 or IPv6) for the service filter. Unlike
/// parseTransportHeader (IPv4-only, used by its tests), this classifies IPv6 too
/// and distinguishes "pass" (ICMP) from "unclassified" so callers can fail closed.
///
/// SECURITY: a non-first fragment (IPv4 offset != 0, or an IPv6 Fragment header
/// with offset != 0) carries no transport header; the bytes at the "port"
/// offset are payload chosen by the sender, so it is never matched against a
/// port rule and is `.unclassified` instead. IPv6 extension headers are walked
/// (bounded, bounds-checked) so a Hop-by-Hop header cannot hide a TCP port
/// from a deny rule.
pub fn classifyPacket(ip_packet: []const u8) FilterClass {
    if (ip_packet.len < 1) return .unclassified;
    switch (ip_packet[0] >> 4) {
        4 => {
            if (ip_packet.len < 20) return .unclassified;
            const ihl = @as(usize, ip_packet[0] & 0x0F) * 4;
            if (ihl < 20) return .unclassified;
            // Flags/fragment offset: low 13 bits are the offset in 8-octet units.
            const frag_offset = std.mem.readInt(u16, ip_packet[6..8], .big) & 0x1FFF;
            if (frag_offset != 0) return .unclassified;
            return classifyL4(ip_packet[9], ip_packet, ihl);
        },
        6 => {
            if (ip_packet.len < 40) return .unclassified;
            return classifyIpv6(ip_packet);
        },
        else => return .unclassified,
    }
}

/// Walk the IPv6 extension-header chain (ip_packet.len >= 40) to the upper
/// layer header and classify it. ESP, No Next Header and unknown next-header
/// values end in classifyL4's `.unclassified`.
fn classifyIpv6(ip_packet: []const u8) FilterClass {
    var next: u8 = ip_packet[6];
    var off: usize = 40;
    var hops: usize = 0;
    while (true) {
        switch (next) {
            // Hop-by-Hop (0), Routing (43), Destination Options (60):
            // Hdr Ext Len counts 8-octet units beyond the first 8.
            0, 43, 60 => {
                if (ip_packet.len < off + 2) return .unclassified;
                next = ip_packet[off];
                off += (@as(usize, ip_packet[off + 1]) + 1) * 8;
            },
            // Fragment (44): fixed 8 octets; only the first fragment carries L4.
            44 => {
                if (ip_packet.len < off + 8) return .unclassified;
                const frag_offset = std.mem.readInt(u16, ip_packet[off + 2 ..][0..2], .big) >> 3;
                if (frag_offset != 0) return .unclassified;
                next = ip_packet[off];
                off += 8;
            },
            // Authentication Header (51): Payload Len counts 4-octet units
            // beyond the first 8.
            51 => {
                if (ip_packet.len < off + 2) return .unclassified;
                next = ip_packet[off];
                off += (@as(usize, ip_packet[off + 1]) + 2) * 4;
            },
            else => return classifyL4(next, ip_packet, off),
        }
        hops += 1;
        // A header that runs past the packet, or an absurdly long chain, is
        // not something we will read a port out of.
        if (hops > MAX_IPV6_EXT_HEADERS or off > ip_packet.len) return .unclassified;
    }
}

// ─── Small file reader (no allocator) ───

const SmallFile = struct {
    buf: [4096]u8,
    len: usize,

    pub fn slice(self: *const SmallFile) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Read a whole file into a fixed buffer. Returns null when the file does not
/// exist; a file that exists but cannot be read, or does not fit, is an error.
fn readSmallFile(path: []const u8) ReadError!?SmallFile {
    const file = std.Io.Dir.openFileAbsolute(zio(), path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return ReadError.Unreadable,
    };
    defer file.close(zio());
    var result = SmallFile{ .buf = undefined, .len = 0 };
    result.len = try readFileBytes(file, &result.buf);
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

    const peer_pubkey = @as([32]u8, @splat(0xAA));
    const other_pubkey = @as([32]u8, @splat(0xBB));

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
    const pk = @as([32]u8, @splat(0x42));

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

test "classifyPacket handles IPv6 and allowPacket fails closed (M5 regression)" {
    // IPv6 TCP to port 80 → classified as transport (was bypassing the filter).
    var v6 = std.mem.zeroes([44]u8);
    v6[0] = 0x60; // IPv6 version
    v6[6] = 6; // next header = TCP
    v6[43] = 80; // dst port (offset 40 + 2)
    const c = classifyPacket(&v6);
    try std.testing.expect(c == .transport);
    try std.testing.expectEqual(@as(u16, 80), c.transport.dst_port);
    try std.testing.expectEqual(Proto.tcp, c.transport.proto);

    // IPv6 whose Hop-by-Hop header chain runs past the packet → unclassified
    // (fail-closed input; a complete chain is walked, see the ext-header tests).
    var v6ext = std.mem.zeroes([44]u8);
    v6ext[0] = 0x60;
    v6ext[6] = 0; // hop-by-hop extension header
    try std.testing.expect(classifyPacket(&v6ext) == .unclassified);

    // ICMPv6 → pass (control traffic).
    var icmp6 = std.mem.zeroes([44]u8);
    icmp6[0] = 0x60;
    icmp6[6] = 58;
    try std.testing.expect(classifyPacket(&icmp6) == .pass);

    // Truncated IPv6 → unclassified (no OOB).
    try std.testing.expect(classifyPacket(&[_]u8{ 0x60, 0, 0 }) == .unclassified);

    // allowPacket: under default-deny, unclassified IPv6 is dropped, ICMPv6 passes.
    const deny = ServiceFilter{ .default_action = .deny, .peer_count = 0, .org_count = 0 };
    try std.testing.expect(!deny.allowPacket(@splat(0), null, &v6ext));
    try std.testing.expect(deny.allowPacket(@splat(0), null, &icmp6));
    // Under default-allow (unconfigured), behavior is unchanged (passes).
    const allow = ServiceFilter{ .default_action = .allow, .peer_count = 0, .org_count = 0 };
    try std.testing.expect(allow.allowPacket(@splat(0), null, &v6ext));
}

// ─── Fragment / extension-header tests ───

/// Minimal IPv4 TCP packet to `dst_port` with the given flags/fragment field.
fn testIpv4Tcp(frag_field: u16, dst_port: u16) [28]u8 {
    var pkt = std.mem.zeroes([28]u8);
    pkt[0] = 0x45; // Version 4, IHL 5
    std.mem.writeInt(u16, pkt[6..8], frag_field, .big);
    pkt[9] = 6; // TCP
    std.mem.writeInt(u16, pkt[22..24], dst_port, .big);
    return pkt;
}

test "classifyPacket: IPv4 non-first fragment never yields a port" {
    // Under default-deny with `allow tcp 22`, a non-first fragment whose payload
    // bytes happen to read as port 22 must NOT be allowed: it has no TCP header.
    var filter = ServiceFilter{ .default_action = .deny, .peer_count = 0, .org_count = 0 };
    filter.global = try parsePolicy("allow tcp 22");
    const pk: [32]u8 = @splat(0x11);

    const non_first = testIpv4Tcp(0x0001, 22); // offset 1 (8 octets), MF clear
    try std.testing.expect(classifyPacket(&non_first) == .unclassified);
    try std.testing.expect(!filter.allowPacket(pk, null, &non_first));

    const mid_with_mf = testIpv4Tcp(0x2005, 22); // MF set, offset 5
    try std.testing.expect(classifyPacket(&mid_with_mf) == .unclassified);
    try std.testing.expect(!filter.allowPacket(pk, null, &mid_with_mf));

    // Non-first ICMP fragments are unclassified too (not blanket-passed).
    var icmp_frag = testIpv4Tcp(0x0002, 0);
    icmp_frag[9] = 1;
    try std.testing.expect(classifyPacket(&icmp_frag) == .unclassified);

    // Unfragmented and first fragments are classified normally.
    const whole = testIpv4Tcp(0x4000, 22); // DF set, offset 0
    const c = classifyPacket(&whole);
    try std.testing.expect(c == .transport);
    try std.testing.expectEqual(@as(u16, 22), c.transport.dst_port);
    try std.testing.expect(filter.allowPacket(pk, null, &whole));

    const first = testIpv4Tcp(0x2000, 22); // MF set, offset 0
    const cf = classifyPacket(&first);
    try std.testing.expect(cf == .transport);
    try std.testing.expectEqual(Proto.tcp, cf.transport.proto);
    try std.testing.expectEqual(@as(u16, 22), cf.transport.dst_port);
    try std.testing.expect(filter.allowPacket(pk, null, &first));
}

test "classifyPacket: IPv4 honors IHL and bounds-checks the L4 header" {
    // IHL=6 (24-byte header with options): the port lives at offset 26.
    var pkt = std.mem.zeroes([32]u8);
    pkt[0] = 0x46;
    pkt[9] = 17; // UDP
    std.mem.writeInt(u16, pkt[22..24], 9999, .big); // where IHL=5 would look
    std.mem.writeInt(u16, pkt[26..28], 53, .big);
    const c = classifyPacket(&pkt);
    try std.testing.expect(c == .transport);
    try std.testing.expectEqual(Proto.udp, c.transport.proto);
    try std.testing.expectEqual(@as(u16, 53), c.transport.dst_port);

    // IHL=15 (60 bytes) on a 32-byte packet: L4 header out of range → unclassified.
    pkt[0] = 0x4F;
    try std.testing.expect(classifyPacket(&pkt) == .unclassified);

    // IHL<5 is malformed → unclassified.
    pkt[0] = 0x44;
    try std.testing.expect(classifyPacket(&pkt) == .unclassified);
}

/// Build an IPv6 packet: fixed header with `first_next`, then `ext` bytes
/// verbatim, then an 8-byte L4 header whose dst port is `dst_port`.
fn testIpv6(buf: []u8, first_next: u8, ext: []const u8, dst_port: u16) []u8 {
    @memset(buf, 0);
    buf[0] = 0x60;
    buf[6] = first_next;
    @memcpy(buf[40 .. 40 + ext.len], ext);
    const l4 = 40 + ext.len;
    std.mem.writeInt(u16, buf[l4 + 2 ..][0..2], dst_port, .big);
    return buf[0 .. l4 + 8];
}

test "classifyPacket: IPv6 Hop-by-Hop before TCP is still TCP (deny applies)" {
    // default allow + `deny tcp 22`: prepending a Hop-by-Hop header used to make
    // the packet unclassified, which the default then allowed.
    var filter = ServiceFilter{ .default_action = .allow, .peer_count = 0, .org_count = 0 };
    filter.global = try parsePolicy("deny tcp 22");
    const pk: [32]u8 = @splat(0x22);

    var buf: [128]u8 = undefined;
    // HBH: next=TCP(6), Hdr Ext Len=0 (8 octets), 6 bytes of padding.
    const hbh = [_]u8{ 6, 0, 0, 0, 0, 0, 0, 0 };
    const pkt = testIpv6(&buf, 0, &hbh, 22);
    const c = classifyPacket(pkt);
    try std.testing.expect(c == .transport);
    try std.testing.expectEqual(Proto.tcp, c.transport.proto);
    try std.testing.expectEqual(@as(u16, 22), c.transport.dst_port);
    try std.testing.expect(!filter.allowPacket(pk, null, pkt));

    // Other ports are still allowed by the default.
    const ok = testIpv6(&buf, 0, &hbh, 443);
    try std.testing.expect(filter.allowPacket(pk, null, ok));

    // Routing (43) with Hdr Ext Len=1 (16 octets) then Dest Opts (60) then UDP.
    var chain: [24]u8 = @splat(0);
    chain[0] = 60; // routing → dest opts
    chain[1] = 1; // 16 octets
    chain[16] = 17; // dest opts → UDP
    chain[17] = 0; // 8 octets
    const c2 = classifyPacket(testIpv6(&buf, 43, &chain, 53));
    try std.testing.expect(c2 == .transport);
    try std.testing.expectEqual(Proto.udp, c2.transport.proto);
    try std.testing.expectEqual(@as(u16, 53), c2.transport.dst_port);
}

test "classifyPacket: IPv6 fragments" {
    var buf: [128]u8 = undefined;

    // Fragment header: next=TCP, reserved, offset(13 bits)<<3 | res(2) | M.
    // Non-first fragment (offset 1): the payload bytes are NOT a TCP header.
    var frag = [_]u8{ 6, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u16, frag[2..4], (1 << 3) | 1, .big);
    try std.testing.expect(classifyPacket(testIpv6(&buf, 44, &frag, 22)) == .unclassified);

    const deny = ServiceFilter{ .default_action = .deny, .peer_count = 0, .org_count = 0 };
    try std.testing.expect(!deny.allowPacket(@splat(0), null, testIpv6(&buf, 44, &frag, 22)));

    // First fragment (offset 0, M=1): classified normally.
    std.mem.writeInt(u16, frag[2..4], 1, .big);
    const c = classifyPacket(testIpv6(&buf, 44, &frag, 22));
    try std.testing.expect(c == .transport);
    try std.testing.expectEqual(Proto.tcp, c.transport.proto);
    try std.testing.expectEqual(@as(u16, 22), c.transport.dst_port);

    // Truncated fragment header (less than 8 bytes) → unclassified, no OOB.
    var short = std.mem.zeroes([44]u8);
    short[0] = 0x60;
    short[6] = 44;
    try std.testing.expect(classifyPacket(&short) == .unclassified);
}

test "classifyPacket: IPv6 AH then UDP, ESP and no-next-header" {
    var buf: [128]u8 = undefined;

    // AH: next=UDP(17), Payload Len=4 → (4+2)*4 = 24 octets.
    var ah: [24]u8 = @splat(0);
    ah[0] = 17;
    ah[1] = 4;
    const c = classifyPacket(testIpv6(&buf, 51, &ah, 53));
    try std.testing.expect(c == .transport);
    try std.testing.expectEqual(Proto.udp, c.transport.proto);
    try std.testing.expectEqual(@as(u16, 53), c.transport.dst_port);

    // ESP (50) and No Next Header (59): nothing to match → unclassified.
    try std.testing.expect(classifyPacket(testIpv6(&buf, 50, &.{}, 22)) == .unclassified);
    try std.testing.expect(classifyPacket(testIpv6(&buf, 59, &.{}, 22)) == .unclassified);

    // HBH then ICMPv6 → pass.
    const hbh = [_]u8{ 58, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(classifyPacket(testIpv6(&buf, 0, &hbh, 0)) == .pass);
}

test "classifyPacket: IPv6 extension chain is bounded and bounds-checked" {
    var buf: [256]u8 = undefined;

    // Exactly MAX_IPV6_EXT_HEADERS Hop-by-Hop headers then TCP → classified.
    var chain: [MAX_IPV6_EXT_HEADERS * 8 + 8]u8 = @splat(0); // next=HBH, len=0 each
    chain[(MAX_IPV6_EXT_HEADERS - 1) * 8] = 6; // last one → TCP
    const ok = classifyPacket(testIpv6(&buf, 0, chain[0 .. MAX_IPV6_EXT_HEADERS * 8], 22));
    try std.testing.expect(ok == .transport);
    try std.testing.expectEqual(@as(u16, 22), ok.transport.dst_port);

    // One more header than the bound → unclassified (the loop terminates).
    chain[(MAX_IPV6_EXT_HEADERS - 1) * 8] = 0;
    chain[MAX_IPV6_EXT_HEADERS * 8] = 6;
    try std.testing.expect(classifyPacket(testIpv6(&buf, 0, &chain, 22)) == .unclassified);

    // A header that claims to run past the packet → unclassified, no OOB read.
    const huge = [_]u8{ 6, 0xFF, 0, 0, 0, 0, 0, 0 }; // 2048 octets
    try std.testing.expect(classifyPacket(testIpv6(&buf, 0, &huge, 22)) == .unclassified);

    // Truncated right after the fixed header with an ext next-header → unclassified.
    var bare = std.mem.zeroes([40]u8);
    bare[0] = 0x60;
    bare[6] = 60;
    try std.testing.expect(classifyPacket(&bare) == .unclassified);
    // AH with only one byte of header present.
    var ah_short = std.mem.zeroes([41]u8);
    ah_short[0] = 0x60;
    ah_short[6] = 51;
    try std.testing.expect(classifyPacket(&ah_short) == .unclassified);
}

// ─── Loader tests ───

test "parseDefaultAction: case, whitespace, comments; rejects anything else" {
    try std.testing.expectEqual(Action.deny, try parseDefaultAction("deny\n"));
    try std.testing.expectEqual(Action.deny, try parseDefaultAction("Deny "));
    try std.testing.expectEqual(Action.deny, try parseDefaultAction("  DENY\r\n"));
    try std.testing.expectEqual(Action.deny, try parseDefaultAction("deny # comment\n"));
    try std.testing.expectEqual(Action.deny, try parseDefaultAction("# header\n\ndeny\n"));
    try std.testing.expectEqual(Action.allow, try parseDefaultAction("allow\n"));
    try std.testing.expectEqual(Action.allow, try parseDefaultAction("Allow"));

    try std.testing.expectError(error.InvalidDefault, parseDefaultAction("maybe"));
    try std.testing.expectError(error.InvalidDefault, parseDefaultAction("deny all"));
    try std.testing.expectError(error.InvalidDefault, parseDefaultAction("denyy"));
    try std.testing.expectError(error.InvalidDefault, parseDefaultAction("allow\ndeny\n"));
    try std.testing.expectError(error.InvalidDefault, parseDefaultAction(""));
    try std.testing.expectError(error.InvalidDefault, parseDefaultAction("# nothing\n"));
}

/// Temporary config dir for loader tests. `root` is absolute; policy files are
/// written relative to it.
const TestConfig = struct {
    tmp: std.testing.TmpDir,
    root: [:0]u8,

    fn init() !TestConfig {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realPathFileAlloc(zio(), ".", std.testing.allocator);
        return .{ .tmp = tmp, .root = root };
    }

    fn deinit(self: *TestConfig) void {
        std.testing.allocator.free(self.root);
        self.tmp.cleanup();
    }

    fn mkdir(self: *TestConfig, sub_path: []const u8) !void {
        try self.tmp.dir.createDirPath(zio(), sub_path);
    }

    fn write(self: *TestConfig, sub_path: []const u8, data: []const u8) !void {
        try self.tmp.dir.writeFile(zio(), .{ .sub_path = sub_path, .data = data });
    }
};

test "loadFromDir: missing or empty services/ loads as allow-all" {
    var cfg = try TestConfig.init();
    defer cfg.deinit();

    var diag = LoadDiagnostics{};
    const none = try ServiceFilter.loadFromDir(cfg.root, &diag);
    try std.testing.expectEqual(Action.allow, none.default_action);
    try std.testing.expect(none.global == null);

    try cfg.mkdir("services");
    const empty = try ServiceFilter.loadFromDir(cfg.root, &diag);
    try std.testing.expectEqual(Action.allow, empty.default_action);
    try std.testing.expect(empty.global == null);
    try std.testing.expectEqual(@as(u8, 0), empty.peer_count);
    try std.testing.expectEqual(@as(u8, 0), empty.org_count);

    // Empty sub-directories are fine too; a null diag is accepted.
    try cfg.mkdir("services/peer");
    try cfg.mkdir("services/org");
    const dirs = try ServiceFilter.loadFromDir(cfg.root, null);
    try std.testing.expectEqual(@as(u8, 0), dirs.peer_count);
}

test "loadFromDir: valid files load with the documented semantics" {
    var cfg = try TestConfig.init();
    defer cfg.deinit();
    try cfg.mkdir("services/peer");
    try cfg.mkdir("services/org");
    try cfg.write("services/default", "Deny # allowlist mode\n");
    try cfg.write("services/global.policy", "# ssh only\nallow tcp 22\ndeny all\n");

    const peer_pk: [32]u8 = @splat(0xAB);
    var b64: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&b64, &peer_pk);
    var name_buf: [80]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "services/peer/{s}.policy", .{b64});
    try cfg.write(name, "allow tcp 5432\n");
    try cfg.write("services/peer/notes.txt", "not a policy\n"); // ignored

    const filter = try ServiceFilter.loadFromDir(cfg.root, null);
    try std.testing.expectEqual(Action.deny, filter.default_action);
    try std.testing.expect(filter.global != null);
    try std.testing.expectEqual(@as(u8, 1), filter.peer_count);
    try std.testing.expect(filter.check(peer_pk, null, .tcp, 5432));
    try std.testing.expect(filter.check(peer_pk, null, .tcp, 22));
    try std.testing.expect(!filter.check(@splat(0xCD), null, .tcp, 5432));
    try std.testing.expect(filter.check(@splat(0xCD), null, .tcp, 22));
}

test "loadFromDir: unrecognized default value fails closed" {
    var cfg = try TestConfig.init();
    defer cfg.deinit();
    try cfg.mkdir("services");
    try cfg.write("services/default", "maybe\n");

    var diag = LoadDiagnostics{};
    try std.testing.expectError(error.InvalidDefault, ServiceFilter.loadFromDir(cfg.root, &diag));
    try std.testing.expect(std.mem.endsWith(u8, diag.path(), "/services/default"));
    try std.testing.expectEqual(@as(usize, 0), diag.line);

    // The accepted spellings load.
    try cfg.write("services/default", "deny # comment\n");
    try std.testing.expectEqual(Action.deny, (try ServiceFilter.loadFromDir(cfg.root, &diag)).default_action);
    try cfg.write("services/default", "Deny \n");
    try std.testing.expectEqual(Action.deny, (try ServiceFilter.loadFromDir(cfg.root, &diag)).default_action);
}

test "loadFromDir: a malformed rule in any policy file fails the load" {
    var cfg = try TestConfig.init();
    defer cfg.deinit();
    try cfg.mkdir("services/peer");
    try cfg.mkdir("services/org");

    // Global: bad action on line 2.
    try cfg.write("services/global.policy", "allow tcp 22\nalow tcp 80\n");
    var diag = LoadDiagnostics{};
    try std.testing.expectError(error.InvalidAction, ServiceFilter.loadFromDir(cfg.root, &diag));
    try std.testing.expect(std.mem.endsWith(u8, diag.path(), "/services/global.policy"));
    try std.testing.expectEqual(@as(usize, 2), diag.line);
    var fmt_buf: [600]u8 = undefined;
    const rendered = try std.fmt.bufPrint(&fmt_buf, "{f}", .{&diag});
    try std.testing.expect(std.mem.endsWith(u8, rendered, "global.policy:2"));

    // Alias-named peer policy (not base64): still validated at load time.
    try cfg.write("services/global.policy", "allow tcp 22\n");
    try cfg.write("services/peer/laptop.policy", "allow tcp 22\n\ndeny udp 1-x\n");
    try std.testing.expectError(error.InvalidPort, ServiceFilter.loadFromDir(cfg.root, &diag));
    try std.testing.expect(std.mem.endsWith(u8, diag.path(), "/services/peer/laptop.policy"));
    try std.testing.expectEqual(@as(usize, 3), diag.line);

    // Org policy with a bad protocol.
    try cfg.write("services/peer/laptop.policy", "deny all\n");
    try cfg.write("services/org/acme.policy", "allow sctp 22\n");
    try std.testing.expectError(error.InvalidProto, ServiceFilter.loadFromDir(cfg.root, &diag));
    try std.testing.expect(std.mem.endsWith(u8, diag.path(), "/services/org/acme.policy"));
    try std.testing.expectEqual(@as(usize, 1), diag.line);

    // Fixed → loads.
    try cfg.write("services/org/acme.policy", "allow tcp 22\n");
    _ = try ServiceFilter.loadFromDir(cfg.root, &diag);
}

test "loadFromDir: too many rules and oversized files fail instead of being dropped" {
    var cfg = try TestConfig.init();
    defer cfg.deinit();
    try cfg.mkdir("services");

    // MAX_RULES + 1 rules: the old loader dropped the whole global policy.
    var content: [(MAX_RULES + 1) * 16]u8 = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i <= MAX_RULES) : (i += 1) {
        const line = try std.fmt.bufPrint(content[n..], "allow tcp {d}\n", .{1000 + i});
        n += line.len;
    }
    try cfg.write("services/global.policy", content[0..n]);
    var diag = LoadDiagnostics{};
    try std.testing.expectError(error.TooManyRules, ServiceFilter.loadFromDir(cfg.root, &diag));
    try std.testing.expectEqual(MAX_RULES + 1, diag.line);

    // Larger than the read buffer: the old loader silently truncated it,
    // losing the trailing `deny all`.
    var big: [4480 + 16]u8 = undefined;
    var off: usize = 0;
    while (off < 4480) : (off += 64) { // 70 comment lines of 64 bytes
        big[off] = '#';
        big[off + 1] = ' ';
        @memset(big[off + 2 .. off + 63], 'x');
        big[off + 63] = '\n';
    }
    const tail = "deny all\n";
    @memcpy(big[off .. off + tail.len], tail);
    try cfg.write("services/global.policy", big[0 .. off + tail.len]);
    try std.testing.expectError(error.FileTooLarge, ServiceFilter.loadFromDir(cfg.root, &diag));
    try std.testing.expect(std.mem.endsWith(u8, diag.path(), "/services/global.policy"));
}

test "loadFromDir: oversized config path is an error, not allow-all" {
    var long_dir: [PATH_BUF_LEN + 10]u8 = @splat('d');
    long_dir[0] = '/';
    var diag = LoadDiagnostics{};
    try std.testing.expectError(error.PathTooLong, ServiceFilter.loadFromDir(&long_dir, &diag));
    try std.testing.expectEqual(PATH_BUF_LEN, diag.path().len);
    try std.testing.expect(std.mem.startsWith(u8, &long_dir, diag.path()));
}
