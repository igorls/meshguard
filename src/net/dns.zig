//! Minimal DNS resolver for meshguard seed discovery.
//!
//! Implements RFC 1035 DNS queries over UDP to resolve:
//!   - A records (hostname → IPv4)
//!   - TXT records (service discovery via `_meshguard._udp.domain`)
//!   - mDNS queries (multicast to 224.0.0.251:5353)
//!
//! Cross-platform: supports both Linux and Windows.

const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const is_linux = builtin.os.tag == .linux;
const is_windows = builtin.os.tag == .windows;
const linux = if (is_linux) std.os.linux else struct {};
const win = if (is_windows) struct {
    const SOCKET = posix.socket_t;
    // Winsock WSAPoll: readable data is POLLRDNORM (0x0100), not 0x0001 — on Windows
    // 0x0001 is POLLERR and makes WSAPoll fail with WSAEINVAL (10022). See net/udp.zig.
    const POLLIN: i16 = 0x0100 | 0x0200; // POLLRDNORM | POLLRDBAND
    const pollfd = extern struct {
        fd: SOCKET,
        events: i16,
        revents: i16,
    };

    extern "ws2_32" fn WSAPoll(fds: [*]pollfd, nfds: u32, timeout: c_int) c_int;
    extern "ws2_32" fn closesocket(socket: SOCKET) c_int;
} else struct {};

/// Returns a blocking Io instance for synchronous operations.
fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn nowMs() i64 {
    return @intCast(std.Io.Timestamp.now(zio(), .awake).toMilliseconds());
}

// ─── DNS Wire Format Constants ───

const DNS_PORT: u16 = 53;
const MDNS_PORT: u16 = 5353;
const MDNS_ADDR: [4]u8 = .{ 224, 0, 0, 251 };

const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const CLASS_IN: u16 = 1;

const HEADER_LEN: usize = 12;
const MAX_RESPONSE: usize = 512; // Standard DNS UDP max

fn ipv4SockaddrAddr(addr: [4]u8) u32 {
    const host_order = (@as(u32, addr[0]) << 24) |
        (@as(u32, addr[1]) << 16) |
        (@as(u32, addr[2]) << 8) |
        @as(u32, addr[3]);
    return std.mem.nativeToBig(u32, host_order);
}

// ─── DNS Header ───

const DnsHeader = struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
};

// ─── Public API ───

/// Get nameserver IPv4 addresses. On Linux, parses /etc/resolv.conf.
/// On Windows, uses well-known public DNS servers as fallback.
pub fn getNameservers(buf: *[3][4]u8) usize {
    if (comptime is_linux) {
        return getNameserversLinux(buf);
    } else if (comptime is_windows) {
        return getNameserversWindows(buf);
    }
    return 0;
}

fn getNameserversLinux(buf: *[3][4]u8) usize {
    const z = zio();
    const file = std.Io.Dir.openFileAbsolute(z, "/etc/resolv.conf", .{}) catch return 0;
    defer file.close(z);

    var read_buf: [2048]u8 = undefined;
    var file_reader = file.reader(z, &.{});
    var n: usize = 0;
    while (n < read_buf.len) {
        const chunk = file_reader.interface.readSliceShort(read_buf[n..]) catch break;
        if (chunk == 0) break;
        n += chunk;
    }
    const content = read_buf[0..n];

    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (count >= 3) break;
        const trimmed = std.mem.trimStart(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, "nameserver")) {
            const rest = std.mem.trimStart(u8, trimmed["nameserver".len..], " \t");
            // Trim any trailing whitespace/CR
            const ip_str = std.mem.trimEnd(u8, rest, " \t\r");
            if (parseIpv4(ip_str)) |addr| {
                buf[count] = addr;
                count += 1;
            }
        }
    }
    return count;
}

fn getNameserversWindows(buf: *[3][4]u8) usize {
    // Use well-known public DNS servers.
    // A more advanced implementation could query the registry at
    // HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*\NameServer
    // or use GetNetworkParams from iphlpapi.dll.
    buf[0] = .{ 8, 8, 8, 8 }; // Google DNS
    buf[1] = .{ 1, 1, 1, 1 }; // Cloudflare DNS
    buf[2] = .{ 9, 9, 9, 9 }; // Quad9 DNS
    return 3;
}

/// Resolve a hostname to an IPv4 address via DNS A record query.
/// Returns null if resolution fails or times out.
pub fn resolveA(hostname: []const u8) ?[4]u8 {
    var ns_buf: [3][4]u8 = undefined;
    const ns_count = getNameservers(&ns_buf);
    if (ns_count == 0) return null;

    // Try each nameserver
    for (ns_buf[0..ns_count]) |ns| {
        if (queryA(ns, hostname)) |addr| {
            return addr;
        }
    }
    return null;
}

/// Query a specific nameserver for an A record.
fn queryA(nameserver: [4]u8, hostname: []const u8) ?[4]u8 {
    var query_buf: [512]u8 = undefined;
    // SECURITY (H5): randomize the transaction ID per query (was a constant
    // 0xABCD, trivially spoofable off-path).
    const id = randomTxid();
    const query_len = buildQuery(&query_buf, hostname, TYPE_A, id) catch return null;

    const response = sendQuery(nameserver, DNS_PORT, query_buf[0..query_len]) orelse return null;

    // SECURITY (H5): reject responses that don't match our query (TXID, QR bit,
    // and the echoed question). The connected socket already filters by source.
    if (!responseMatchesQuery(response.data[0..response.len], id, hostname, TYPE_A)) return null;

    // Parse A record from response
    return parseAResponse(&response.data, response.len);
}

/// Query DNS TXT records for a domain.
/// Returns parsed TXT record strings as "key=value" pairs.
/// Caller owns the returned slice and each string.
pub fn queryTXT(allocator: std.mem.Allocator, domain: []const u8) ![][]const u8 {
    var ns_buf: [3][4]u8 = undefined;
    const ns_count = getNameservers(&ns_buf);
    if (ns_count == 0) return &.{};

    for (ns_buf[0..ns_count]) |ns| {
        var query_buf: [512]u8 = undefined;
        const id = randomTxid(); // SECURITY (H5): random TXID (was constant 0xCDEF)
        const query_len = buildQuery(&query_buf, domain, TYPE_TXT, id) catch continue;

        const response = sendQuery(ns, DNS_PORT, query_buf[0..query_len]) orelse continue;
        // SECURITY (H5): only accept a response that matches our query.
        if (!responseMatchesQuery(response.data[0..response.len], id, domain, TYPE_TXT)) continue;
        return parseTXTResponse(allocator, &response.data, response.len);
    }
    return &.{};
}

/// Query mDNS for TXT records on the local network.
/// Sends multicast to 224.0.0.251:5353 and collects responses.
/// Caller owns the returned slice and each string.
pub fn queryMDNS(allocator: std.mem.Allocator, service_name: []const u8) ![][]const u8 {
    var query_buf: [512]u8 = undefined;
    const query_len = buildQuery(&query_buf, service_name, TYPE_TXT, 0) catch return &.{};

    // Create UDP socket for mDNS
    const sock_fd = createDgramSocket() orelse return &.{};
    defer closeFd(sock_fd);

    // Set SO_REUSEADDR
    const one: i32 = 1;
    if (comptime is_linux) {
        _ = linux.setsockopt(sock_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(i32));
    } else {
        _ = std.c.setsockopt(sock_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, @ptrCast(&one), @sizeOf(i32));
    }

    // Send multicast query
    const mdns_addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, MDNS_PORT),
        .addr = ipv4SockaddrAddr(MDNS_ADDR),
        .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    if (comptime is_linux) {
        const rc = linux.sendto(sock_fd, query_buf[0..query_len].ptr, query_len, 0, @ptrCast(&mdns_addr), @sizeOf(@TypeOf(mdns_addr)));
        if (rawSyscallFailed(rc)) return &.{};
    } else {
        if (std.c.sendto(sock_fd, query_buf[0..query_len].ptr, query_len, 0, @ptrCast(&mdns_addr), @sizeOf(@TypeOf(mdns_addr))) < 0) {
            return &.{};
        }
    }

    // Collect responses with a short timeout (500ms)
    var results: std.ArrayList([]const u8) = .empty;

    // Poll for up to 1 second, collecting multiple responses
    var deadline: i32 = 1000;
    while (deadline > 0) {
        const poll_start = nowMs();
        const n_ready = pollReadFd(sock_fd, deadline);
        const elapsed: i32 = @intCast(@min(nowMs() - poll_start, deadline));
        deadline -= elapsed;

        if (n_ready <= 0) break; // timeout or error

        var resp_buf: [MAX_RESPONSE]u8 = undefined;
        const resp_n = recvFromSocket(sock_fd, &resp_buf) orelse break;
        if (resp_n > HEADER_LEN) {
            const parsed = parseTXTResponse(allocator, &resp_buf, resp_n) catch continue;
            for (parsed) |txt| {
                results.append(allocator, txt) catch {};
            }
            if (parsed.len > 0) allocator.free(parsed);
        }
    }

    return results.toOwnedSlice(allocator);
}

// ─── DNS Wire Encoding ───

/// Build a DNS query packet for the given domain and record type.
fn buildQuery(buf: *[512]u8, domain: []const u8, qtype: u16, id: u16) !usize {
    var pos: usize = 0;

    // Header
    writeU16(buf, &pos, id); // ID
    writeU16(buf, &pos, 0x0100); // Flags: standard query, recursion desired
    writeU16(buf, &pos, 1); // QDCOUNT: 1 question
    writeU16(buf, &pos, 0); // ANCOUNT
    writeU16(buf, &pos, 0); // NSCOUNT
    writeU16(buf, &pos, 0); // ARCOUNT

    // Question: encode domain name as labels
    pos = try encodeDomainName(buf, pos, domain);

    // QTYPE and QCLASS
    writeU16(buf, &pos, qtype);
    writeU16(buf, &pos, CLASS_IN);

    return pos;
}

/// Encode a domain name as DNS labels (e.g., "example.com" → \x07example\x03com\x00).
fn encodeDomainName(buf: *[512]u8, start: usize, domain: []const u8) !usize {
    var pos = start;
    var labels = std.mem.splitScalar(u8, domain, '.');

    while (labels.next()) |label| {
        if (label.len == 0) continue;
        if (label.len > 63) return error.LabelTooLong;
        if (pos + 1 + label.len >= buf.len) return error.BufferTooSmall;

        buf[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(buf[pos .. pos + label.len], label);
        pos += label.len;
    }

    // Null terminator
    if (pos >= buf.len) return error.BufferTooSmall;
    buf[pos] = 0;
    pos += 1;

    return pos;
}

// ─── DNS Wire Decoding ───

/// Parse an A record response, returning the first IPv4 address found.
fn parseAResponse(data: []const u8, len: usize) ?[4]u8 {
    if (len < HEADER_LEN) return null;

    const ancount = readU16(data, 6);
    if (ancount == 0) return null;

    // Skip header + question section
    var pos: usize = HEADER_LEN;
    pos = skipDomainName(data, pos, len) orelse return null;
    pos += 4; // QTYPE + QCLASS
    if (pos >= len) return null;

    // Parse answer records
    var i: u16 = 0;
    while (i < ancount) : (i += 1) {
        pos = skipDomainName(data, pos, len) orelse return null;
        if (pos + 10 > len) return null;

        const rtype = readU16(data, pos);
        pos += 2;
        _ = readU16(data, pos); // class
        pos += 2;
        pos += 4; // TTL
        const rdlength = readU16(data, pos);
        pos += 2;

        if (rtype == TYPE_A and rdlength == 4 and pos + 4 <= len) {
            return .{ data[pos], data[pos + 1], data[pos + 2], data[pos + 3] };
        }

        pos += rdlength;
        if (pos > len) return null;
    }
    return null;
}

/// Parse TXT record responses, returning all TXT strings.
fn parseTXTResponse(allocator: std.mem.Allocator, data: []const u8, len: usize) ![][]const u8 {
    if (len < HEADER_LEN) return &.{};

    const flags = readU16(data, 2);
    // Check RCODE (bits 0-3): 0 = no error
    if (flags & 0x000F != 0) return &.{};

    const ancount = readU16(data, 6);
    if (ancount == 0) return &.{};

    var results: std.ArrayList([]const u8) = .empty;

    // Skip header + question section
    var pos: usize = HEADER_LEN;
    pos = skipDomainName(data, pos, len) orelse return results.toOwnedSlice(allocator);
    pos += 4; // QTYPE + QCLASS
    if (pos >= len) return results.toOwnedSlice(allocator);

    // Parse answer records
    var i: u16 = 0;
    while (i < ancount) : (i += 1) {
        pos = skipDomainName(data, pos, len) orelse break;
        if (pos + 10 > len) break;

        const rtype = readU16(data, pos);
        pos += 2;
        _ = readU16(data, pos); // class
        pos += 2;
        pos += 4; // TTL
        const rdlength = readU16(data, pos);
        pos += 2;

        if (rtype == TYPE_TXT) {
            // TXT RDATA: one or more length-prefixed strings
            const rdata_end = pos + rdlength;
            while (pos < rdata_end and pos < len) {
                const txt_len = data[pos];
                pos += 1;
                if (pos + txt_len > len or pos + txt_len > rdata_end) break;

                const txt = try allocator.dupe(u8, data[pos .. pos + txt_len]);
                try results.append(allocator, txt);
                pos += txt_len;
            }
        } else {
            pos += rdlength;
        }

        if (pos > len) break;
    }

    return results.toOwnedSlice(allocator);
}

/// Skip a DNS domain name (handles compression pointers).
fn skipDomainName(data: []const u8, start: usize, len: usize) ?usize {
    var pos = start;
    while (pos < len) {
        const label_len = data[pos];
        if (label_len == 0) {
            return pos + 1; // null terminator
        }
        // Compression pointer (top 2 bits set)
        if (label_len & 0xC0 == 0xC0) {
            return pos + 2; // pointer is 2 bytes
        }
        pos += 1 + label_len;
    }
    return null;
}

// ─── Network I/O (cross-platform) ───

const QueryResponse = struct {
    data: [MAX_RESPONSE]u8,
    len: usize,
};

/// Cross-platform poll: check if a socket is readable within timeout_ms.
/// Returns > 0 if readable, 0 on timeout, < 0 on error.
fn pollReadFd(fd: posix.socket_t, timeout_ms: i32) i32 {
    if (comptime is_windows) {
        var fds = [1]win.pollfd{.{ .fd = fd, .events = win.POLLIN, .revents = 0 }};
        return win.WSAPoll(&fds, 1, timeout_ms);
    } else {
        var fds = [_]posix.pollfd{
            .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 },
        };
        const rc = posix.poll(&fds, timeout_ms) catch return -1;
        if (rc == 0) return 0;
        if (fds[0].revents & posix.POLL.IN != 0) return 1;
        return 0;
    }
}

/// Cross-platform socket close.
fn closeFd(fd: posix.socket_t) void {
    if (comptime is_windows) {
        _ = win.closesocket(fd);
    } else if (comptime is_linux) {
        _ = linux.close(fd);
    } else {
        _ = std.c.close(fd);
    }
}

/// Raw std.os.linux.* syscalls return -errno as a usize on failure. std.posix.errno
/// misclassifies that when libc is linked (it only handles rv == -1 and reads the C
/// errno global, which a raw syscall never sets), so a -errno slips through as
/// "success" — the same class as the recvfrom OOB fixed in udp.zig. Decode the sign
/// of the raw return directly instead of trusting posix.errno.
fn rawSyscallFailed(rc: usize) bool {
    return @as(isize, @bitCast(rc)) < 0;
}

/// Create a DGRAM socket (cross-platform).
fn createDgramSocket() ?posix.socket_t {
    if (comptime is_linux) {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
        if (rawSyscallFailed(rc)) return null;
        return @intCast(@as(i32, @bitCast(@as(u32, @truncate(rc)))));
    } else if (comptime is_windows) {
        const sock = std.c.socket(std.c.AF.INET, std.c.SOCK.DGRAM, 0);
        if (sock < 0) return null;
        return @ptrFromInt(@as(usize, @intCast(sock)));
    } else {
        const sock = std.c.socket(std.c.AF.INET, std.c.SOCK.DGRAM, 0);
        if (sock < 0) return null;
        return @intCast(sock);
    }
}

/// Receive from a socket (cross-platform).
fn recvFromSocket(fd: posix.socket_t, buf: []u8) ?usize {
    if (comptime is_linux) {
        const rc = linux.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
        if (rawSyscallFailed(rc)) return null;
        return @intCast(rc);
    } else {
        const rc = std.c.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
        if (rc < 0) return null;
        return @intCast(rc);
    }
}

/// Random 16-bit DNS transaction ID. SECURITY (H5): unpredictable per query so
/// off-path attackers cannot forge a matching response.
fn randomTxid() u16 {
    var b: [2]u8 = undefined;
    zio().random(&b);
    return (@as(u16, b[0]) << 8) | @as(u16, b[1]);
}

/// SECURITY (H5): validate that a unicast DNS response actually answers OUR
/// query — matching transaction ID, the QR (response) bit set, exactly one
/// echoed question, and that question's name (case-insensitive) and type equal
/// what we asked. Combined with the connected socket (source filtering) this
/// blocks off-path cache-poisoning of the bootstrap path. Not used for mDNS,
/// whose responses legitimately carry id 0 and no echoed question.
fn responseMatchesQuery(data: []const u8, expected_id: u16, domain: []const u8, qtype: u16) bool {
    if (data.len < HEADER_LEN) return false;
    if (readU16(data, 0) != expected_id) return false; // transaction ID
    if ((readU16(data, 2) & 0x8000) == 0) return false; // QR bit must be set
    if (readU16(data, 4) != 1) return false; // exactly one question echoed
    var q_buf: [512]u8 = undefined;
    const q_end = encodeDomainName(&q_buf, 0, domain) catch return false;
    if (HEADER_LEN + q_end + 4 > data.len) return false;
    if (!std.ascii.eqlIgnoreCase(data[HEADER_LEN .. HEADER_LEN + q_end], q_buf[0..q_end])) return false;
    if (readU16(data, HEADER_LEN + q_end) != qtype) return false; // QTYPE echoed
    if (readU16(data, HEADER_LEN + q_end + 2) != CLASS_IN) return false; // QCLASS echoed
    return true;
}

/// Send a DNS query to a nameserver and wait for a response (2s timeout).
fn sendQuery(nameserver: [4]u8, port: u16, query: []const u8) ?QueryResponse {
    const sock_fd = createDgramSocket() orelse return null;
    defer closeFd(sock_fd);

    const addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = ipv4SockaddrAddr(nameserver),
        .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };

    // SECURITY (H5): connect() the UDP socket so the kernel only delivers
    // datagrams from THIS nameserver, dropping off-path spoofed responses. After
    // connect we send with a null destination (the connected peer).
    if (comptime is_linux) {
        const crc = linux.connect(sock_fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
        if (rawSyscallFailed(crc)) return null;
    } else {
        if (std.c.connect(sock_fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))) != 0) return null;
    }

    if (comptime is_linux) {
        const rc = linux.sendto(sock_fd, query.ptr, query.len, 0, null, 0);
        if (rawSyscallFailed(rc)) return null;
    } else {
        if (std.c.sendto(sock_fd, query.ptr, query.len, 0, null, 0) < 0) return null;
    }

    // Wait for response with 2s timeout (cross-platform)
    const ready = pollReadFd(sock_fd, 2000);
    if (ready <= 0) return null;

    var result: QueryResponse = undefined;
    const n = recvFromSocket(sock_fd, &result.data) orelse return null;
    result.len = n;
    return result;
}

// ─── Helpers ───

fn writeU16(buf: *[512]u8, pos: *usize, value: u16) void {
    buf[pos.*] = @intCast(value >> 8);
    buf[pos.* + 1] = @intCast(value & 0xFF);
    pos.* += 2;
}

fn readU16(data: []const u8, offset: usize) u16 {
    return (@as(u16, data[offset]) << 8) | @as(u16, data[offset + 1]);
}

fn parseIpv4(s: []const u8) ?[4]u8 {
    var addr: [4]u8 = undefined;
    var octets = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (octets.next()) |octet| {
        if (i >= 4) return null;
        addr[i] = std.fmt.parseInt(u8, octet, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;
    return addr;
}

/// Parse meshguard TXT record values.
/// Expected format: "meshguard=ip:port"
/// Returns the endpoint portion ("ip:port") or null if not a meshguard record.
pub fn parseMeshguardTXT(txt: []const u8) ?struct { addr: [4]u8, port: u16 } {
    const prefix = "meshguard=";
    if (!std.mem.startsWith(u8, txt, prefix)) return null;
    const endpoint_str = txt[prefix.len..];

    const colon_idx = std.mem.lastIndexOfScalar(u8, endpoint_str, ':') orelse return null;
    const ip_str = endpoint_str[0..colon_idx];
    const port_str = endpoint_str[colon_idx + 1 ..];

    const addr = parseIpv4(ip_str) orelse return null;
    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;

    return .{ .addr = addr, .port = port };
}

// ─── Tests ───

test "encode domain name" {
    var buf: [512]u8 = undefined;
    const pos = try encodeDomainName(&buf, 0, "example.com");
    try std.testing.expectEqual(pos, 13); // \x07example\x03com\x00
    try std.testing.expectEqual(buf[0], 7);
    try std.testing.expectEqualSlices(u8, buf[1..8], "example");
    try std.testing.expectEqual(buf[8], 3);
    try std.testing.expectEqualSlices(u8, buf[9..12], "com");
    try std.testing.expectEqual(buf[12], 0);
}

test "build query" {
    var buf: [512]u8 = undefined;
    const len = try buildQuery(&buf, "example.com", TYPE_A, 0x1234);
    try std.testing.expect(len > HEADER_LEN);
    // Check ID
    try std.testing.expectEqual(buf[0], 0x12);
    try std.testing.expectEqual(buf[1], 0x34);
    // Check QDCOUNT = 1
    try std.testing.expectEqual(readU16(&buf, 4), 1);
}

test "responseMatchesQuery rejects spoofed/mismatched responses (H5 regression)" {
    const domain = "seed.example.com";
    const id: u16 = 0x1234;

    // Craft a well-formed response: header (QR=1, QDCOUNT=1) + echoed question.
    var buf: [512]u8 = undefined;
    buf[0] = 0x12;
    buf[1] = 0x34; // id
    buf[2] = 0x81;
    buf[3] = 0x80; // flags: QR=1, RD, RA
    buf[4] = 0x00;
    buf[5] = 0x01; // QDCOUNT = 1
    buf[6] = 0x00;
    buf[7] = 0x01; // ANCOUNT = 1
    buf[8] = 0;
    buf[9] = 0;
    buf[10] = 0;
    buf[11] = 0;
    var pos = try encodeDomainName(&buf, HEADER_LEN, domain);
    buf[pos] = TYPE_A >> 8;
    buf[pos + 1] = TYPE_A & 0xFF;
    pos += 2;
    buf[pos] = CLASS_IN >> 8;
    buf[pos + 1] = CLASS_IN & 0xFF;
    pos += 2;
    const total = pos;

    // Legitimate matching response is accepted.
    try std.testing.expect(responseMatchesQuery(buf[0..total], id, domain, TYPE_A));

    // Spoofed responses are all rejected:
    try std.testing.expect(!responseMatchesQuery(buf[0..total], 0x9999, domain, TYPE_A)); // wrong TXID
    try std.testing.expect(!responseMatchesQuery(buf[0..total], id, "evil.example.com", TYPE_A)); // wrong name
    try std.testing.expect(!responseMatchesQuery(buf[0..total], id, domain, TYPE_TXT)); // wrong qtype

    var as_query = buf;
    as_query[2] = 0x01; // clear QR bit → looks like a query, not a response
    try std.testing.expect(!responseMatchesQuery(as_query[0..total], id, domain, TYPE_A));

    // Truncated response rejected (no OOB).
    try std.testing.expect(!responseMatchesQuery(buf[0..5], id, domain, TYPE_A));
}

test "IPv4 sockaddr address preserves octet order" {
    const raw = ipv4SockaddrAddr(.{ 127, 0, 0, 53 });
    try std.testing.expectEqual(@as(u32, 0x7f000035), std.mem.bigToNative(u32, raw));
}

test "parse meshguard TXT" {
    const result = parseMeshguardTXT("meshguard=1.2.3.4:51821").?;
    try std.testing.expectEqual(result.addr, [4]u8{ 1, 2, 3, 4 });
    try std.testing.expectEqual(result.port, 51821);

    // Non-meshguard TXT should return null
    try std.testing.expect(parseMeshguardTXT("v=spf1 include:...") == null);
    try std.testing.expect(parseMeshguardTXT("") == null);
}

test "parse resolv.conf nameservers" {
    // This test just verifies the function doesn't crash — actual content
    // depends on the host system
    var buf: [3][4]u8 = undefined;
    _ = getNameservers(&buf);
}

test "skip domain name" {
    // Regular name: \x03www\x07example\x03com\x00
    const name = [_]u8{ 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const pos = skipDomainName(&name, 0, name.len).?;
    try std.testing.expectEqual(pos, 17);

    // Compression pointer
    const compressed = [_]u8{ 0xC0, 0x0C };
    const pos2 = skipDomainName(&compressed, 0, compressed.len).?;
    try std.testing.expectEqual(pos2, 2);
}
