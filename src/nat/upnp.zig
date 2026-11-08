//! UPnP-IGD client for automatic port forwarding on consumer routers.
//!
//! Implements the minimal subset of UPnP Internet Gateway Device protocol:
//!   1. SSDP discovery via multicast (find the gateway)
//!   2. HTTP GET device description XML (find the control URL)
//!   3. SOAP AddPortMapping request (create port forwarding rule)
//!
//! This enables meshguard to automatically forward the gossip port on
//! UPnP-enabled routers (~70% of consumer routers), eliminating the
//! need for coordinated punch in most cases.

const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const is_linux = builtin.os.tag == .linux;
const is_windows = builtin.os.tag == .windows;
const is_macos = builtin.os.tag == .macos;
const is_ios = builtin.os.tag == .ios;
const is_darwin = is_macos or is_ios;
const linux = if (is_linux) std.os.linux else struct {};
const win = if (is_windows) struct {
    // Winsock WSAPoll: readable data is POLLRDNORM (0x0100), not 0x0001 (POLLERR,
    // which makes WSAPoll fail with WSAEINVAL 10022). See net/udp.zig.
    const POLLIN: i16 = 0x0100 | 0x0200; // POLLRDNORM | POLLRDBAND
    const pollfd = extern struct {
        fd: posix.socket_t,
        events: i16,
        revents: i16,
    };

    extern "ws2_32" fn WSAPoll(fds: [*]pollfd, nfds: u32, timeout: c_int) c_int;
} else struct {};

fn linuxSocket(domain: u32, sock_type: u32, protocol: u32) !std.posix.socket_t {
    const fd = std.c.socket(@intCast(domain), @intCast(sock_type), @intCast(protocol));
    switch (std.posix.errno(fd)) {
        .SUCCESS => {
            if (comptime is_windows) {
                return @as(posix.socket_t, @ptrFromInt(@as(usize, @intCast(fd))));
            }
            return @intCast(fd);
        },
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

fn closeSocket(fd: posix.socket_t) void {
    _ = std.c.close(fd);
}

/// Create a socket via raw Linux syscall (replaces removed posix.socket).
/// Returns a blocking Io instance for synchronous operations.
fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn nowMs() i64 {
    return @intCast(std.Io.Timestamp.now(zio(), .awake).toMilliseconds());
}

const Stun = @import("stun.zig");

/// Bound every TCP socket operation against the gateway (connect included on
/// Linux, where SO_SNDTIMEO applies to connect()) so a black-holed router
/// cannot hang startup.
fn setSocketTimeouts(fd: posix.socket_t, timeout_ms: u32) void {
    if (comptime is_windows) {
        // Winsock takes a DWORD of milliseconds.
        _ = std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, @ptrCast(&timeout_ms), @sizeOf(u32));
        _ = std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&timeout_ms), @sizeOf(u32));
    } else {
        const tv = std.c.timeval{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    }
}

/// Milliseconds to hand to the next poll(): never past `deadline_ms`, never more
/// than one slice, 0 once the deadline has passed.
pub fn pollSliceMs(deadline_ms: i64, now_ms: i64) i32 {
    const remaining = deadline_ms - now_ms;
    if (remaining <= 0) return 0;
    return @intCast(@min(remaining, SSDP_POLL_SLICE_MS));
}

/// RFC1918 (10/8, 172.16/12, 192.168/16) or link-local (169.254/16): the only
/// address space a real UPnP gateway can answer an M-SEARCH from.
pub fn isLanAddress(addr: [4]u8) bool {
    if (addr[0] == 10) return true;
    if (addr[0] == 172 and addr[1] >= 16 and addr[1] <= 31) return true;
    if (addr[0] == 192 and addr[1] == 168) return true;
    if (addr[0] == 169 and addr[1] == 254) return true;
    return false;
}

/// Safe to splice into an HTTP request line or header: printable ASCII without
/// whitespace or control bytes (0x21..0x7E). Rejects CR/LF (header injection),
/// SP (request-line splitting), DEL, NUL and every other control byte.
pub fn isRequestTokenSafe(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (c < 0x21 or c > 0x7E) return false;
    }
    return true;
}

/// Strict dotted-quad parser: exactly four all-digit octets without leading
/// zeros, no signs, no separators, no hostnames.
fn parseIpv4Literal(s: []const u8) ?[4]u8 {
    var addr: [4]u8 = undefined;
    var octets = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (octets.next()) |octet| {
        if (i >= 4 or octet.len == 0 or octet.len > 3) return null;
        if (octet.len > 1 and octet[0] == '0') return null;
        for (octet) |c| {
            if (c < '0' or c > '9') return null;
        }
        addr[i] = std.fmt.parseInt(u8, octet, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;
    return addr;
}

/// Whether a LOCATION URL points back at the device that sent it: its host must
/// be an IPv4 literal equal to `responder`. A hostname or a different address
/// would let a rogue SSDP responder redirect the description fetch and the SOAP
/// control requests to a host of its choosing.
pub fn locationHostIs(location: []const u8, responder: [4]u8) bool {
    var host_buf: [64]u8 = undefined;
    var path_buf: [256]u8 = undefined;
    var port: u16 = 80;
    const parts = parseUrl(location, &host_buf, &path_buf, &port) orelse return false;
    const host_ip = parseIpv4Literal(parts.host) orelse return false;
    return std.mem.eql(u8, &host_ip, &responder);
}

fn ipv4Sockaddr(ip: [4]u8, port: u16) posix.sockaddr.in {
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, @as(u32, @bitCast(ip))),
        .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
}

// ─── Constants ───

const SSDP_ADDR = [4]u8{ 239, 255, 255, 250 };
const SSDP_PORT: u16 = 1900;
const SSDP_TIMEOUT_MS: i32 = 3000;
/// Total wall-clock budget for SSDP discovery, fixed when discovery starts.
const SSDP_DISCOVERY_DEADLINE_MS: i64 = 5000;
/// Longest single poll() inside the discovery loop.
const SSDP_POLL_SLICE_MS: i64 = 500;
/// SO_SNDTIMEO / SO_RCVTIMEO applied to the TCP socket used for HTTP/SOAP.
const HTTP_SOCKET_TIMEOUT_MS: u32 = 3000;

const SSDP_SEARCH =
    "M-SEARCH * HTTP/1.1\r\n" ++
    "HOST: 239.255.255.250:1900\r\n" ++
    "MAN: \"ssdp:discover\"\r\n" ++
    "MX: 3\r\n" ++
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" ++
    "\r\n";

const SSDP_SEARCH_V2 =
    "M-SEARCH * HTTP/1.1\r\n" ++
    "HOST: 239.255.255.250:1900\r\n" ++
    "MAN: \"ssdp:discover\"\r\n" ++
    "MX: 3\r\n" ++
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n" ++
    "\r\n";

// ─── Public API ───

pub const UPnPResult = struct {
    external_ip: [4]u8,
    internal_port: u16,
    external_port: u16,
    gateway_ip: [4]u8,
};

pub const UPnPError = error{
    NoGatewayFound,
    DescriptionFetchFailed,
    NoControlUrl,
    MappingFailed,
    ExternalIpFailed,
    ParseError,
    ConnectFailed,
    Timeout,
};

/// Try to add a UPnP port mapping for the given port.
/// Returns the external IP and port if successful.
pub fn addPortMapping(
    internal_port: u16,
    external_port: u16,
    description: []const u8,
    lease_duration: u32,
) UPnPError!UPnPResult {
    // Step 1: SSDP discovery — find the gateway
    var gateway_ip: [4]u8 = undefined;
    var location_buf: [512]u8 = undefined;
    const location = ssdpDiscover(&gateway_ip, &location_buf) orelse return error.NoGatewayFound;

    // Step 2: Parse host and path from location URL
    var host_buf: [64]u8 = undefined;
    var path_buf: [256]u8 = undefined;
    var port: u16 = 80;
    const host_info = parseUrl(location, &host_buf, &path_buf, &port) orelse return error.ParseError;

    // Step 3: HTTP GET device description — find control URL
    var desc_buf: [4096]u8 = undefined;
    const desc = httpGet(gateway_ip, port, host_info.host, host_info.path, &desc_buf) orelse return error.DescriptionFetchFailed;

    // Step 4: Parse control URL from XML description
    var control_path_buf: [256]u8 = undefined;
    const control_path = findControlUrl(desc, &control_path_buf) orelse return error.NoControlUrl;

    // Step 5: Get external IP via SOAP (best-effort — may fail on double NAT)
    var ext_ip: [4]u8 = .{ 0, 0, 0, 0 };
    getExternalIp(gateway_ip, port, host_info.host, control_path, &ext_ip) catch {};

    // Step 6: SOAP AddPortMapping
    addMapping(
        gateway_ip,
        port,
        host_info.host,
        control_path,
        internal_port,
        external_port,
        description,
        lease_duration,
    ) catch return error.MappingFailed;

    return UPnPResult{
        .external_ip = ext_ip,
        .internal_port = internal_port,
        .external_port = external_port,
        .gateway_ip = gateway_ip,
    };
}

/// Try to delete a previously created UPnP port mapping.
pub fn deletePortMapping(external_port: u16) void {
    var gateway_ip: [4]u8 = undefined;
    var location_buf: [512]u8 = undefined;
    const location = ssdpDiscover(&gateway_ip, &location_buf) orelse return;

    var host_buf: [64]u8 = undefined;
    var path_buf: [256]u8 = undefined;
    var port: u16 = 80;
    const host_info = parseUrl(location, &host_buf, &path_buf, &port) orelse return;

    var desc_buf: [4096]u8 = undefined;
    const desc = httpGet(gateway_ip, port, host_info.host, host_info.path, &desc_buf) orelse return;

    var control_path_buf: [256]u8 = undefined;
    const control_path = findControlUrl(desc, &control_path_buf) orelse return;

    deleteMapping(gateway_ip, port, host_info.host, control_path, external_port) catch {};
}

// ─── SSDP Discovery ───

fn ssdpDiscover(gateway_ip: *[4]u8, location_buf: *[512]u8) ?[]const u8 {
    // Create UDP socket for multicast
    const fd = blk: {
        if (comptime is_linux) {
            break :blk linuxSocket(linux.AF.INET, @intCast(linux.SOCK.DGRAM | linux.SOCK.CLOEXEC), 0) catch return null;
        } else {
            break :blk linuxSocket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return null;
        }
    };
    defer closeSocket(fd);

    // Allow reuse
    const one: u32 = 1;
    if (comptime is_windows) {
        _ = std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, @ptrCast(&one), @sizeOf(u32));
    } else {
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
    }

    // Bind to any port (required for receiving multicast responses)
    var bind_addr = ipv4Sockaddr(.{ 0, 0, 0, 0 }, 0);
    _ = std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(posix.sockaddr.in));

    // Set TTL for multicast (4 hops is enough for most LANs)
    const ttl: u32 = 4;
    if (comptime is_linux) {
        posix.setsockopt(fd, posix.IPPROTO.IP, linux.IP.MULTICAST_TTL, std.mem.asBytes(&ttl)) catch {};
    } else if (comptime is_darwin) {
        // Darwin IP_MULTICAST_TTL = 10
        posix.setsockopt(fd, posix.IPPROTO.IP, 10, std.mem.asBytes(&ttl)) catch {};
    }

    const dest_addr = ipv4Sockaddr(SSDP_ADDR, SSDP_PORT);

    // Send M-SEARCH for IGD v1 (most common) and rootdevice (broader)
    if (std.c.sendto(fd, SSDP_SEARCH.ptr, SSDP_SEARCH.len, 0, @ptrCast(&dest_addr), @sizeOf(posix.sockaddr.in)) < 0) {
        return null;
    }
    _ = std.c.sendto(fd, SSDP_SEARCH_V2.ptr, SSDP_SEARCH_V2.len, 0, @ptrCast(&dest_addr), @sizeOf(posix.sockaddr.in));

    // Receive responses, filtering for an IGD device. Many non-IGD devices (TVs,
    // speakers) respond instantly and are skipped.
    // SECURITY: the give-up point is an absolute deadline computed once. The old
    // loop reset a "silence" counter on every datagram, so a trickle of junk SSDP
    // kept discovery running indefinitely.
    const deadline = nowMs() + SSDP_DISCOVERY_DEADLINE_MS;
    while (true) {
        const slice = pollSliceMs(deadline, nowMs());
        if (slice == 0) break;

        if (comptime is_linux or is_darwin) {
            const POLLIN: i16 = 0x0001;
            var fds = [1]posix.pollfd{.{ .fd = fd, .events = POLLIN, .revents = 0 }};
            _ = posix.poll(&fds, slice) catch 0;
            if ((fds[0].revents & POLLIN) == 0) continue;
        } else if (comptime is_windows) {
            const POLLIN: i16 = 0x0100 | 0x0200; // POLLRDNORM | POLLRDBAND (Winsock)
            var fds = [1]win.pollfd{.{ .fd = fd, .events = POLLIN, .revents = 0 }};
            const rc = win.WSAPoll(&fds, 1, slice);
            if (rc <= 0) continue;
            if ((fds[0].revents & POLLIN) == 0) continue;
        }

        var recv_buf: [2048]u8 = undefined;
        var src_addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        const rc = std.c.recvfrom(fd, recv_buf[0..].ptr, recv_buf.len, 0, @ptrCast(&src_addr), &addr_len);
        if (rc < 0) continue;
        const n: usize = @intCast(rc);
        if (n == 0) continue;

        const response = recv_buf[0..n];
        const src_ip: [4]u8 = @bitCast(src_addr.addr);

        // SECURITY: a gateway lives on the LAN. A unicast "response" from a public
        // address (spoofed, or a hostile peer on a shared segment) must not be able
        // to hand us a control URL.
        if (!isLanAddress(src_ip)) continue;

        // Only accept responses that contain InternetGatewayDevice or WANIPConnection
        const is_igd = std.mem.indexOf(u8, response, "InternetGatewayDevice") != null;
        const is_wan = std.mem.indexOf(u8, response, "WANIPConnection") != null;
        if (!is_igd and !is_wan) continue;

        // SECURITY: LOCATION must point back at the responder itself (IPv4 literal
        // equal to the source address), so the description fetch and the SOAP
        // control requests can only ever reach the LAN host that answered.
        const location = parseHeader(response, "LOCATION:", location_buf) orelse continue;
        if (!locationHostIs(location, src_ip)) continue;

        // Found the gateway
        gateway_ip.* = src_ip;
        return location;
    }

    return null;
}

// ─── HTTP Client (minimal) ───

const UrlParts = struct {
    host: []const u8,
    path: []const u8,
};

fn parseUrl(url: []const u8, host_buf: *[64]u8, path_buf: *[256]u8, port: *u16) ?UrlParts {
    // Skip "http://"
    const prefix = "http://";
    if (!std.mem.startsWith(u8, url, prefix)) return null;
    var rest = url[prefix.len..];

    // Extract host:port
    const path_start = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host_port = rest[0..path_start];
    const path = if (path_start < rest.len) rest[path_start..] else "/";

    // SECURITY: host and path are spliced verbatim into the request line and the
    // Host header. Reject whitespace and control bytes so a crafted LOCATION
    // cannot inject headers or split the request.
    if (!isRequestTokenSafe(path)) return null;

    // Parse port if present
    if (std.mem.indexOfScalar(u8, host_port, ':')) |colon| {
        const host = host_port[0..colon];
        if (!isRequestTokenSafe(host)) return null;
        port.* = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch 80;
        if (host.len > host_buf.len) return null;
        @memcpy(host_buf[0..host.len], host);
        if (path.len > path_buf.len) return null;
        @memcpy(path_buf[0..path.len], path);
        return .{ .host = host_buf[0..host.len], .path = path_buf[0..path.len] };
    } else {
        port.* = 80;
        if (!isRequestTokenSafe(host_port)) return null;
        if (host_port.len > host_buf.len) return null;
        @memcpy(host_buf[0..host_port.len], host_port);
        if (path.len > path_buf.len) return null;
        @memcpy(path_buf[0..path.len], path);
        return .{ .host = host_buf[0..host_port.len], .path = path_buf[0..path.len] };
    }
}

fn httpGet(ip: [4]u8, port: u16, host: []const u8, path: []const u8, out: *[4096]u8) ?[]const u8 {
    return httpRequest(ip, port, host, path, "GET", null, null, out);
}

fn httpRequest(
    ip: [4]u8,
    port: u16,
    host: []const u8,
    path: []const u8,
    method: []const u8,
    content_type: ?[]const u8,
    body: ?[]const u8,
    out: *[4096]u8,
) ?[]const u8 {
    // Connect TCP
    const fd = blk: {
        if (comptime is_linux) {
            break :blk linuxSocket(linux.AF.INET, @intCast(linux.SOCK.STREAM | linux.SOCK.CLOEXEC), 0) catch return null;
        } else {
            break :blk linuxSocket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return null;
        }
    };
    defer closeSocket(fd);

    // Bound connect()/write()/read() so an unresponsive gateway cannot block
    // startup (previously connect() was blocking with no timeout at all).
    setSocketTimeouts(fd, HTTP_SOCKET_TIMEOUT_MS);

    const addr = ipv4Sockaddr(ip, port);
    if (std.c.connect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) != 0) {
        return null;
    }

    // Build and send request
    var req_buf: [2048]u8 = undefined;
    var req_len: usize = 0;

    req_len += (std.fmt.bufPrint(req_buf[req_len..], "{s} {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n", .{ method, path, host }) catch return null).len;

    if (content_type) |ct| {
        req_len += (std.fmt.bufPrint(req_buf[req_len..], "Content-Type: {s}\r\n", .{ct}) catch return null).len;
    }
    if (body) |b| {
        req_len += (std.fmt.bufPrint(req_buf[req_len..], "Content-Length: {d}\r\n", .{b.len}) catch return null).len;
    }
    // SOAPAction header (needed for UPnP SOAP requests)
    if (content_type != null and body != null) {
        // Extract SOAPAction from body — look for <u: tag
        if (std.mem.indexOf(u8, body.?, "<u:")) |upos| {
            const action_start = upos + 3; // skip "<u:"
            const action_end = std.mem.indexOfScalarPos(u8, body.?, action_start, ' ') orelse
                (std.mem.indexOfScalarPos(u8, body.?, action_start, '>') orelse body.?.len);
            const action = body.?[action_start..action_end];
            req_len += (std.fmt.bufPrint(req_buf[req_len..], "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#{s}\"\r\n", .{action}) catch return null).len;
        }
    }
    req_len += (std.fmt.bufPrint(req_buf[req_len..], "\r\n", .{}) catch return null).len;

    // Send headers
    _ = writeAll(fd, req_buf[0..req_len]) catch return null;

    // Send body if present
    if (body) |b| {
        _ = writeAll(fd, b) catch return null;
    }

    // Read response (with timeout)
    var total: usize = 0;
    var attempts: u32 = 0;
    while (total < out.len and attempts < 20) : (attempts += 1) {
        if (comptime is_linux or is_darwin) {
            const POLLIN: i16 = 0x0001;
            var fds = [1]posix.pollfd{.{ .fd = fd, .events = POLLIN, .revents = 0 }};
            _ = posix.poll(&fds, 2000) catch break;
            if ((fds[0].revents & POLLIN) == 0) break;
        } else if (comptime is_windows) {
            const POLLIN: i16 = 0x0100 | 0x0200; // POLLRDNORM | POLLRDBAND (Winsock)
            var fds = [1]win.pollfd{.{ .fd = fd, .events = POLLIN, .revents = 0 }};
            const rc = win.WSAPoll(&fds, 1, 2000);
            if (rc <= 0) break;
            if ((fds[0].revents & POLLIN) == 0) break;
        }

        const rc = std.c.read(fd, out[total..].ptr, out.len - total);
        if (rc < 0) break;
        const n: usize = @intCast(rc);
        if (n == 0) break;
        total += n;
    }

    if (total == 0) return null;
    return out[0..total];
}

fn writeAll(fd: posix.fd_t, data: []const u8) !void {
    var sent: usize = 0;
    while (sent < data.len) {
        const rc = std.c.write(fd, data[sent..].ptr, data.len - sent);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }
        const n: usize = @intCast(rc);
        sent += n;
    }
}

// ─── XML Parsing (minimal) ───

/// Find the control URL for WANIPConnection service in the device description XML.
fn findControlUrl(xml: []const u8, out: *[256]u8) ?[]const u8 {
    // Look for WANIPConnection service type
    const wan_svc = "WANIPConnection";
    const svc_pos = std.mem.indexOf(u8, xml, wan_svc) orelse return null;

    // From that position, find <controlURL>
    const control_tag = "<controlURL>";
    const control_end_tag = "</controlURL>";
    const ctrl_pos = std.mem.indexOfPos(u8, xml, svc_pos, control_tag) orelse {
        // Try from the beginning — some routers list controlURL before serviceType
        const alt_pos = std.mem.indexOf(u8, xml, control_tag) orelse return null;
        const alt_start = alt_pos + control_tag.len;
        const alt_end = std.mem.indexOfPos(u8, xml, alt_start, control_end_tag) orelse return null;
        const alt_url = xml[alt_start..alt_end];
        // SECURITY: controlURL becomes the SOAP request target verbatim.
        if (!isRequestTokenSafe(alt_url)) return null;
        if (alt_url.len > out.len) return null;
        @memcpy(out[0..alt_url.len], alt_url);
        return out[0..alt_url.len];
    };
    const start = ctrl_pos + control_tag.len;
    const end = std.mem.indexOfPos(u8, xml, start, control_end_tag) orelse return null;
    const url = xml[start..end];
    if (!isRequestTokenSafe(url)) return null;
    if (url.len > out.len) return null;
    @memcpy(out[0..url.len], url);
    return out[0..url.len];
}

// ─── SOAP Requests ───

fn getLocalIp(gateway_ip: [4]u8) [4]u8 {
    // Create a UDP socket and "connect" to the gateway to determine our local IP
    const fd = blk: {
        if (comptime is_linux) {
            break :blk linuxSocket(linux.AF.INET, @intCast(linux.SOCK.DGRAM | linux.SOCK.CLOEXEC), 0) catch return .{ 0, 0, 0, 0 };
        } else {
            break :blk linuxSocket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return .{ 0, 0, 0, 0 };
        }
    };
    defer closeSocket(fd);

    const addr = ipv4Sockaddr(gateway_ip, 80);
    if (std.c.connect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) != 0) {
        return .{ 0, 0, 0, 0 };
    }

    var local_addr: posix.sockaddr.in = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    if (std.c.getsockname(fd, @ptrCast(&local_addr), &addr_len) != 0) {
        return .{ 0, 0, 0, 0 };
    }

    return @bitCast(local_addr.addr);
}

fn getExternalIp(ip: [4]u8, port: u16, host: []const u8, control_path: []const u8, ext_ip: *[4]u8) !void {
    const body =
        "<?xml version=\"1.0\"?>" ++
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " ++
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" ++
        "<s:Body>" ++
        "<u:GetExternalIPAddress xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">" ++
        "</u:GetExternalIPAddress>" ++
        "</s:Body></s:Envelope>";

    var resp_buf: [4096]u8 = undefined;
    const resp = httpRequest(ip, port, host, control_path, "POST", "text/xml; charset=\"utf-8\"", body, &resp_buf) orelse return error.ConnectFailed;

    // Parse <NewExternalIPAddress>X.X.X.X</NewExternalIPAddress>
    const tag = "<NewExternalIPAddress>";
    const end_tag = "</NewExternalIPAddress>";
    const tag_pos = std.mem.indexOf(u8, resp, tag) orelse return error.ParseError;
    const start = tag_pos + tag.len;
    const end = std.mem.indexOfPos(u8, resp, start, end_tag) orelse return error.ParseError;
    const ip_str = resp[start..end];

    // Parse IP string
    var parts: [4]u8 = .{ 0, 0, 0, 0 };
    var rest: []const u8 = ip_str;
    for (0..4) |i| {
        const dot = std.mem.indexOfScalar(u8, rest, '.');
        const part = if (dot) |d| rest[0..d] else rest;
        parts[i] = std.fmt.parseInt(u8, part, 10) catch return error.ParseError;
        rest = if (dot) |d| rest[d + 1 ..] else rest[rest.len..];
    }
    // SECURITY: an "external" address that cannot be a public endpoint (loopback,
    // link-local, multicast, the mesh prefix, ...) is treated as no external IP at
    // all, so the caller keeps the STUN result instead of advertising it.
    if (!Stun.isPlausiblePublicAddress(parts)) return error.ParseError;
    ext_ip.* = parts;
}

fn addMapping(
    ip: [4]u8,
    port: u16,
    host: []const u8,
    control_path: []const u8,
    internal_port: u16,
    external_port: u16,
    description: []const u8,
    lease_duration: u32,
) !void {
    const local_ip = getLocalIp(ip);
    var local_ip_str: [15]u8 = undefined;
    const local_ip_len = (std.fmt.bufPrint(&local_ip_str, "{d}.{d}.{d}.{d}", .{ local_ip[0], local_ip[1], local_ip[2], local_ip[3] }) catch return error.ParseError).len;

    var body_buf: [1024]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "<?xml version=\"1.0\"?>" ++
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " ++
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" ++
        "<s:Body>" ++
        "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">" ++
        "<NewRemoteHost></NewRemoteHost>" ++
        "<NewExternalPort>{d}</NewExternalPort>" ++
        "<NewProtocol>UDP</NewProtocol>" ++
        "<NewInternalPort>{d}</NewInternalPort>" ++
        "<NewInternalClient>{s}</NewInternalClient>" ++
        "<NewEnabled>1</NewEnabled>" ++
        "<NewPortMappingDescription>{s}</NewPortMappingDescription>" ++
        "<NewLeaseDuration>{d}</NewLeaseDuration>" ++
        "</u:AddPortMapping>" ++
        "</s:Body></s:Envelope>", .{
        external_port,
        internal_port,
        local_ip_str[0..local_ip_len],
        description,
        lease_duration,
    }) catch return error.ParseError;

    var resp_buf: [4096]u8 = undefined;
    const resp = httpRequest(ip, port, host, control_path, "POST", "text/xml; charset=\"utf-8\"", body, &resp_buf) orelse return error.ConnectFailed;

    // Check for success (HTTP 200 in response)
    if (!std.mem.startsWith(u8, resp, "HTTP/1.")) return error.MappingFailed;
    // Find status code
    const space = std.mem.indexOfScalar(u8, resp, ' ') orelse return error.MappingFailed;
    const status_end = std.mem.indexOfScalarPos(u8, resp, space + 1, ' ') orelse return error.MappingFailed;
    const status_str = resp[space + 1 .. status_end];
    const status = std.fmt.parseInt(u16, status_str, 10) catch return error.MappingFailed;
    if (status != 200) return error.MappingFailed;
}

fn deleteMapping(
    ip: [4]u8,
    port: u16,
    host: []const u8,
    control_path: []const u8,
    external_port: u16,
) !void {
    var body_buf: [768]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "<?xml version=\"1.0\"?>" ++
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " ++
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" ++
        "<s:Body>" ++
        "<u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">" ++
        "<NewRemoteHost></NewRemoteHost>" ++
        "<NewExternalPort>{d}</NewExternalPort>" ++
        "<NewProtocol>UDP</NewProtocol>" ++
        "</u:DeletePortMapping>" ++
        "</s:Body></s:Envelope>", .{external_port}) catch return;

    var resp_buf: [4096]u8 = undefined;
    _ = httpRequest(ip, port, host, control_path, "POST", "text/xml; charset=\"utf-8\"", body, &resp_buf);
}

// ─── Header Parsing ───

fn parseHeader(data: []const u8, name: []const u8, out: *[512]u8) ?[]const u8 {
    // Case-insensitive search for the header name
    var i: usize = 0;
    while (i + name.len < data.len) : (i += 1) {
        if (asciiEqlIgnoreCase(data[i..][0..name.len], name)) {
            var pos = i + name.len;
            // Skip whitespace
            while (pos < data.len and data[pos] == ' ') pos += 1;
            // Read until \r\n
            const end = std.mem.indexOfPos(u8, data, pos, "\r\n") orelse data.len;
            const val = std.mem.trimEnd(u8, data[pos..end], " \t");
            // SECURITY: the (LOCATION) value feeds the HTTP request line; refuse
            // anything with whitespace or control bytes inside it.
            if (!isRequestTokenSafe(val)) return null;
            if (val.len > out.len) return null;
            @memcpy(out[0..val.len], val);
            return out[0..val.len];
        }
    }
    return null;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la = if (ca >= 'A' and ca <= 'Z') ca + 32 else ca;
        const lb = if (cb >= 'A' and cb <= 'Z') cb + 32 else cb;
        if (la != lb) return false;
    }
    return true;
}

// ─── Tests ───

test "parseUrl basic" {
    var host_buf: [64]u8 = undefined;
    var path_buf: [256]u8 = undefined;
    var port: u16 = 80;
    const result = parseUrl("http://192.168.1.1:5000/rootDesc.xml", &host_buf, &path_buf, &port) orelse unreachable;
    try std.testing.expectEqualStrings("192.168.1.1", result.host);
    try std.testing.expectEqualStrings("/rootDesc.xml", result.path);
    try std.testing.expectEqual(port, 5000);
}

test "parseUrl no port" {
    var host_buf: [64]u8 = undefined;
    var path_buf: [256]u8 = undefined;
    var port: u16 = 80;
    const result = parseUrl("http://192.168.0.1/desc.xml", &host_buf, &path_buf, &port) orelse unreachable;
    try std.testing.expectEqualStrings("192.168.0.1", result.host);
    try std.testing.expectEqualStrings("/desc.xml", result.path);
    try std.testing.expectEqual(port, 80);
}

test "findControlUrl" {
    const xml =
        "<service>" ++
        "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>" ++
        "<controlURL>/ctl/IPConn</controlURL>" ++
        "</service>";
    var out: [256]u8 = undefined;
    const url = findControlUrl(xml, &out) orelse unreachable;
    try std.testing.expectEqualStrings("/ctl/IPConn", url);
}

test "parseHeader case insensitive" {
    const data = "HTTP/1.1 200 OK\r\nlocation: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n";
    var out: [512]u8 = undefined;
    const val = parseHeader(data, "LOCATION:", &out) orelse unreachable;
    try std.testing.expectEqualStrings("http://192.168.1.1:5000/rootDesc.xml", val);
}

test "parseUrl enforces host and path buffer limits" {
    // (Formerly a no-op "isNewerVersion" test that did not compile: it passed
    // const buffers to parseUrl and asserted `... or true`.)
    var host_buf: [64]u8 = undefined;
    var path_buf: [256]u8 = undefined;
    var port: u16 = 0;
    try std.testing.expect(parseUrl("http://x.x:1/a", &host_buf, &path_buf, &port) != null);
    try std.testing.expectEqual(@as(u16, 1), port);

    // A host longer than the 64-byte buffer is rejected rather than truncated.
    const long_host: []const u8 = "http://" ++ @as([65]u8, @splat('a')) ++ "/x";
    try std.testing.expect(parseUrl(long_host, &host_buf, &path_buf, &port) == null);
    // A path longer than the 256-byte buffer is rejected too.
    const long_path: []const u8 = "http://192.168.1.1/" ++ @as([256]u8, @splat('p'));
    try std.testing.expect(parseUrl(long_path, &host_buf, &path_buf, &port) == null);
}

test "isLanAddress accepts only RFC1918 and link-local responders" {
    try std.testing.expect(isLanAddress(.{ 192, 168, 1, 1 }));
    try std.testing.expect(isLanAddress(.{ 10, 0, 0, 1 }));
    try std.testing.expect(isLanAddress(.{ 172, 16, 0, 1 }));
    try std.testing.expect(isLanAddress(.{ 172, 31, 255, 254 }));
    try std.testing.expect(isLanAddress(.{ 169, 254, 10, 20 }));

    try std.testing.expect(!isLanAddress(.{ 172, 15, 0, 1 }));
    try std.testing.expect(!isLanAddress(.{ 172, 32, 0, 1 }));
    try std.testing.expect(!isLanAddress(.{ 192, 169, 0, 1 }));
    try std.testing.expect(!isLanAddress(.{ 203, 0, 113, 1 })); // public
    try std.testing.expect(!isLanAddress(.{ 127, 0, 0, 1 })); // loopback
    try std.testing.expect(!isLanAddress(.{ 100, 64, 0, 1 })); // CGNAT is not a LAN gateway
    try std.testing.expect(!isLanAddress(.{ 0, 0, 0, 0 }));
}

test "locationHostIs requires an IPv4 literal equal to the responder" {
    const gw = [4]u8{ 192, 168, 1, 1 };
    try std.testing.expect(locationHostIs("http://192.168.1.1:5000/rootDesc.xml", gw));
    try std.testing.expect(locationHostIs("http://192.168.1.1/rootDesc.xml", gw));
    try std.testing.expect(locationHostIs("http://192.168.1.1", gw));

    try std.testing.expect(!locationHostIs("http://192.168.1.2:5000/rootDesc.xml", gw)); // other host
    try std.testing.expect(!locationHostIs("http://router.local:5000/rootDesc.xml", gw)); // hostname
    try std.testing.expect(!locationHostIs("http://192.168.1.1.evil.example/x", gw)); // not a literal
    try std.testing.expect(!locationHostIs("http://192.168.1/x", gw)); // too few octets
    try std.testing.expect(!locationHostIs("http://192.168.001.1/x", gw)); // keep it strict: no padding
    try std.testing.expect(!locationHostIs("https://192.168.1.1/x", gw)); // only http://
    try std.testing.expect(!locationHostIs("http://:5000/x", gw)); // empty host
}

test "isRequestTokenSafe rejects whitespace and control bytes" {
    try std.testing.expect(isRequestTokenSafe("/ctl/IPConn"));
    try std.testing.expect(isRequestTokenSafe("192.168.1.1"));
    try std.testing.expect(isRequestTokenSafe("/a?b=c&d=%20"));
    try std.testing.expect(isRequestTokenSafe("!~")); // 0x21 and 0x7E are the bounds

    try std.testing.expect(!isRequestTokenSafe(""));
    try std.testing.expect(!isRequestTokenSafe("/a b"));
    try std.testing.expect(!isRequestTokenSafe("/a\r\nX-Injected: 1"));
    try std.testing.expect(!isRequestTokenSafe("/a\n"));
    try std.testing.expect(!isRequestTokenSafe("/a\t"));
    try std.testing.expect(!isRequestTokenSafe("/a\x00"));
    try std.testing.expect(!isRequestTokenSafe("/a\x7f"));
    try std.testing.expect(!isRequestTokenSafe("/a\x80"));
}

test "parseUrl rejects hosts and paths that could inject into the request" {
    var host_buf: [64]u8 = undefined;
    var path_buf: [256]u8 = undefined;
    var port: u16 = 80;
    // CRLF in path -> header injection
    try std.testing.expect(parseUrl("http://192.168.1.1/desc.xml\r\nHost: evil", &host_buf, &path_buf, &port) == null);
    // Space in path -> request-line splitting
    try std.testing.expect(parseUrl("http://192.168.1.1/a b", &host_buf, &path_buf, &port) == null);
    // Control byte / space in host (with and without an explicit port)
    try std.testing.expect(parseUrl("http://192.168.1.1\x01:80/x", &host_buf, &path_buf, &port) == null);
    try std.testing.expect(parseUrl("http://192.168 .1.1/x", &host_buf, &path_buf, &port) == null);
    // Empty host
    try std.testing.expect(parseUrl("http:///x", &host_buf, &path_buf, &port) == null);
    try std.testing.expect(parseUrl("http://:80/x", &host_buf, &path_buf, &port) == null);
    // A clean URL still parses
    try std.testing.expect(parseUrl("http://192.168.1.1:5000/rootDesc.xml", &host_buf, &path_buf, &port) != null);
}

test "findControlUrl rejects control URLs with whitespace or control bytes" {
    var out: [256]u8 = undefined;
    const injected =
        "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>" ++
        "<controlURL>/ctl\r\nX-Injected: 1</controlURL>";
    try std.testing.expect(findControlUrl(injected, &out) == null);

    const spaced =
        "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>" ++
        "<controlURL>/ctl IPConn</controlURL>";
    try std.testing.expect(findControlUrl(spaced, &out) == null);

    const empty =
        "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>" ++
        "<controlURL></controlURL>";
    try std.testing.expect(findControlUrl(empty, &out) == null);

    // The fallback branch (controlURL listed before the serviceType) is covered too.
    const alt_injected =
        "<controlURL>/ctl\nX</controlURL>" ++
        "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>";
    try std.testing.expect(findControlUrl(alt_injected, &out) == null);
    const alt_ok =
        "<controlURL>/ctl/IPConn</controlURL>" ++
        "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>";
    try std.testing.expectEqualStrings("/ctl/IPConn", findControlUrl(alt_ok, &out) orelse unreachable);
}

test "parseHeader rejects LOCATION values with control bytes" {
    var out: [512]u8 = undefined;
    const data = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/\x01desc.xml\r\n\r\n";
    try std.testing.expect(parseHeader(data, "LOCATION:", &out) == null);
    const spaced = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/desc.xml HTTP/1.0\r\n\r\n";
    try std.testing.expect(parseHeader(spaced, "LOCATION:", &out) == null);
}

test "pollSliceMs never outlives the deadline and never exceeds one slice" {
    try std.testing.expectEqual(@as(i32, 500), pollSliceMs(5000, 0));
    try std.testing.expectEqual(@as(i32, 500), pollSliceMs(5000, 4500));
    try std.testing.expectEqual(@as(i32, 200), pollSliceMs(5000, 4800));
    try std.testing.expectEqual(@as(i32, 1), pollSliceMs(5000, 4999));
    try std.testing.expectEqual(@as(i32, 0), pollSliceMs(5000, 5000));
    try std.testing.expectEqual(@as(i32, 0), pollSliceMs(5000, 6000)); // past the deadline: stop

    // A deadline fixed at start is unaffected by how many datagrams arrived: the
    // slice only ever shrinks as the clock advances.
    var now: i64 = 0;
    var total: i64 = 0;
    while (true) {
        const slice = pollSliceMs(5000, now);
        if (slice == 0) break;
        now += slice;
        total += slice;
    }
    try std.testing.expectEqual(@as(i64, 5000), total);
}
