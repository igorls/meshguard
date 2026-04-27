//! UDP socket abstraction for meshguard gossip.
//! Cross-platform: Linux (syscalls), Windows (Winsock2).

const std = @import("std");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;
const is_ios = builtin.os.tag == .ios;
const is_darwin = is_macos or is_ios;
const posix = std.posix;
const messages = @import("../protocol/messages.zig");

const linux = if (is_linux) std.os.linux else struct {};
const win = if (is_windows) struct {
    const SOCKET = posix.socket_t;
    const POLLIN: i16 = 0x0001;
    const pollfd = extern struct {
        fd: SOCKET,
        events: i16,
        revents: i16,
    };

    extern "ws2_32" fn WSAPoll(fds: [*]pollfd, nfds: u32, timeout: c_int) c_int;
    extern "ws2_32" fn closesocket(socket: SOCKET) c_int;
} else struct {};

/// Received datagram with sender info.
pub const RecvResult = struct {
    data: []const u8,
    sender_addr: [4]u8,
    sender_addr6: ?[16]u8 = null,
    sender_port: u16,

    pub fn endpoint(self: RecvResult) messages.Endpoint {
        if (self.sender_addr6) |addr6| return messages.Endpoint.initV6(addr6, self.sender_port);
        return messages.Endpoint.initV4(self.sender_addr, self.sender_port);
    }
};

/// A non-blocking UDP socket bound to a port.
pub const UdpSocket = struct {
    fd: posix.socket_t,
    port: u16,
    ipv6: bool = false,

    /// Bind a UDP socket to the given port on all interfaces (or a specific address).
    pub fn bind(port: u16) !UdpSocket {
        return bindAddr(.{ 0, 0, 0, 0 }, port);
    }

    /// Bind a UDP socket to a specific address and port.
    pub fn bindAddr(addr: [4]u8, port: u16) !UdpSocket {
        const fd = blk: {
            if (comptime is_linux) {
                const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
                switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    else => |err| return posix.unexpectedErrno(err),
                }
                break :blk @as(posix.socket_t, @intCast(@as(i32, @bitCast(@as(u32, @truncate(rc))))));
            } else if (comptime is_windows) {
                const sock = std.c.socket(std.c.AF.INET, std.c.SOCK.DGRAM, 0);
                if (sock < 0) return error.SocketCreateFailed;
                break :blk @as(posix.socket_t, @ptrFromInt(@as(usize, @intCast(sock))));
            } else {
                // macOS/iOS: use std.c
                const sock = std.c.socket(std.c.AF.INET, std.c.SOCK.DGRAM, 0);
                if (sock < 0) return error.SocketCreateFailed;
                break :blk @as(posix.socket_t, @intCast(sock));
            }
        };
        errdefer closeSocket(fd);

        // Enable SO_REUSEADDR
        const one: u32 = 1;
        if (comptime is_linux) {
            _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(u32));
            _ = linux.setsockopt(fd, posix.SOL.SOCKET, linux.SO.REUSEPORT, std.mem.asBytes(&one), @sizeOf(u32));
        } else if (comptime is_windows) {
            if (std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, @ptrCast(&one), @sizeOf(u32)) != 0) {
                return error.SocketCreateFailed;
            }
        } else {
            try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));
            if (comptime is_darwin) {
                const SO_REUSEPORT: u32 = 0x0200;
                posix.setsockopt(fd, posix.SOL.SOCKET, SO_REUSEPORT, std.mem.asBytes(&one)) catch {};
            }
        }

        // Bind
        var bind_addr = makeSockaddrIn(addr, port);
        if (comptime is_linux) {
            const bind_rc = linux.bind(fd, @ptrCast(&bind_addr), @sizeOf(@TypeOf(bind_addr)));
            switch (posix.errno(bind_rc)) {
                .SUCCESS => {},
                else => |err| return posix.unexpectedErrno(err),
            }
        } else if (comptime is_windows) {
            if (std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(@TypeOf(bind_addr))) != 0) return error.BindFailed;
        } else {
            if (std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(@TypeOf(bind_addr))) != 0) return error.BindFailed;
        }

        // Resolve actual port (important when binding to ephemeral port 0)
        var actual_port = port;
        var bound_addr = bind_addr;
        var bound_len: u32 = @sizeOf(@TypeOf(bind_addr));
        if (comptime is_linux) {
            _ = linux.getsockname(fd, @ptrCast(&bound_addr), &bound_len);
        } else if (comptime is_windows) {
            _ = std.c.getsockname(fd, @ptrCast(&bound_addr), @ptrCast(&bound_len));
        } else {
            _ = std.c.getsockname(fd, @ptrCast(&bound_addr), @ptrCast(&bound_len));
        }
        actual_port = std.mem.bigToNative(u16, bound_addr.port);

        return .{ .fd = fd, .port = actual_port };
    }

    /// Bind an IPv6 UDP socket to a specific address and port.
    pub fn bindAddr6(addr: [16]u8, port: u16) !UdpSocket {
        const fd = blk: {
            if (comptime is_linux) {
                const rc = linux.socket(linux.AF.INET6, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
                switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    else => |err| return posix.unexpectedErrno(err),
                }
                break :blk @as(posix.socket_t, @intCast(@as(i32, @bitCast(@as(u32, @truncate(rc))))));
            } else {
                const sock = std.c.socket(std.c.AF.INET6, std.c.SOCK.DGRAM, 0);
                if (sock < 0) return error.SocketCreateFailed;
                break :blk if (comptime is_windows)
                    @as(posix.socket_t, @ptrFromInt(@as(usize, @intCast(sock))))
                else
                    @as(posix.socket_t, @intCast(sock));
            }
        };
        errdefer closeSocket(fd);

        const one: u32 = 1;
        if (comptime is_linux) {
            _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(u32));
            _ = linux.setsockopt(fd, posix.SOL.SOCKET, linux.SO.REUSEPORT, std.mem.asBytes(&one), @sizeOf(u32));
        } else if (comptime is_windows) {
            if (std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, @ptrCast(&one), @sizeOf(u32)) != 0) {
                return error.SocketCreateFailed;
            }
        } else {
            try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));
        }

        var bind_addr = makeSockaddrIn6(addr, port);
        if (comptime is_linux) {
            const bind_rc = linux.bind(fd, @ptrCast(&bind_addr), @sizeOf(@TypeOf(bind_addr)));
            switch (posix.errno(bind_rc)) {
                .SUCCESS => {},
                else => |err| return posix.unexpectedErrno(err),
            }
        } else if (std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(@TypeOf(bind_addr))) != 0) {
            return error.BindFailed;
        }

        var actual_port = port;
        var bound_addr = bind_addr;
        var bound_len: u32 = @sizeOf(@TypeOf(bind_addr));
        if (comptime is_linux) {
            _ = linux.getsockname(fd, @ptrCast(&bound_addr), &bound_len);
        } else {
            _ = std.c.getsockname(fd, @ptrCast(&bound_addr), @ptrCast(&bound_len));
        }
        actual_port = std.mem.bigToNative(u16, bound_addr.port);

        return .{ .fd = fd, .port = actual_port, .ipv6 = true };
    }

    /// Create a UDP socket for GSO data-plane sends (send-only, no bind).
    /// Linux-only: Sets IP_PMTUDISC_PROBE and increases SO_SNDBUF.
    /// On Windows, creates a basic unbound UDP socket.
    pub fn createGSOSender() !UdpSocket {
        const fd = blk: {
            if (comptime is_linux) {
                const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
                switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    else => |err| return posix.unexpectedErrno(err),
                }
                break :blk @as(posix.socket_t, @intCast(@as(i32, @bitCast(@as(u32, @truncate(rc))))));
            } else if (comptime is_windows) {
                const sock = std.c.socket(std.c.AF.INET, std.c.SOCK.DGRAM, 0);
                if (sock < 0) return error.SocketCreateFailed;
                break :blk @as(posix.socket_t, @ptrFromInt(@as(usize, @intCast(sock))));
            } else {
                const sock = std.c.socket(std.c.AF.INET, std.c.SOCK.DGRAM, 0);
                if (sock < 0) return error.SocketCreateFailed;
                break :blk @as(posix.socket_t, @intCast(sock));
            }
        };
        errdefer closeSocket(fd);

        if (comptime is_linux) {
            // IP_MTU_DISCOVER = IP_PMTUDISC_PROBE (3) — prevents EMSGSIZE on GSO
            const IP_MTU_DISCOVER = 10;
            const IP_PMTUDISC_PROBE: u32 = 3;
            _ = linux.setsockopt(fd, posix.IPPROTO.IP, IP_MTU_DISCOVER, std.mem.asBytes(&IP_PMTUDISC_PROBE), @sizeOf(u32));

            // SO_SNDBUF = 256KB for large GSO super-packets
            const sndbuf: u32 = 262144;
            _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf), @sizeOf(u32));
        }

        return .{ .fd = fd, .port = 0 };
    }

    /// Enable UDP GRO (Generic Receive Offload) on this socket. Linux-only.
    pub fn enableGRO(self: UdpSocket) void {
        if (comptime !is_linux) return;
        const IPPROTO_UDP = 17;
        const UDP_GRO = 104;
        const one: u32 = 1;
        _ = linux.setsockopt(self.fd, IPPROTO_UDP, UDP_GRO, std.mem.asBytes(&one), @sizeOf(u32));
    }

    /// Enable UDP GSO (Generic Segmentation Offload) on this socket. Linux-only.
    pub fn enableGSO(self: UdpSocket) void {
        if (comptime !is_linux) return;
        const IPPROTO_UDP = 17;
        const UDP_SEGMENT = 103;
        const one: u32 = 1;
        _ = linux.setsockopt(self.fd, IPPROTO_UDP, UDP_SEGMENT, std.mem.asBytes(&one), @sizeOf(u32));

        const IP_MTU_DISCOVER = 10;
        const IP_PMTUDISC_PROBE: u32 = 3;
        _ = linux.setsockopt(self.fd, posix.IPPROTO.IP, IP_MTU_DISCOVER, std.mem.asBytes(&IP_PMTUDISC_PROBE), @sizeOf(u32));

        const sndbuf: u32 = 262144;
        _ = linux.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf), @sizeOf(u32));
    }

    /// Send data to a specific address.
    pub fn sendTo(self: UdpSocket, data: []const u8, dest_addr: [4]u8, dest_port: u16) !usize {
        const addr = makeSockaddrIn(dest_addr, dest_port);
        if (comptime is_linux) {
            const rc = linux.sendto(self.fd, data.ptr, data.len, 0, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                else => |err| return posix.unexpectedErrno(err),
            }
            return @intCast(rc);
        } else if (comptime is_windows) {
            const n = std.c.sendto(self.fd, data.ptr, data.len, 0, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
            if (n < 0) return error.SendFailed;
            return @intCast(n);
        } else {
            const n = std.c.sendto(self.fd, data.ptr, data.len, 0, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
            if (n < 0) return error.SendFailed;
            return @intCast(n);
        }
    }

    /// Send data to an IPv6 address.
    pub fn sendTo6(self: UdpSocket, data: []const u8, dest_addr: [16]u8, dest_port: u16) !usize {
        const addr = makeSockaddrIn6(dest_addr, dest_port);
        if (comptime is_linux) {
            const rc = linux.sendto(self.fd, data.ptr, data.len, 0, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                else => |err| return posix.unexpectedErrno(err),
            }
            return @intCast(rc);
        } else {
            const n = std.c.sendto(self.fd, data.ptr, data.len, 0, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
            if (n < 0) return error.SendFailed;
            return @intCast(n);
        }
    }

    pub fn sendToEndpoint(self: UdpSocket, data: []const u8, endpoint: messages.Endpoint) !usize {
        if (endpoint.addr6) |addr6| return self.sendTo6(data, addr6, endpoint.port);
        return self.sendTo(data, endpoint.addr, endpoint.port);
    }

    /// Receive a datagram (non-blocking). Returns null if no data available.
    pub fn recvFrom(self: UdpSocket, buf: []u8) !?RecvResult {
        if (self.ipv6) return self.recvFrom6(buf);
        var src_addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        if (comptime is_linux) {
            const rc = linux.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(&src_addr), &addr_len);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .AGAIN => return null,
                else => |err| return posix.unexpectedErrno(err),
            }
            const n: usize = @intCast(rc);

            // Extract sender IP and port
            const ip_bytes: [4]u8 = @bitCast(src_addr.addr);
            const port_val = std.mem.bigToNative(u16, src_addr.port);

            return RecvResult{
                .data = buf[0..n],
                .sender_addr = ip_bytes,
                .sender_port = port_val,
            };
        } else {
            const rc = std.c.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(&src_addr), &addr_len);
            if (rc < 0) return null;

            const n: usize = @intCast(rc);
            const ip_bytes: [4]u8 = @bitCast(src_addr.addr);
            const port_val = std.mem.bigToNative(u16, src_addr.port);

            return RecvResult{
                .data = buf[0..n],
                .sender_addr = ip_bytes,
                .sender_port = port_val,
            };
        }
    }

    fn recvFrom6(self: UdpSocket, buf: []u8) !?RecvResult {
        var src_addr: posix.sockaddr.in6 = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in6);

        if (comptime is_linux) {
            const rc = linux.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(&src_addr), &addr_len);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .AGAIN => return null,
                else => |err| return posix.unexpectedErrno(err),
            }
            const n: usize = @intCast(rc);
            return RecvResult{
                .data = buf[0..n],
                .sender_addr = .{0} ** 4,
                .sender_addr6 = src_addr.addr,
                .sender_port = std.mem.bigToNative(u16, src_addr.port),
            };
        } else {
            const rc = std.c.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(&src_addr), &addr_len);
            if (rc < 0) return null;
            const n: usize = @intCast(rc);
            return RecvResult{
                .data = buf[0..n],
                .sender_addr = .{0} ** 4,
                .sender_addr6 = src_addr.addr,
                .sender_port = std.mem.bigToNative(u16, src_addr.port),
            };
        }
    }

    /// Poll the socket for readability with a timeout (milliseconds).
    /// Returns true if data is available.
    pub fn pollRead(self: UdpSocket, timeout_ms: i32) !bool {
        if (comptime is_linux or is_darwin) {
            // Use std.posix.poll — works on Linux, macOS, iOS, and Android
            // without requiring C headers (critical for iOS cross-compilation).
            const POLLIN: i16 = 0x0001;
            var fds = [1]std.posix.pollfd{.{
                .fd = self.fd,
                .events = POLLIN,
                .revents = 0,
            }};

            _ = try std.posix.poll(&fds, timeout_ms);
            return (fds[0].revents & POLLIN) != 0;
        } else if (comptime is_windows) {
            var fds = [1]win.pollfd{.{
                .fd = self.fd,
                .events = win.POLLIN,
                .revents = 0,
            }};
            const rc = win.WSAPoll(&fds, 1, timeout_ms);
            if (rc < 0) return error.PollFailed;
            return rc > 0 and (fds[0].revents & win.POLLIN) != 0;
        } else {
            @compileError("Unsupported OS for pollRead");
        }
    }

    /// Close the socket.
    pub fn close(self: *UdpSocket) void {
        closeSocket(self.fd);
    }
};

/// Cross-platform socket close.
fn closeSocket(fd: posix.socket_t) void {
    if (comptime is_windows) {
        _ = win.closesocket(fd);
    } else if (comptime is_linux) {
        _ = linux.close(fd);
    } else {
        _ = std.c.close(fd);
    }
}

/// Build a Linux sockaddr.in from IP bytes and port.
fn makeSockaddrIn(addr: [4]u8, port: u16) posix.sockaddr.in {
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(addr),
        .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
}

fn makeSockaddrIn6(addr: [16]u8, port: u16) posix.sockaddr.in6 {
    return .{
        .family = posix.AF.INET6,
        .port = std.mem.nativeToBig(u16, port),
        .flowinfo = 0,
        .addr = addr,
        .scope_id = 0,
    };
}
