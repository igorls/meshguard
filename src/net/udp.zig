//! UDP socket abstraction for meshguard gossip.
//! Cross-platform: Linux (POSIX), Windows (Winsock2).

const std = @import("std");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;
const posix = std.posix;

const linux = if (is_linux) std.os.linux else struct {};

/// Received datagram with sender info.
pub const RecvResult = struct {
    data: []const u8,
    sender_addr: [4]u8,
    sender_port: u16,
};

/// A non-blocking UDP socket bound to a port.
pub const UdpSocket = struct {
    fd: posix.socket_t,
    port: u16,

    /// Bind a UDP socket to the given port on all interfaces (or a specific address).
    pub fn bind(port: u16) !UdpSocket {
        return bindAddr(.{ 0, 0, 0, 0 }, port);
    }

    /// Bind a UDP socket to a specific address and port.
    pub fn bindAddr(addr: [4]u8, port: u16) !UdpSocket {
        const fd = blk: {
            if (comptime is_linux) {
                break :blk try posix.socket(
                    linux.AF.INET,
                    @intCast(linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC),
                    0,
                );
            } else {
                // Windows and macOS: create socket without SOCK_NONBLOCK
                break :blk try posix.socket(
                    posix.AF.INET,
                    posix.SOCK.DGRAM,
                    0,
                );
            }
        };
        errdefer closeSocket(fd);

        // Enable SO_REUSEADDR
        const one: u32 = 1;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));
        if (comptime is_linux) {
            // SO_REUSEPORT is Linux and macOS
            posix.setsockopt(fd, posix.SOL.SOCKET, linux.SO.REUSEPORT, std.mem.asBytes(&one)) catch {};
        } else if (comptime is_macos) {
            // macOS SO_REUSEPORT = 0x0200
            const SO_REUSEPORT: u32 = 0x0200;
            posix.setsockopt(fd, posix.SOL.SOCKET, SO_REUSEPORT, std.mem.asBytes(&one)) catch {};
        }

        var bind_addr = std.net.Address.initIp4(addr, port);
        try posix.bind(fd, &bind_addr.any, bind_addr.getOsSockLen());

        // Resolve actual port (important when binding to ephemeral port 0)
        var actual_port = port;
        var bound_addr = bind_addr;
        var bound_len = bind_addr.getOsSockLen();
        posix.getsockname(fd, &bound_addr.any, &bound_len) catch {};
        actual_port = bound_addr.getPort();

        return .{ .fd = fd, .port = actual_port };
    }

    /// Create a UDP socket for GSO data-plane sends (send-only, no bind).
    /// Linux-only: Sets IP_PMTUDISC_PROBE and increases SO_SNDBUF.
    /// On Windows, creates a basic unbound UDP socket.
    pub fn createGSOSender() !UdpSocket {
        const fd = blk: {
            if (comptime is_linux) {
                break :blk try posix.socket(
                    linux.AF.INET,
                    @intCast(linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC),
                    0,
                );
            } else {
                break :blk try posix.socket(
                    posix.AF.INET,
                    posix.SOCK.DGRAM,
                    0,
                );
            }
        };
        errdefer closeSocket(fd);

        if (comptime is_linux) {
            // IP_MTU_DISCOVER = IP_PMTUDISC_PROBE (3) — prevents EMSGSIZE on GSO
            const IP_MTU_DISCOVER = 10;
            const IP_PMTUDISC_PROBE: u32 = 3;
            posix.setsockopt(fd, posix.IPPROTO.IP, IP_MTU_DISCOVER, std.mem.asBytes(&IP_PMTUDISC_PROBE)) catch {};

            // SO_SNDBUF = 256KB for large GSO super-packets
            const sndbuf: u32 = 262144;
            posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf)) catch {};
        }

        return .{ .fd = fd, .port = 0 };
    }

    /// Enable UDP GRO (Generic Receive Offload) on this socket. Linux-only.
    pub fn enableGRO(self: UdpSocket) void {
        if (comptime !is_linux) return;
        const IPPROTO_UDP = 17;
        const UDP_GRO = 104;
        const one: u32 = 1;
        posix.setsockopt(self.fd, IPPROTO_UDP, UDP_GRO, std.mem.asBytes(&one)) catch {};
    }

    /// Enable UDP GSO (Generic Segmentation Offload) on this socket. Linux-only.
    pub fn enableGSO(self: UdpSocket) void {
        if (comptime !is_linux) return;
        const IPPROTO_UDP = 17;
        const UDP_SEGMENT = 103;
        const one: u32 = 1;
        posix.setsockopt(self.fd, IPPROTO_UDP, UDP_SEGMENT, std.mem.asBytes(&one)) catch {};

        const IP_MTU_DISCOVER = 10;
        const IP_PMTUDISC_PROBE: u32 = 3;
        posix.setsockopt(self.fd, posix.IPPROTO.IP, IP_MTU_DISCOVER, std.mem.asBytes(&IP_PMTUDISC_PROBE)) catch {};

        const sndbuf: u32 = 262144;
        posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf)) catch {};
    }

    /// Send data to a specific address.
    pub fn sendTo(self: UdpSocket, data: []const u8, dest_addr: [4]u8, dest_port: u16) !usize {
        const addr = std.net.Address.initIp4(dest_addr, dest_port);
        return posix.sendto(self.fd, data, 0, &addr.any, addr.getOsSockLen());
    }

    /// Receive a datagram (non-blocking). Returns null if no data available.
    pub fn recvFrom(self: UdpSocket, buf: []u8) !?RecvResult {
        var src_addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        const n = posix.recvfrom(self.fd, buf, 0, @ptrCast(&src_addr), &addr_len) catch |err| {
            if (err == error.WouldBlock) return null;
            return err;
        };

        // Extract sender IP and port
        const ip_bytes: [4]u8 = @bitCast(src_addr.addr);
        const port = std.mem.bigToNative(u16, src_addr.port);

        return RecvResult{
            .data = buf[0..n],
            .sender_addr = ip_bytes,
            .sender_port = port,
        };
    }

    /// Poll the socket for readability with a timeout (milliseconds).
    /// Returns true if data is available.
    pub fn pollRead(self: UdpSocket, timeout_ms: i32) !bool {
        if (comptime is_linux or is_macos) {
            // Use libc poll() — works on Linux, macOS, and Android.
            // Android's seccomp blocks the old poll syscall (7) on modern Android.
            const c = @cImport(@cInclude("poll.h"));
            var fds = [1]c.struct_pollfd{.{
                .fd = self.fd,
                .events = c.POLLIN,
                .revents = 0,
            }};

            const rc = c.poll(&fds, 1, timeout_ms);
            if (rc < 0) return error.PollFailed;
            return (fds[0].revents & c.POLLIN) != 0;
        } else if (comptime is_windows) {
            // Use WSAPoll directly from ws2_32 (mingw doesn't export poll)
            const ws2 = std.os.windows.ws2_32;
            var fds = [1]ws2.pollfd{.{
                .fd = self.fd,
                .events = ws2.POLL.IN,
                .revents = 0,
            }};
            const rc = ws2.WSAPoll(&fds, 1, timeout_ms);
            if (rc < 0) return error.PollFailed;
            return rc > 0 and (fds[0].revents & ws2.POLL.IN) != 0;
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
        // Windows sockets must be closed with closesocket, not CloseHandle
        _ = std.os.windows.ws2_32.closesocket(fd);
    } else {
        posix.close(fd);
    }
}
