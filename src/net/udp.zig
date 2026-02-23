//! UDP socket abstraction for meshguard gossip.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

/// Received datagram with sender info.
pub const RecvResult = struct {
    data: []const u8,
    sender_addr: [4]u8,
    sender_port: u16,
};

/// A non-blocking UDP socket bound to a port.
pub const UdpSocket = struct {
    fd: posix.fd_t,
    port: u16,

    /// Bind a UDP socket to the given port on all interfaces.
    pub fn bind(port: u16) !UdpSocket {
        const fd = try posix.socket(
            linux.AF.INET,
            @intCast(linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC),
            0,
        );
        errdefer posix.close(fd);

        // Enable SO_REUSEADDR
        const one: u32 = 1;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));

        var addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        try posix.bind(fd, &addr.any, addr.getOsSockLen());

        return .{ .fd = fd, .port = port };
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
        var fds = [1]linux.pollfd{.{
            .fd = self.fd,
            .events = linux.POLL.IN,
            .revents = 0,
        }};

        const rc = linux.poll(&fds, 1, timeout_ms);
        if (rc < 0) return error.PollFailed;
        return (fds[0].revents & linux.POLL.IN) != 0;
    }

    /// Close the socket.
    pub fn close(self: *UdpSocket) void {
        posix.close(self.fd);
        self.fd = -1;
    }
};
