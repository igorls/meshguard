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

        // Enable SO_REUSEADDR + SO_REUSEPORT
        // REUSEPORT allows multiple sockets to bind to the same port;
        // the kernel distributes incoming packets by 4-tuple hash.
        const one: u32 = 1;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));
        try posix.setsockopt(fd, posix.SOL.SOCKET, linux.SO.REUSEPORT, std.mem.asBytes(&one));

        var addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        try posix.bind(fd, &addr.any, addr.getOsSockLen());

        return .{ .fd = fd, .port = port };
    }

    /// Create a UDP socket for GSO data-plane sends (send-only, no bind).
    /// Sets IP_PMTUDISC_PROBE (required for >MTU GSO sendmsg)
    /// and increases SO_SNDBUF for large GSO batches.
    pub fn createGSOSender() !UdpSocket {
        const fd = try posix.socket(
            linux.AF.INET,
            @intCast(linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC),
            0,
        );
        errdefer posix.close(fd);

        // IP_MTU_DISCOVER = IP_PMTUDISC_PROBE (3) — prevents EMSGSIZE on GSO
        const IP_MTU_DISCOVER = 10;
        const IP_PMTUDISC_PROBE: u32 = 3;
        posix.setsockopt(fd, posix.IPPROTO.IP, IP_MTU_DISCOVER, std.mem.asBytes(&IP_PMTUDISC_PROBE)) catch {};

        // SO_SNDBUF = 256KB for large GSO super-packets
        const sndbuf: u32 = 262144;
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf)) catch {};

        return .{ .fd = fd, .port = 0 };
    }

    /// Enable UDP GRO (Generic Receive Offload) on this socket.
    /// When enabled, the kernel coalesces incoming UDP packets into a single
    /// 64KB buffer, reducing recvmsg syscalls by ~44x.
    pub fn enableGRO(self: UdpSocket) void {
        const IPPROTO_UDP = 17;
        const UDP_GRO = 104;
        const one: u32 = 1;
        posix.setsockopt(self.fd, IPPROTO_UDP, UDP_GRO, std.mem.asBytes(&one)) catch {};
    }

    /// Enable UDP GSO (Generic Segmentation Offload) on this socket.
    /// Sets IP_PMTUDISC_PROBE to prevent EMSGSIZE on oversized sendmsg,
    /// and increases SO_SNDBUF for large GSO batches.
    /// When enabled, sendmsg can pass a 64KB buffer with a cmsg indicating
    /// segment size — the kernel/NIC splits it into individual UDP packets.
    pub fn enableGSO(self: UdpSocket) void {
        const IPPROTO_UDP = 17;
        const UDP_SEGMENT = 103;
        const one: u32 = 1;
        posix.setsockopt(self.fd, IPPROTO_UDP, UDP_SEGMENT, std.mem.asBytes(&one)) catch {};

        // Set IP_MTU_DISCOVER = IP_PMTUDISC_PROBE (3)
        // This prevents EMSGSIZE when sending > MTU via GSO.
        // wireguard-go does this in conn_linux.go.
        const IP_MTU_DISCOVER = 10;
        const IP_PMTUDISC_PROBE: u32 = 3;
        posix.setsockopt(self.fd, posix.IPPROTO.IP, IP_MTU_DISCOVER, std.mem.asBytes(&IP_PMTUDISC_PROBE)) catch {};

        // Increase send buffer for GSO super-packets (256KB)
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
