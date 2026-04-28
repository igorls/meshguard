//! FreeBSD TUN device interface for userspace WireGuard.
//!
//! Opens the clone TUN device at /dev/tun and uses TUNGIFNAME to discover
//! the kernel-assigned interface name.  FreeBSD's tun(4) prepends a 4-byte
//! address-family header (like macOS utun), so read/write strip/add it.
//!
//! Note: we define FreeBSD ioctl constants manually rather than using
//! @cImport to avoid @bitCast translation errors in cross-compilation.
const std = @import("std");
const posix = std.posix;

// FreeBSD ioctl constants (from sys/ioccom.h, net/if_tun.h, net/if.h)
// _IOR('t', 89, struct ifreq) — get tun interface name
const TUNGIFNAME: c_ulong = 0x40107489;
// _IOW('t', 96, int) — enable address-family header
const TUNSIFHEAD: c_ulong = 0x80047460;
// _IOW('i', 23, struct ifreq) — set interface MTU
const SIOCSIFMTU: c_ulong = 0x80206934;

pub const TunDevice = struct {
    fd: posix.fd_t,
    name: [16]u8,
    name_len: usize,
    /// FreeBSD tun(4) has no virtio-net header support; kept for API parity.
    vnet_hdr: bool = false,

    const HEADER_LEN: usize = 4; // AF family header prepended by tun(4)
    const AF_INET: u32 = 2;

    const Ifreq = extern struct {
        ifr_name: [16]u8 = .{0} ** 16,
        _pad: [24]u8 = .{0} ** 24,
    };

    pub fn open(name: []const u8) !TunDevice {
        // FreeBSD's /dev/tun clone device assigns the actual interface name.
        _ = name;
        const fd = std.c.open("/dev/tun", .{ .ACCMODE = .RDWR });
        switch (posix.errno(fd)) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }
        errdefer _ = std.c.close(fd);

        // Set TUNSIFHEAD to get AF-family headers on read/write
        const one: c_int = 1;
        if (std.c.ioctl(fd, @as(c_int, @bitCast(@as(c_uint, @truncate(TUNSIFHEAD)))), &one) < 0)
            return error.TunSetupFailed;

        var ifr = Ifreq{};
        const rc = std.c.ioctl(fd, @as(c_int, @bitCast(@as(c_uint, @truncate(TUNGIFNAME)))), &ifr);
        if (rc < 0) return error.TunSetupFailed;

        var name_len: usize = 0;
        for (ifr.ifr_name) |ch| {
            if (ch == 0) break;
            name_len += 1;
        }
        if (name_len == 0) return error.TunSetupFailed;

        return .{
            .fd = fd,
            .name = ifr.ifr_name,
            .name_len = name_len,
        };
    }

    /// Read an IP packet from the tun device.
    /// Strips the 4-byte address-family header prepended by tun(4).
    pub fn read(self: *TunDevice, buf: []u8) !usize {
        var read_buf: [65536 + HEADER_LEN]u8 = undefined;
        const max_read = @min(buf.len + HEADER_LEN, read_buf.len);

        const n = posix.read(self.fd, read_buf[0..max_read]) catch |err| {
            if (err == error.WouldBlock) return 0;
            return err;
        };

        if (n <= HEADER_LEN) return 0;

        const ip_len = n - HEADER_LEN;
        @memcpy(buf[0..ip_len], read_buf[HEADER_LEN..][0..ip_len]);
        return ip_len;
    }

    /// Write an IP packet to the tun device.
    /// Prepends the 4-byte address-family header expected by tun(4).
    pub fn write(self: *TunDevice, data: []const u8) !void {
        // Detect IP version from first nibble
        const af: u32 = if (data.len > 0 and (data[0] >> 4) == 6) 30 else AF_INET;

        var hdr: [HEADER_LEN]u8 = undefined;
        std.mem.writeInt(u32, &hdr, af, .big);
        var iov = [_]posix.iovec_const{
            .{ .base = &hdr, .len = HEADER_LEN },
            .{ .base = data.ptr, .len = data.len },
        };
        if (std.c.writev(self.fd, &iov, iov.len) < 0) return error.WriteFailed;
    }

    pub fn setNonBlocking(self: *TunDevice) !void {
        const flags = posix.system.fcntl(self.fd, posix.F.GETFL, @as(usize, 0));
        switch (posix.errno(flags)) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }

        const rc = posix.system.fcntl(
            self.fd,
            posix.F.SETFL,
            @as(usize, @intCast(flags)) | @as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK")),
        );
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    pub fn getName(self: *const TunDevice) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn setMtu(self: *const TunDevice, mtu: u32) !void {
        const MtuIfreq = extern struct {
            ifr_name: [16]u8 = .{0} ** 16,
            ifr_mtu: i32 = 0,
            _pad: [20]u8 = .{0} ** 20,
        };

        var ifr = MtuIfreq{};
        @memcpy(ifr.ifr_name[0..self.name_len], self.name[0..self.name_len]);
        ifr.ifr_mtu = @intCast(mtu);

        const sock = std.c.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        switch (posix.errno(sock)) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }
        defer _ = std.c.close(sock);

        const rc = std.c.ioctl(sock, @as(c_int, @bitCast(@as(c_uint, @truncate(SIOCSIFMTU)))), &ifr);
        if (rc < 0) return error.SetMtuFailed;
    }

    pub fn close(self: *TunDevice) void {
        _ = std.c.close(self.fd);
    }

    pub fn pollRead(self: *TunDevice, timeout_ms: i32) !bool {
        var fds = [_]posix.pollfd{.{
            .fd = self.fd,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        const n = try posix.poll(&fds, timeout_ms);
        return n > 0 and (fds[0].revents & posix.POLL.IN != 0);
    }

    /// GSO/GRO offloads are not available on FreeBSD tun(4).
    pub fn enableOffload(self: *TunDevice) void {
        _ = self;
    }

    /// FreeBSD tun(4) does not support multi-queue.
    pub fn openQueue(self: *const TunDevice) !TunDevice {
        _ = self;
        return error.Unsupported;
    }
};
