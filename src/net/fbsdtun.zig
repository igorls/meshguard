///! FreeBSD TUN device interface for userspace WireGuard.
///!
///! Opens the clone TUN device at /dev/tun and uses TUNGIFNAME to discover
///! the kernel-assigned interface name.
const std = @import("std");
const posix = std.posix;

const c = @cImport({
    @cInclude("sys/ioctl.h");
    @cInclude("net/if.h");
    @cInclude("net/if_tun.h");
});

pub const TunDevice = struct {
    fd: posix.fd_t,
    name: [16]u8,
    name_len: usize,
    vnet_hdr: bool = false,

    const Ifreq = extern struct {
        ifr_name: [16]u8 = .{0} ** 16,
        _pad: [24]u8 = .{0} ** 24,
    };

    pub fn open(name: []const u8) !TunDevice {
        _ = name;
        const fd = std.c.open("/dev/tun", .{ .ACCMODE = .RDWR });
        switch (posix.errno(fd)) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }
        errdefer _ = std.c.close(fd);

        var ifr = Ifreq{};
        const rc = std.c.ioctl(fd, c.TUNGIFNAME, &ifr);
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

    pub fn read(self: *TunDevice, buf: []u8) !usize {
        const n = posix.read(self.fd, buf) catch |err| {
            if (err == error.WouldBlock) return 0;
            return err;
        };
        return n;
    }

    pub fn write(self: *TunDevice, data: []const u8) !void {
        const rc = std.c.write(self.fd, data.ptr, data.len);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }
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

        const rc = std.c.ioctl(sock, c.SIOCSIFMTU, &ifr);
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

    pub fn enableOffload(self: *TunDevice) void {
        _ = self;
    }

    pub fn openQueue(self: *const TunDevice) !TunDevice {
        _ = self;
        return error.Unsupported;
    }
};
