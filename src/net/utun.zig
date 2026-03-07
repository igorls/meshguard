///! macOS utun TUN device interface for userspace WireGuard.
///!
///! Opens a utun device via the kernel control socket API.
///! IP packets written to the utun fd appear on the interface;
///! IP packets sent to the interface can be read from the fd.
///!
///! Each read/write is prefixed with a 4-byte protocol family header
///! (AF_INET = 2 for IPv4, AF_INET6 = 30 for IPv6).
const std = @import("std");
const posix = std.posix;

pub const TunDevice = struct {
    fd: posix.fd_t,
    name: [16]u8,
    name_len: usize,
    /// utun has no vnet_hdr support — always false.
    vnet_hdr: bool = false,

    // macOS PF_SYSTEM / SYSPROTO_CONTROL constants
    const PF_SYSTEM: u32 = 32; // AF_SYSTEM
    const SOCK_DGRAM: u32 = 2;
    const SYSPROTO_CONTROL: u32 = 2;
    const AF_SYS_CONTROL: u16 = 2;

    // ioctl for CTLIOCGINFO
    const CTLIOCGINFO: c_ulong = 0xc0644e03;

    // utun control name
    const UTUN_CONTROL_NAME = "com.apple.net.utun_control";

    // Protocol family header size (prepended to each packet)
    const UTUN_HEADER_LEN: usize = 4;
    const AF_INET: u32 = 2;

    // ctl_info structure for CTLIOCGINFO ioctl
    const CtlInfo = extern struct {
        ctl_id: u32 = 0,
        ctl_name: [96]u8 = .{0} ** 96,
    };

    // sockaddr_ctl for connect()
    const SockaddrCtl = extern struct {
        sc_len: u8 = @sizeOf(SockaddrCtl),
        sc_family: u8 = AF_SYS_CONTROL,
        ss_sysaddr: u16 = AF_SYS_CONTROL,
        sc_id: u32 = 0,
        sc_unit: u32 = 0, // utun unit number + 1 (0 = auto-assign)
        sc_reserved: [5]u32 = .{0} ** 5,
    };

    /// Open a utun device. The name parameter is a hint — macOS auto-assigns
    /// the interface name as utunN. Pass "utun" to auto-assign, or "utun5"
    /// to request a specific unit number.
    /// Requires root or specific entitlements.
    pub fn open(name: []const u8) !TunDevice {
        // Create PF_SYSTEM control socket
        const fd = blk: {
            const c = @cImport({
                @cInclude("sys/socket.h");
            });
            const result = c.socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
            if (result < 0) return error.TunSetupFailed;
            break :blk @as(posix.fd_t, @intCast(result));
        };
        errdefer posix.close(fd);

        // Get the control ID for utun
        var ctl_info = CtlInfo{};
        @memcpy(ctl_info.ctl_name[0..UTUN_CONTROL_NAME.len], UTUN_CONTROL_NAME);

        const ioctl_rc = std.c.ioctl(fd, @as(c_int, @bitCast(@as(c_uint, CTLIOCGINFO))), &ctl_info);
        if (ioctl_rc < 0) return error.TunSetupFailed;

        // Parse requested unit number from name (e.g., "utun5" → unit=6)
        var unit: u32 = 0; // 0 = auto-assign
        if (name.len > 4 and std.mem.startsWith(u8, name, "utun")) {
            if (std.fmt.parseInt(u32, name[4..], 10)) |n| {
                unit = n + 1; // kernel uses 1-based (unit=N+1 creates utunN)
            } else |_| {}
        }

        // Connect to create the utun interface
        var addr = SockaddrCtl{};
        addr.sc_id = ctl_info.ctl_id;
        addr.sc_unit = unit;

        const connect_rc = std.c.connect(
            fd,
            @ptrCast(&addr),
            @sizeOf(SockaddrCtl),
        );
        if (connect_rc < 0) return error.TunSetupFailed;

        // Get the actual interface name via getsockopt(UTUN_OPT_IFNAME)
        const UTUN_OPT_IFNAME: u32 = 2;
        var if_name: [16]u8 = .{0} ** 16;
        var name_len: posix.socklen_t = @sizeOf(@TypeOf(if_name));
        const gso_rc = std.c.getsockopt(
            fd,
            SYSPROTO_CONTROL,
            @intCast(UTUN_OPT_IFNAME),
            &if_name,
            &name_len,
        );
        if (gso_rc < 0) return error.TunSetupFailed;

        // Measure actual name length (null-terminated)
        var actual_len: usize = 0;
        for (if_name) |c| {
            if (c == 0) break;
            actual_len += 1;
        }

        return .{
            .fd = fd,
            .name = if_name,
            .name_len = actual_len,
        };
    }

    /// Read an IP packet from the utun device.
    /// Strips the 4-byte protocol family header.
    /// Returns the number of bytes read (IP packet only), or 0 if no data available.
    pub fn read(self: *TunDevice, buf: []u8) !usize {
        // Read into a temporary buffer that includes space for the 4-byte header
        var read_buf: [65536 + UTUN_HEADER_LEN]u8 = undefined;
        const max_read = @min(buf.len + UTUN_HEADER_LEN, read_buf.len);

        const n = posix.read(self.fd, read_buf[0..max_read]) catch |err| {
            if (err == error.WouldBlock) return 0;
            return err;
        };

        if (n <= UTUN_HEADER_LEN) return 0;

        // Copy the IP packet (skip 4-byte header) into the caller's buffer
        const ip_len = n - UTUN_HEADER_LEN;
        @memcpy(buf[0..ip_len], read_buf[UTUN_HEADER_LEN..][0..ip_len]);
        return ip_len;
    }

    /// Write an IP packet to the utun device (inject into OS network stack).
    /// Prepends the 4-byte AF_INET protocol family header.
    pub fn write(self: *TunDevice, data: []const u8) !void {
        // Detect IP version from first nibble
        const af: u32 = if (data.len > 0 and (data[0] >> 4) == 6) 30 else AF_INET;

        // Prepend the 4-byte protocol family header
        var hdr: [UTUN_HEADER_LEN]u8 = undefined;
        std.mem.writeInt(u32, &hdr, af, .big);
        var iov = [_]posix.iovec_const{
            .{ .base = &hdr, .len = UTUN_HEADER_LEN },
            .{ .base = data.ptr, .len = data.len },
        };
        _ = try posix.writev(self.fd, &iov);
    }

    /// Set the utun fd to non-blocking mode.
    pub fn setNonBlocking(self: *TunDevice) !void {
        // macOS O_NONBLOCK = 0x0004
        const flags = try posix.fcntl(self.fd, posix.F.GETFL, 0);
        _ = try posix.fcntl(
            self.fd,
            posix.F.SETFL,
            flags | @as(usize, 0x0004), // O_NONBLOCK
        );
    }

    /// Get the interface name as a slice.
    pub fn getName(self: *const TunDevice) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Set the MTU of the utun interface.
    pub fn setMtu(self: *const TunDevice, mtu: u32) !void {
        // Use ifconfig via child process — more reliable on macOS than raw ioctls
        // which require the interface to be fully configured first
        const c = @cImport({
            @cInclude("sys/ioctl.h");
            @cInclude("net/if.h");
        });

        const MtuIfreq = extern struct {
            ifr_name: [16]u8 = .{0} ** 16,
            ifr_mtu: i32 = 0,
        };

        var ifr = MtuIfreq{};
        @memcpy(ifr.ifr_name[0..self.name_len], self.name[0..self.name_len]);
        ifr.ifr_mtu = @intCast(mtu);

        const sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return error.SocketFailed;
        defer std.posix.close(sock);

        const rc = std.c.ioctl(sock, @as(c_int, @bitCast(@as(c_uint, c.SIOCSIFMTU))), &ifr);
        if (rc < 0) return error.SetMtuFailed;
    }

    /// Close the utun device. This also destroys the utun interface.
    pub fn close(self: *TunDevice) void {
        posix.close(self.fd);
    }

    /// Poll for readable data with timeout.
    pub fn pollRead(self: *TunDevice, timeout_ms: i32) !bool {
        var fds = [_]posix.pollfd{.{
            .fd = self.fd,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        const n = try posix.poll(&fds, timeout_ms);
        return n > 0 and (fds[0].revents & posix.POLL.IN != 0);
    }

    /// GSO/GRO offloads are not available on macOS utun.
    /// This is a no-op stub for API compatibility with the Linux TUN device.
    pub fn enableOffload(self: *TunDevice) void {
        _ = self;
        // No-op: macOS utun does not support GSO/GRO offloads
    }
};
