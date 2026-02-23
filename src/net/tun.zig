///! Linux TUN device interface for userspace WireGuard.
///!
///! Opens /dev/net/tun to create a virtual network interface.
///! IP packets written to the TUN fd appear on the interface;
///! IP packets sent to the interface can be read from the fd.
///!
///! This replaces the kernel WireGuard module's direct integration
///! with the networking stack.
const std = @import("std");
const posix = std.posix;

pub const TunDevice = struct {
    fd: posix.fd_t,
    name: [16]u8,
    name_len: usize,
    vnet_hdr: bool = false,

    const Offload = @import("offload.zig");

    // ioctl constants for TUN/TAP
    const TUNSETIFF: u32 = 0x400454ca;
    const TUNSETOFFLOAD: u32 = 0x400454d0;
    const IFF_TUN: u16 = 0x0001;
    const IFF_NO_PI: u16 = 0x1000; // No packet info (no 4-byte header)
    const IFF_MULTI_QUEUE: u16 = 0x0100; // Multi-queue TUN for parallel I/O
    const IFF_VNET_HDR: u16 = 0x4000; // Prepend virtio_net_hdr to each packet

    // TUNSETOFFLOAD flags
    const TUN_F_CSUM: u32 = 0x01;
    const TUN_F_TSO4: u32 = 0x02;
    const TUN_F_TSO6: u32 = 0x04;
    const TUN_F_USO4: u32 = 0x20;
    const TUN_F_USO6: u32 = 0x40;

    // ifreq structure for ioctl
    const Ifreq = extern struct {
        ifr_name: [16]u8 = .{0} ** 16,
        ifr_flags: u16 = 0,
        _pad: [22]u8 = .{0} ** 22,
    };

    /// Open a TUN device with the given name.
    /// Requires CAP_NET_ADMIN. Uses IFF_MULTI_QUEUE to allow parallel I/O.
    pub fn open(name: []const u8) !TunDevice {
        // Open /dev/net/tun
        const fd = try posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);
        errdefer posix.close(fd);

        // Set up ifreq with MULTI_QUEUE
        var ifr = Ifreq{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE | IFF_VNET_HDR;
        const copy_len = @min(name.len, 15);
        @memcpy(ifr.ifr_name[0..copy_len], name[0..copy_len]);

        // ioctl TUNSETIFF
        const rc = std.os.linux.ioctl(
            @intCast(fd),
            TUNSETIFF,
            @intFromPtr(&ifr),
        );
        if (rc != 0) {
            posix.close(fd);
            return error.TunSetupFailed;
        }

        // Extract the actual assigned name
        var name_len: usize = 0;
        for (ifr.ifr_name) |c| {
            if (c == 0) break;
            name_len += 1;
        }

        return .{
            .fd = fd,
            .name = ifr.ifr_name,
            .name_len = name_len,
            .vnet_hdr = false, // caller calls enableOffload() after setup
        };
    }

    /// Enable GSO/GRO offloads on a vnet_hdr-capable TUN device.
    /// Call after open() + IP config. Gracefully falls back on failure.
    pub fn enableOffload(self: *TunDevice) void {
        const linux = std.os.linux;
        // Enable only TUN_F_CSUM — no TSO/USO to avoid read-side GSO super-packets.
        // With just TUN_F_CSUM, reads deliver individual packets (gso_type=NONE),
        // but writes can still use GSO by setting virtio_net_hdr.gso_type.
        const offloads: u32 = TUN_F_CSUM;
        const rc = linux.ioctl(@intCast(self.fd), TUNSETOFFLOAD, offloads);
        if (rc != 0) return;

        self.vnet_hdr = true;
    }

    /// Open an additional queue fd above an existing multi-queue TUN device.
    /// The kernel distributes packets across queues by flow hash.
    pub fn openQueue(self: *const TunDevice) !TunDevice {
        const fd = try posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);
        errdefer posix.close(fd);

        var ifr = Ifreq{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE | IFF_VNET_HDR;
        @memcpy(ifr.ifr_name[0..self.name_len], self.name[0..self.name_len]);

        const rc = std.os.linux.ioctl(
            @intCast(fd),
            TUNSETIFF,
            @intFromPtr(&ifr),
        );
        if (rc != 0) {
            posix.close(fd);
            return error.TunSetupFailed;
        }

        return .{
            .fd = fd,
            .name = self.name,
            .name_len = self.name_len,
            .vnet_hdr = self.vnet_hdr,
        };
    }

    /// Read an IP packet from the TUN device.
    /// Returns the number of bytes read, or 0 if no data available.
    pub fn read(self: *TunDevice, buf: []u8) !usize {
        const n = posix.read(self.fd, buf) catch |err| {
            if (err == error.WouldBlock) return 0;
            return err;
        };
        return n;
    }

    /// Write an IP packet to the TUN device (inject into OS network stack).
    pub fn write(self: *TunDevice, data: []const u8) !void {
        if (self.vnet_hdr) {
            // Prepend a zero virtio_net_hdr (GSO_NONE)
            var vhdr_bytes = std.mem.zeroes([Offload.VNET_HDR_LEN]u8);
            var iov = [_]posix.iovec_const{
                .{ .base = &vhdr_bytes, .len = Offload.VNET_HDR_LEN },
                .{ .base = data.ptr, .len = data.len },
            };
            _ = try posix.writev(self.fd, &iov);
        } else {
            _ = try posix.write(self.fd, data);
        }
    }

    /// Write an IP packet with a GSO virtio_net_hdr to the TUN device.
    /// The kernel will segment the large packet for us.
    pub fn writeGSO(self: *const TunDevice, vhdr: Offload.VirtioNetHdr, data: []const u8) !void {
        var hdr_bytes: [Offload.VNET_HDR_LEN]u8 = undefined;
        @memcpy(&hdr_bytes, std.mem.asBytes(&vhdr));
        var iov = [_]posix.iovec_const{
            .{ .base = &hdr_bytes, .len = Offload.VNET_HDR_LEN },
            .{ .base = data.ptr, .len = data.len },
        };
        _ = try posix.writev(self.fd, &iov);
    }

    /// Set the TUN fd to non-blocking mode.
    pub fn setNonBlocking(self: *TunDevice) !void {
        const flags = try posix.fcntl(self.fd, posix.F.GETFL, 0);
        _ = try posix.fcntl(
            self.fd,
            posix.F.SETFL,
            flags | @as(usize, 0x800), // O_NONBLOCK = 0x800 on Linux
        );
    }

    /// Get the interface name as a slice.
    pub fn getName(self: *const TunDevice) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Set the MTU of the TUN interface.
    /// WireGuard adds 80 bytes overhead, so MTU should be 1420 for standard Ethernet.
    pub fn setMtu(self: *const TunDevice, mtu: u32) !void {
        const SIOCSIFMTU: u32 = 0x8922;
        // ifreq for MTU: name + u32 mtu at offset 16
        const MtuIfreq = extern struct {
            ifr_name: [16]u8 = .{0} ** 16,
            ifr_mtu: u32 = 0,
            _pad: [20]u8 = .{0} ** 20,
        };
        var ifr = MtuIfreq{};
        @memcpy(ifr.ifr_name[0..self.name_len], self.name[0..self.name_len]);
        ifr.ifr_mtu = mtu;

        // Need a socket for the ioctl
        const sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return error.SocketFailed;
        defer std.posix.close(sock);

        const rc = std.os.linux.ioctl(
            @intCast(sock),
            SIOCSIFMTU,
            @intFromPtr(&ifr),
        );
        if (rc != 0) return error.SetMtuFailed;
    }

    /// Close the TUN device.
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
};
