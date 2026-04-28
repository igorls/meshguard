const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const IoUring = linux.IoUring;
const Offload = @import("offload.zig");

const UDP_RECV_USER_DATA: u64 = 0x1000_0000_0000_0000;
const UDP_SEND_USER_DATA: u64 = 0x2000_0000_0000_0000;
const UDP_SLOT_MASK: u64 = 0x0000_0000_0000_ffff;

const UDP_GRO = 104;
const SOL_UDP = 17;
const O_NONBLOCK_FLAG: usize = 1 << @bitOffsetOf(posix.O, "NONBLOCK");

const Cmsghdr = extern struct {
    len: usize,
    level: i32,
    type: i32,
};

fn initRing(entries: u16, use_sqpoll: bool) !IoUring {
    if (use_sqpoll) {
        return IoUring.init(entries, linux.IORING_SETUP_SQPOLL) catch {
            return try IoUring.init(entries, 0);
        };
    }
    return try IoUring.init(entries, 0);
}

/// TUN reader backed by io_uring.
/// Pre-submits N read SQEs and resubmits on each completion.
/// The caller processes completed reads identically to the poll()+read() path.
pub const TunRingReader = struct {
    /// Number of concurrent read SQEs in flight.
    pub const RING_DEPTH: u16 = 32;
    /// Max bytes per TUN read (virtio-net header + GSO super-packet).
    pub const BUF_SIZE: usize = Offload.VNET_HDR_LEN + 65535;

    /// Per-slot read buffer. Each outstanding SQE gets its own buffer.
    pub const ReadSlot = struct {
        buf: [BUF_SIZE]u8 align(@alignOf(Offload.VirtioNetHdr)) = undefined,
    };

    // --- Fields (must all come first) ---
    ring: IoUring,
    slots: [RING_DEPTH]ReadSlot,

    /// Initialize the io_uring and pre-submit read SQEs for the TUN fd.
    pub fn init(tun_fd: posix.fd_t) !TunRingReader {
        var self = TunRingReader{
            .ring = try initRing(RING_DEPTH, true),
            .slots = undefined,
        };

        // Pre-submit RING_DEPTH read SQEs
        for (0..RING_DEPTH) |i| {
            _ = try self.ring.read(
                @intCast(i), // user_data = slot index
                tun_fd,
                .{ .buffer = &self.slots[i].buf },
                // offset must be maxInt(u64) for non-seekable fds (TUN device)
                std.math.maxInt(u64),
            );
        }
        _ = try self.ring.submit();

        return self;
    }

    /// Resubmit a read SQE for a completed slot.
    pub fn resubmit(self: *TunRingReader, slot: u32, tun_fd: posix.fd_t) !void {
        _ = try self.ring.read(
            slot, // user_data = slot index
            tun_fd,
            .{ .buffer = &self.slots[slot].buf },
            std.math.maxInt(u64),
        );
        _ = try self.ring.submit();
    }

    /// Wait for and return completed reads.
    /// Returns the number of completions copied into `cqes`.
    /// Blocks until at least `wait_nr` completions are available.
    pub fn waitCompletions(
        self: *TunRingReader,
        cqes: []linux.io_uring_cqe,
        wait_nr: u32,
    ) !u32 {
        return try self.ring.copy_cqes(cqes, wait_nr);
    }

    /// Get the buffer data for a completed read CQE.
    /// Returns null if the CQE indicates an error.
    pub fn getReadData(self: *TunRingReader, cqe: linux.io_uring_cqe) ?[]u8 {
        if (cqe.res <= 0) return null;
        const slot: u32 = @intCast(cqe.user_data);
        const len: usize = @intCast(cqe.res);
        return self.slots[slot].buf[0..len];
    }

    pub fn deinit(self: *TunRingReader) void {
        self.ring.deinit();
    }
};

/// UDP receive/send event loop backed by io_uring.
/// Keeps receive SQEs in flight and uses registered fixed buffers plus SQPOLL
/// when the kernel/container permits it. UDP payload buffers are stable for the
/// lifetime of the ring, so callers can process completions without a copy.
pub const UdpRing = struct {
    pub const RECV_DEPTH: u16 = 32;
    pub const SEND_DEPTH: u16 = 32;
    pub const RING_DEPTH: u16 = 128;
    pub const RECV_BUF_SIZE: usize = 65536;
    pub const SEND_BUF_SIZE: usize = 2048;

    pub const RecvCompletion = struct {
        data: []const u8,
        sender_addr: [4]u8,
        sender_port: u16,
        segment_size: u16,
        slot: u16,
    };

    const RecvSlot = struct {
        buf: [RECV_BUF_SIZE]u8 = undefined,
        cmsg_buf: [128]u8 align(@alignOf(Cmsghdr)) = undefined,
        addr: posix.sockaddr.in = undefined,
        iov: posix.iovec = undefined,
        msg: linux.msghdr = undefined,

        fn setup(self: *RecvSlot) void {
            self.addr = std.mem.zeroes(posix.sockaddr.in);
            self.iov = .{ .base = &self.buf, .len = self.buf.len };
            @memset(&self.cmsg_buf, 0);
            self.msg = .{
                .msg_name = @ptrCast(&self.addr),
                .msg_namelen = @sizeOf(posix.sockaddr.in),
                .msg_iov = @ptrCast(&self.iov),
                .msg_iovlen = 1,
                .msg_control = @ptrCast(&self.cmsg_buf),
                .msg_controllen = self.cmsg_buf.len,
                .msg_flags = 0,
            };
        }

        fn resetForRecv(self: *RecvSlot) void {
            self.addr = std.mem.zeroes(posix.sockaddr.in);
            self.iov.len = self.buf.len;
            @memset(&self.cmsg_buf, 0);
            self.msg.msg_namelen = @sizeOf(posix.sockaddr.in);
            self.msg.msg_controllen = self.cmsg_buf.len;
            self.msg.msg_flags = 0;
        }

        fn segmentSize(self: *const RecvSlot) u16 {
            if (self.msg.msg_controllen == 0) return 0;
            var offset: usize = 0;
            while (offset + @sizeOf(Cmsghdr) <= self.msg.msg_controllen) {
                const cmsg: *const Cmsghdr = @ptrCast(@alignCast(&self.cmsg_buf[offset]));
                if (cmsg.len < @sizeOf(Cmsghdr)) break;
                if (cmsg.level == SOL_UDP and cmsg.type == UDP_GRO) {
                    const data_offset = offset + @sizeOf(Cmsghdr);
                    if (data_offset + 2 <= self.msg.msg_controllen) {
                        return std.mem.readInt(u16, self.cmsg_buf[data_offset..][0..2], .little);
                    }
                    break;
                }
                const aligned_len = (cmsg.len + @alignOf(Cmsghdr) - 1) & ~(@as(usize, @alignOf(Cmsghdr)) - 1);
                offset += aligned_len;
            }
            return 0;
        }
    };

    const SendSlot = struct {
        buf: [SEND_BUF_SIZE]u8 = undefined,
        addr: posix.sockaddr.in = undefined,
        iov: posix.iovec_const = undefined,
        msg: linux.msghdr_const = undefined,
        busy: bool = false,

        fn setup(self: *SendSlot) void {
            self.addr = std.mem.zeroes(posix.sockaddr.in);
            self.iov = .{ .base = &self.buf, .len = 0 };
            self.msg = .{
                .msg_name = @ptrCast(&self.addr),
                .msg_namelen = @sizeOf(posix.sockaddr.in),
                .msg_iov = @ptrCast(&self.iov),
                .msg_iovlen = 1,
                .msg_control = null,
                .msg_controllen = 0,
                .msg_flags = 0,
            };
            self.busy = false;
        }
    };

    ring: IoUring,
    recv_slots: [RECV_DEPTH]RecvSlot,
    send_slots: [SEND_DEPTH]SendSlot,
    registered_iovecs: [RECV_DEPTH + SEND_DEPTH]posix.iovec,
    fd: posix.fd_t,
    original_status_flags: ?usize,
    registered_buffers: bool,
    sqpoll: bool,

    pub fn init(self: *UdpRing, fd: posix.fd_t) !void {
        self.* = UdpRing{
            .ring = try initRing(RING_DEPTH, true),
            .recv_slots = undefined,
            .send_slots = undefined,
            .registered_iovecs = undefined,
            .fd = fd,
            .original_status_flags = null,
            .registered_buffers = false,
            .sqpoll = false,
        };
        self.sqpoll = (self.ring.flags & linux.IORING_SETUP_SQPOLL) != 0;
        errdefer {
            self.restoreFdFlags();
            self.ring.deinit();
        }

        const flags = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
        switch (posix.errno(flags)) {
            .SUCCESS => {
                self.original_status_flags = flags;
                if ((flags & O_NONBLOCK_FLAG) != 0) {
                    _ = posix.system.fcntl(fd, posix.F.SETFL, flags & ~O_NONBLOCK_FLAG);
                }
            },
            else => {},
        }

        for (0..RECV_DEPTH) |i| {
            self.recv_slots[i].setup();
            self.registered_iovecs[i] = .{
                .base = &self.recv_slots[i].buf,
                .len = self.recv_slots[i].buf.len,
            };
        }
        for (0..SEND_DEPTH) |i| {
            self.send_slots[i].setup();
            self.registered_iovecs[RECV_DEPTH + i] = .{
                .base = &self.send_slots[i].buf,
                .len = self.send_slots[i].buf.len,
            };
        }

        if (self.ring.register_buffers(&self.registered_iovecs)) |_| {
            self.registered_buffers = true;
        } else |_| {}

        for (0..RECV_DEPTH) |i| {
            try self.submitRecv(@intCast(i), fd);
        }
        _ = try self.ring.submit();
    }

    fn submitRecv(self: *UdpRing, slot: u16, fd: posix.fd_t) !void {
        self.recv_slots[slot].resetForRecv();
        _ = try self.ring.recvmsg(UDP_RECV_USER_DATA | slot, fd, &self.recv_slots[slot].msg, 0);
    }

    pub fn resubmitRecv(self: *UdpRing, slot: u16, fd: posix.fd_t) !void {
        try self.submitRecv(slot, fd);
        _ = try self.ring.submit();
    }

    pub fn copyCompletions(
        self: *UdpRing,
        cqes: []linux.io_uring_cqe,
        wait_nr: u32,
    ) !u32 {
        return try self.ring.copy_cqes(cqes, wait_nr);
    }

    pub fn recvSlotFromUserData(user_data: u64) ?u16 {
        if ((user_data & UDP_RECV_USER_DATA) == 0) return null;
        const slot: u16 = @intCast(user_data & UDP_SLOT_MASK);
        if (slot >= RECV_DEPTH) return null;
        return slot;
    }

    pub fn recvCompletion(self: *UdpRing, cqe: linux.io_uring_cqe) ?RecvCompletion {
        const slot = recvSlotFromUserData(cqe.user_data) orelse return null;
        if (cqe.res <= 0) return null;
        const len: usize = @intCast(cqe.res);
        const recv_slot = &self.recv_slots[slot];
        return .{
            .data = recv_slot.buf[0..len],
            .sender_addr = @bitCast(recv_slot.addr.addr),
            .sender_port = std.mem.bigToNative(u16, recv_slot.addr.port),
            .segment_size = recv_slot.segmentSize(),
            .slot = slot,
        };
    }

    pub fn noteSendCompletion(self: *UdpRing, cqe: linux.io_uring_cqe) void {
        if ((cqe.user_data & UDP_SEND_USER_DATA) == 0) return;
        const slot: u16 = @intCast(cqe.user_data & UDP_SLOT_MASK);
        if (slot < SEND_DEPTH) self.send_slots[slot].busy = false;
    }

    /// Queue a UDP datagram through IORING_OP_SENDMSG. The payload is copied
    /// into a registered ring-owned slot so the caller's buffer may go out of
    /// scope immediately after this function returns.
    pub fn sendTo(self: *UdpRing, fd: posix.fd_t, data: []const u8, dest_addr: [4]u8, dest_port: u16) !bool {
        if (data.len > SEND_BUF_SIZE) return error.DatagramTooLarge;

        for (0..SEND_DEPTH) |i| {
            if (self.send_slots[i].busy) continue;
            var slot = &self.send_slots[i];
            @memcpy(slot.buf[0..data.len], data);
            slot.addr = .{
                .family = linux.AF.INET,
                .port = std.mem.nativeToBig(u16, dest_port),
                .addr = @bitCast(dest_addr),
                .zero = .{0} ** 8,
            };
            slot.iov = .{ .base = &slot.buf, .len = data.len };
            slot.msg.msg_namelen = @sizeOf(posix.sockaddr.in);
            slot.busy = true;
            _ = try self.ring.sendmsg(UDP_SEND_USER_DATA | @as(u64, @intCast(i)), fd, &slot.msg, 0);
            _ = try self.ring.submit();
            return true;
        }

        return false;
    }

    pub fn deinit(self: *UdpRing) void {
        if (self.registered_buffers) {
            self.ring.unregister_buffers() catch {};
        }
        self.restoreFdFlags();
        self.ring.deinit();
    }

    fn restoreFdFlags(self: *UdpRing) void {
        if (self.original_status_flags) |flags| {
            _ = posix.system.fcntl(self.fd, posix.F.SETFL, flags);
            self.original_status_flags = null;
        }
    }
};

/// Check if io_uring is available AND compatible with TUN devices.
/// Currently disabled: TUN character devices (tun_chr_read_iter) do not
/// reliably support io_uring IORING_OP_READ — reads fail silently or
/// return errors in LXC containers. The io_uring TUN reader code is
/// preserved for future bare-metal testing.
pub fn isAvailable() bool {
    // TODO: Enable after validating io_uring reads on TUN devices work
    // on bare metal (outside LXC containers).
    return false;
}

test "UdpRing parses UDP_GRO cmsg segment size" {
    var slot = UdpRing.RecvSlot{};
    slot.setup();

    const cmsg_len = @sizeOf(Cmsghdr) + @sizeOf(u16);
    const cmsg_space = (cmsg_len + @alignOf(Cmsghdr) - 1) & ~(@as(usize, @alignOf(Cmsghdr)) - 1);
    const hdr: *Cmsghdr = @ptrCast(@alignCast(&slot.cmsg_buf));
    hdr.* = .{
        .len = cmsg_len,
        .level = SOL_UDP,
        .type = UDP_GRO,
    };
    std.mem.writeInt(u16, slot.cmsg_buf[@sizeOf(Cmsghdr)..][0..2], 1440, .little);
    slot.msg.msg_controllen = cmsg_space;

    try std.testing.expectEqual(@as(u16, 1440), slot.segmentSize());
}
