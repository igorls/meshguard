///! Batch UDP I/O using Linux recvmmsg/sendmmsg syscalls.
///!
///! Operates on any existing socket fd — no new socket type needed.
///! Reduces syscall overhead by batching up to BATCH_SIZE packets per call.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

pub const BATCH_SIZE: usize = 64;
pub const MAX_PACKET: usize = 2048;

// Linux iovec — must match kernel ABI exactly
const Iovec = extern struct {
    base: [*]u8,
    len: usize,
};

// Linux msghdr
const Msghdr = extern struct {
    msg_name: ?*anyopaque,
    msg_namelen: u32,
    msg_iov: [*]Iovec,
    msg_iovlen: usize,
    msg_control: ?*anyopaque = null,
    msg_controllen: usize = 0,
    msg_flags: i32 = 0,
};

// Linux mmsghdr
const Mmsghdr = extern struct {
    msg_hdr: Msghdr,
    msg_len: u32,
};

// Syscall numbers (x86_64 Linux)
const SYS_recvmmsg = 299;
const SYS_sendmmsg = 307;

/// Pre-allocated batch receive state.
/// After declaring, call `setupPointers()` to wire up internal self-references.
/// Do NOT move this struct after calling setupPointers (pointers become dangling).
pub const BatchReceiver = struct {
    bufs: [BATCH_SIZE][MAX_PACKET]u8 = undefined,
    iovecs: [BATCH_SIZE]Iovec = undefined,
    addrs: [BATCH_SIZE]posix.sockaddr.in = undefined,
    msgs: [BATCH_SIZE]Mmsghdr = undefined,
    ready: bool = false,

    /// Wire up internal pointers. Must be called ONCE, AFTER the struct
    /// is at its final stack/heap location. Moving the struct after this
    /// invalidates all pointers.
    pub fn setupPointers(self: *BatchReceiver) void {
        for (0..BATCH_SIZE) |i| {
            self.iovecs[i] = .{
                .base = &self.bufs[i],
                .len = MAX_PACKET,
            };
            self.addrs[i] = std.mem.zeroes(posix.sockaddr.in);
            self.msgs[i] = .{
                .msg_hdr = .{
                    .msg_name = @ptrCast(&self.addrs[i]),
                    .msg_namelen = @sizeOf(posix.sockaddr.in),
                    .msg_iov = @ptrCast(&self.iovecs[i]),
                    .msg_iovlen = 1,
                },
                .msg_len = 0,
            };
        }
        self.ready = true;
    }

    /// Receive a batch of packets from an existing fd.
    /// Returns the number of packets received (0 if none available).
    pub fn recvBatch(self: *BatchReceiver, fd: posix.fd_t) usize {
        // Reset msg_namelen for each message
        for (0..BATCH_SIZE) |i| {
            self.msgs[i].msg_hdr.msg_namelen = @sizeOf(posix.sockaddr.in);
            self.iovecs[i].len = MAX_PACKET;
        }

        const rc = linux.syscall6(
            @enumFromInt(SYS_recvmmsg),
            @as(usize, @intCast(fd)),
            @intFromPtr(&self.msgs),
            BATCH_SIZE,
            @as(usize, linux.MSG.DONTWAIT),
            0,
            0,
        );

        const signed: isize = @bitCast(rc);
        if (signed <= 0) return 0;
        return @intCast(signed);
    }

    /// Get the i-th received packet data.
    pub fn getPacket(self: *BatchReceiver, i: usize) []const u8 {
        return self.bufs[i][0..self.msgs[i].msg_len];
    }

    /// Get the i-th sender address and port.
    pub fn getSender(self: *BatchReceiver, i: usize) struct { addr: [4]u8, port: u16 } {
        return .{
            .addr = @bitCast(self.addrs[i].addr),
            .port = std.mem.bigToNative(u16, self.addrs[i].port),
        };
    }
};

/// Pre-allocated batch send state.
pub const BatchSender = struct {
    iovecs: [BATCH_SIZE]Iovec = undefined,
    addrs: [BATCH_SIZE]posix.sockaddr.in = undefined,
    msgs: [BATCH_SIZE]Mmsghdr = undefined,
    count: usize = 0,

    /// Queue a packet for sending. Data pointer must remain valid until sendFlush.
    pub fn queue(self: *BatchSender, data: []const u8, dest_addr: [4]u8, dest_port: u16) void {
        if (self.count >= BATCH_SIZE) return;
        const i = self.count;

        self.iovecs[i] = .{
            .base = @constCast(data.ptr),
            .len = data.len,
        };

        self.addrs[i] = .{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, dest_port),
            .addr = @bitCast(dest_addr),
            .zero = .{0} ** 8,
        };

        self.msgs[i] = .{
            .msg_hdr = .{
                .msg_name = @ptrCast(&self.addrs[i]),
                .msg_namelen = @sizeOf(posix.sockaddr.in),
                .msg_iov = @ptrCast(&self.iovecs[i]),
                .msg_iovlen = 1,
            },
            .msg_len = 0,
        };

        self.count += 1;
    }

    /// Flush all queued packets via sendmmsg. Returns packets sent.
    pub fn flush(self: *BatchSender, fd: posix.fd_t) usize {
        if (self.count == 0) return 0;

        const rc = linux.syscall4(
            @enumFromInt(SYS_sendmmsg),
            @as(usize, @intCast(fd)),
            @intFromPtr(&self.msgs),
            self.count,
            @as(usize, linux.MSG.DONTWAIT),
        );

        self.count = 0;

        const signed: isize = @bitCast(rc);
        if (signed <= 0) return 0;
        return @intCast(signed);
    }

    /// Reset without sending.
    pub fn reset(self: *BatchSender) void {
        self.count = 0;
    }
};
