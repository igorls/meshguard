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

// ── GRO/GSO offload support ──

const IPPROTO_UDP = 17;
const UDP_GRO = 104;
const UDP_SEGMENT = 103;
const SOL_UDP = 17;

// cmsg header (matches Linux kernel ABI)
const Cmsghdr = extern struct {
    len: usize, // cmsg_len (includes header)
    level: i32,
    type: i32,
};

/// GRO-aware receiver: uses a single 64KB recvmsg with cmsg to receive
/// coalesced UDP packets. The kernel delivers N UDP segments as one buffer.
pub const GROReceiver = struct {
    buf: [65536]u8 = undefined,
    addr: posix.sockaddr.in = undefined,
    cmsg_buf: [128]u8 align(@alignOf(Cmsghdr)) = undefined,
    received: usize = 0,
    segment_size: u16 = 0,

    /// Receive a GRO-coalesced batch. Returns total bytes received.
    /// After this call, `segment_size` contains the per-segment size from
    /// the kernel's cmsg (or 0 if no GRO info — treat entire buffer as one packet).
    pub fn recvGRO(self: *GROReceiver, fd: posix.fd_t) usize {
        self.segment_size = 0;
        self.received = 0;

        var iov = Iovec{
            .base = &self.buf,
            .len = self.buf.len,
        };

        self.addr = std.mem.zeroes(posix.sockaddr.in);
        @memset(&self.cmsg_buf, 0);

        var hdr = Msghdr{
            .msg_name = @ptrCast(&self.addr),
            .msg_namelen = @sizeOf(posix.sockaddr.in),
            .msg_iov = @ptrCast(&iov),
            .msg_iovlen = 1,
            .msg_control = @ptrCast(&self.cmsg_buf),
            .msg_controllen = self.cmsg_buf.len,
            .msg_flags = 0,
        };

        // SYS_recvmsg = 47 on x86_64
        const rc = linux.syscall3(
            @enumFromInt(47),
            @as(usize, @intCast(fd)),
            @intFromPtr(&hdr),
            @as(usize, linux.MSG.DONTWAIT),
        );

        const signed: isize = @bitCast(rc);
        if (signed <= 0) return 0;

        self.received = @intCast(signed);

        // Parse cmsg to find UDP_GRO segment size
        if (hdr.msg_controllen > 0) {
            var offset: usize = 0;
            while (offset + @sizeOf(Cmsghdr) <= hdr.msg_controllen) {
                const cmsg: *const Cmsghdr = @ptrCast(@alignCast(&self.cmsg_buf[offset]));
                if (cmsg.len < @sizeOf(Cmsghdr)) break;

                if (cmsg.level == SOL_UDP and cmsg.type == UDP_GRO) {
                    // Data is a u16 segment size
                    const data_offset = offset + @sizeOf(Cmsghdr);
                    if (data_offset + 2 <= hdr.msg_controllen) {
                        self.segment_size = std.mem.readInt(u16, self.cmsg_buf[data_offset..][0..2], .little);
                    }
                    break;
                }

                // Advance to next cmsg (aligned to usize boundary)
                const cmsg_aligned_len = (cmsg.len + @alignOf(Cmsghdr) - 1) & ~(@as(usize, @alignOf(Cmsghdr)) - 1);
                offset += cmsg_aligned_len;
            }
        }

        return self.received;
    }

    /// Get sender address and port.
    pub fn getSender(self: *const GROReceiver) struct { addr: [4]u8, port: u16 } {
        return .{
            .addr = @bitCast(self.addr.addr),
            .port = std.mem.bigToNative(u16, self.addr.port),
        };
    }
};

/// GSO-aware sender: packs encrypted segments into a linear buffer, sends
/// with a single sendmsg + cmsg(UDP_SEGMENT) to let the kernel/NIC segment.
/// Buffer is capped at ~10 segments to stay under the kernel's EMSGSIZE limit
/// on veth interfaces (65KB total fails, ~15KB works).
pub const GSOSender = struct {
    pub const GSO_MAX_SIZE = 15000; // ~10 segments of 1456B each
    buf: [GSO_MAX_SIZE]u8 = undefined,
    used: usize = 0,
    segment_size: u16 = 0,

    pub fn reset(self: *GSOSender) void {
        self.used = 0;
        self.segment_size = 0;
    }

    /// Append an encrypted segment to the GSO buffer.
    pub fn append(self: *GSOSender, data: []const u8) bool {
        if (self.used + data.len > self.buf.len) return false;
        @memcpy(self.buf[self.used..][0..data.len], data);
        if (self.segment_size == 0) {
            self.segment_size = @intCast(data.len);
        }
        self.used += data.len;
        return true;
    }

    pub const SendResult = struct {
        bytes_sent: usize,
        err: usize, // raw Linux errno (0 = success)
    };

    /// Send all segments with UDP GSO (single syscall).
    /// Returns bytes sent and errno for diagnostic purposes.
    pub fn sendGSO(self: *GSOSender, fd: posix.fd_t, dest_addr: [4]u8, dest_port: u16) SendResult {
        if (self.used == 0) return .{ .bytes_sent = 0, .err = 0 };

        var addr = posix.sockaddr.in{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, dest_port),
            .addr = @bitCast(dest_addr),
            .zero = .{0} ** 8,
        };

        var iov = Iovec{
            .base = &self.buf,
            .len = self.used,
        };

        // Build cmsg with UDP_SEGMENT (u16 segment size)
        // CMSG_LEN(sizeof(u16)) = sizeof(Cmsghdr) + 2 = 18 (for cmsg_len field)
        // CMSG_SPACE(sizeof(u16)) = align_up(18, alignof(Cmsghdr)) = 24 (for msg_controllen)
        const CMSG_LEN_U16 = @sizeOf(Cmsghdr) + 2;
        const CMSG_SPACE_U16 = (CMSG_LEN_U16 + @alignOf(Cmsghdr) - 1) & ~(@as(usize, @alignOf(Cmsghdr)) - 1);

        var cmsg_buf: [CMSG_SPACE_U16]u8 align(@alignOf(Cmsghdr)) = @splat(0);
        const cmsg_hdr: *Cmsghdr = @ptrCast(@alignCast(&cmsg_buf));
        cmsg_hdr.len = CMSG_LEN_U16;
        cmsg_hdr.level = SOL_UDP;
        cmsg_hdr.type = UDP_SEGMENT;
        std.mem.writeInt(u16, cmsg_buf[@sizeOf(Cmsghdr)..][0..2], self.segment_size, .little);

        var hdr = Msghdr{
            .msg_name = @ptrCast(&addr),
            .msg_namelen = @sizeOf(posix.sockaddr.in),
            .msg_iov = @ptrCast(&iov),
            .msg_iovlen = 1,
            .msg_control = @ptrCast(&cmsg_buf),
            .msg_controllen = CMSG_SPACE_U16,
            .msg_flags = 0,
        };

        // SYS_sendmsg = 46 on x86_64
        const rc = linux.syscall3(
            @enumFromInt(46),
            @as(usize, @intCast(fd)),
            @intFromPtr(&hdr),
            @as(usize, linux.MSG.DONTWAIT),
        );

        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            return .{ .bytes_sent = 0, .err = @as(usize, @bitCast(-signed)) };
        }
        return .{ .bytes_sent = @intCast(signed), .err = 0 };
    }
};

/// Zero-copy GSO sender: builds an iovec array pointing directly into pool
/// buffers (no memcpy). Supports up to 64 segments / 65535 bytes total.
/// When the buffer is full, the caller should sendGSO(), reset(), and continue.
pub const ZeroCopyGSOSender = struct {
    iovs: [64]Iovec = undefined,
    used: usize = 0,
    segment_size: u16 = 0,
    total_bytes: usize = 0,

    pub fn reset(self: *ZeroCopyGSOSender) void {
        self.used = 0;
        self.segment_size = 0;
        self.total_bytes = 0;
    }

    /// Append a pointer to an encrypted segment (zero-copy — no memcpy).
    /// Returns false if appending would exceed 64 segments or GSO_MAX_SIZE bytes.
    /// GSO_MAX_SIZE is capped at 15000 to stay under veth's EMSGSIZE limit;
    /// when full, the caller should sendGSO(), reset(), and continue.
    pub const GSO_MAX_SIZE: usize = 15000;
    pub fn append(self: *ZeroCopyGSOSender, data: []const u8) bool {
        if (self.used >= 64 or self.total_bytes + data.len > GSO_MAX_SIZE) return false;
        self.iovs[self.used] = .{
            // sendmsg only reads from the buffer; the cast is safe.
            .base = @constCast(data.ptr),
            .len = data.len,
        };
        if (self.segment_size == 0) {
            self.segment_size = @intCast(data.len);
        }
        self.used += 1;
        self.total_bytes += data.len;
        return true;
    }

    pub const SendResult = struct {
        bytes_sent: usize,
        err: usize, // raw Linux errno (0 = success)
    };

    /// Send all segments with UDP GSO (single syscall, zero-copy from pool).
    pub fn sendGSO(self: *ZeroCopyGSOSender, fd: posix.fd_t, dest_addr: [4]u8, dest_port: u16) SendResult {
        if (self.used == 0) return .{ .bytes_sent = 0, .err = 0 };

        var addr = posix.sockaddr.in{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, dest_port),
            .addr = @bitCast(dest_addr),
            .zero = .{0} ** 8,
        };

        // Build cmsg with UDP_SEGMENT
        const CMSG_LEN_U16 = @sizeOf(Cmsghdr) + 2;
        const CMSG_SPACE_U16 = (CMSG_LEN_U16 + @alignOf(Cmsghdr) - 1) & ~(@as(usize, @alignOf(Cmsghdr)) - 1);

        var cmsg_buf: [CMSG_SPACE_U16]u8 align(@alignOf(Cmsghdr)) = @splat(0);
        const cmsg_hdr: *Cmsghdr = @ptrCast(@alignCast(&cmsg_buf));
        cmsg_hdr.len = CMSG_LEN_U16;
        cmsg_hdr.level = SOL_UDP;
        cmsg_hdr.type = UDP_SEGMENT;
        std.mem.writeInt(u16, cmsg_buf[@sizeOf(Cmsghdr)..][0..2], self.segment_size, .little);

        var hdr = Msghdr{
            .msg_name = @ptrCast(&addr),
            .msg_namelen = @sizeOf(posix.sockaddr.in),
            .msg_iov = @ptrCast(&self.iovs),
            .msg_iovlen = self.used,
            .msg_control = @ptrCast(&cmsg_buf),
            .msg_controllen = CMSG_SPACE_U16,
            .msg_flags = 0,
        };

        const rc = linux.syscall3(
            @enumFromInt(46), // SYS_sendmsg
            @as(usize, @intCast(fd)),
            @intFromPtr(&hdr),
            @as(usize, linux.MSG.DONTWAIT),
        );

        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            return .{ .bytes_sent = 0, .err = @as(usize, @bitCast(-signed)) };
        }
        return .{ .bytes_sent = @intCast(signed), .err = 0 };
    }
};
