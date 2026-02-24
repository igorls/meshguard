const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const IoUring = linux.IoUring;
const Offload = @import("offload.zig");

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
            .ring = try IoUring.init(RING_DEPTH, 0),
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
