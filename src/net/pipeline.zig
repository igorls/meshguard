///! Zero-copy parallel encryption pipeline for the data plane.
///!
///! Architecture (2-stage with opportunistic Tx):
///!   Stage 1 - TUN Reader: reads TUN → GSO split → alloc buffer indices from pool →
///!             build PacketBatch per peer → assign nonces → push to CryptoQueue + PeerTxRing
///!   Stage 2 - Crypto Worker: pop batch from CryptoQueue → encrypt all packets in-place →
///!             mark batch Ready → tryLock peer.send_lock → if acquired, drain Ready batches
///!             in order and sendmmsg (opportunistic Tx)
///!
///! Key design properties:
///!   - Zero-copy: packets copied once (TUN→pool buffer at offset 16), never again
///!   - Index-passing: only u16 indices (2 bytes) cross thread boundaries, not 1500B packets
///!   - Batch-amortized: at 8 Gbps, only ~11k cross-thread ops/sec (not 700k per-packet)
///!   - Cache-line aligned: no false sharing between threads
///!   - Ordering: per-peer TxRing + atomic state machine ensures strict nonce sequence
const std = @import("std");
const posix = std.posix;

pub const CACHE_LINE = 64;
pub const BATCH_SIZE: usize = 64;
pub const WG_HEADER_LEN: usize = 16; // WireGuard TransportHeader size
pub const MAX_BUFFERS: usize = 16384; // ~32MB pool
pub const MAX_BATCHES: usize = 1024;
pub const CRYPTO_QUEUE_SIZE: usize = 2048; // must be power of 2

pub const BatchState = enum(u32) {
    Empty = 0,
    Encrypting = 1,
    Ready = 2,
};

/// Cache-line aligned packet buffer for zero-copy encryption.
/// TUN reader writes IP payload at data[16..], leaving room for the WG transport header.
/// Crypto worker encrypts in-place and writes the header at data[0..16].
/// Result: data[0..len] is the complete WG transport message ready to sendmmsg.
pub const PacketBuffer = struct {
    data: [2048]u8 align(CACHE_LINE) = undefined,
    len: u16 = 0,
    endpoint_addr: [4]u8 = .{ 0, 0, 0, 0 },
    endpoint_port: u16 = 0,
};

/// A batch of packets destined for a single peer — the unit of work in the pipeline.
/// Uses Struct-of-Arrays layout for SIMD-friendly iteration.
pub const PacketBatch = struct {
    state: std.atomic.Value(u32) align(CACHE_LINE) = std.atomic.Value(u32).init(@intFromEnum(BatchState.Empty)),
    peer_slot: usize = 0,
    count: u16 = 0,

    // SoA layout for cache-friendly sequential access
    buf_indices: [BATCH_SIZE]u16 = undefined,
    lengths: [BATCH_SIZE]u16 = undefined,
    nonces: [BATCH_SIZE]u64 = undefined,
};

/// Global zero-copy memory pool for the data plane.
/// Pre-allocates all buffers and batches at startup — zero allocations in the hot path.
pub const DataPlanePool = struct {
    buffers: [MAX_BUFFERS]PacketBuffer align(CACHE_LINE) = undefined,
    batches: [MAX_BATCHES]PacketBatch align(CACHE_LINE) = undefined,

    // Buffer free-list (mutex-protected, but only hit once per batch of 64)
    buf_lock: std.Thread.Mutex = .{},
    free_bufs: [MAX_BUFFERS]u16 = undefined,
    free_buf_count: usize = MAX_BUFFERS,

    // Batch free-list
    batch_lock: std.Thread.Mutex = .{},
    free_batches: [MAX_BATCHES]u16 = undefined,
    free_batch_count: usize = MAX_BATCHES,

    /// Initialize all free-lists.
    pub fn init(self: *DataPlanePool) void {
        for (0..MAX_BUFFERS) |i| {
            self.free_bufs[i] = @intCast(i);
        }
        for (0..MAX_BATCHES) |i| {
            self.free_batches[i] = @intCast(i);
            self.batches[i] = .{};
        }
    }

    /// Allocate a single buffer index from the pool.
    pub fn allocBuffer(self: *DataPlanePool) ?u16 {
        self.buf_lock.lock();
        defer self.buf_lock.unlock();
        if (self.free_buf_count == 0) return null;
        self.free_buf_count -= 1;
        return self.free_bufs[self.free_buf_count];
    }

    /// Return buffer indices to the pool (bulk free).
    pub fn freeBuffers(self: *DataPlanePool, indices: []const u16) void {
        self.buf_lock.lock();
        defer self.buf_lock.unlock();
        for (indices) |idx| {
            self.free_bufs[self.free_buf_count] = idx;
            self.free_buf_count += 1;
        }
    }

    /// Allocate a batch of buffer indices at once (bulk allocation).
    pub fn allocBufferBatch(self: *DataPlanePool, out: []u16) usize {
        self.buf_lock.lock();
        defer self.buf_lock.unlock();
        const count = @min(out.len, self.free_buf_count);
        for (0..count) |i| {
            self.free_buf_count -= 1;
            out[i] = self.free_bufs[self.free_buf_count];
        }
        return count;
    }

    /// Allocate a batch slot.
    pub fn allocBatch(self: *DataPlanePool) ?u16 {
        self.batch_lock.lock();
        defer self.batch_lock.unlock();
        if (self.free_batch_count == 0) return null;
        self.free_batch_count -= 1;
        const idx = self.free_batches[self.free_batch_count];
        self.batches[idx] = .{};
        return idx;
    }

    /// Return a batch to the pool.
    pub fn freeBatch(self: *DataPlanePool, idx: u16) void {
        self.batch_lock.lock();
        defer self.batch_lock.unlock();
        self.free_batches[self.free_batch_count] = idx;
        self.free_batch_count += 1;
    }
};

/// Bounded MPMC queue for dispatching batches to crypto workers.
/// Lock-free using atomic head/tail with futex for blocking pop.
pub const CryptoQueue = struct {
    slots: [CRYPTO_QUEUE_SIZE]std.atomic.Value(u32) = init_slots(),
    head: std.atomic.Value(u64) align(CACHE_LINE) = std.atomic.Value(u64).init(0),
    tail: std.atomic.Value(u64) align(CACHE_LINE) = std.atomic.Value(u64).init(0),
    closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // Condition variable for blocking pop (simpler than futex for correctness)
    mutex: std.Thread.Mutex = .{},
    not_empty: std.Thread.Condition = .{},

    const EMPTY_SLOT: u32 = 0xFFFF;

    fn init_slots() [CRYPTO_QUEUE_SIZE]std.atomic.Value(u32) {
        @setEvalBranchQuota(CRYPTO_QUEUE_SIZE * 4);
        var s: [CRYPTO_QUEUE_SIZE]std.atomic.Value(u32) = undefined;
        for (&s) |*slot| {
            slot.* = std.atomic.Value(u32).init(EMPTY_SLOT);
        }
        return s;
    }

    /// Try to push a batch index. Returns false if queue is full.
    pub fn tryPush(self: *CryptoQueue, batch_idx: u16) bool {
        const tail = self.tail.load(.monotonic);
        const head = self.head.load(.acquire);

        if (tail -% head >= CRYPTO_QUEUE_SIZE) return false;

        const slot_idx = tail % CRYPTO_QUEUE_SIZE;
        // Only succeed if the slot is empty
        const prev = self.slots[slot_idx].cmpxchgStrong(
            EMPTY_SLOT,
            @as(u32, batch_idx),
            .release,
            .monotonic,
        );
        if (prev != null) return false;

        _ = self.tail.fetchAdd(1, .release);

        // Signal any waiting consumer
        self.mutex.lock();
        self.not_empty.signal();
        self.mutex.unlock();
        return true;
    }

    /// Push a batch index, blocking if full.
    pub fn push(self: *CryptoQueue, batch_idx: u16) void {
        while (!self.tryPush(batch_idx)) {
            if (self.closed.load(.acquire)) return;
            // Brief spin before yield
            std.atomic.spinLoopHint();
        }
    }

    /// Try to pop a batch index without blocking. Returns null if empty.
    pub fn tryPop(self: *CryptoQueue) ?u16 {
        const head = self.head.load(.monotonic);
        const tail = self.tail.load(.acquire);

        if (head >= tail) return null;

        const slot_idx = head % CRYPTO_QUEUE_SIZE;
        const val = self.slots[slot_idx].swap(EMPTY_SLOT, .acquire);
        if (val == EMPTY_SLOT) return null;

        _ = self.head.fetchAdd(1, .release);
        return @intCast(val);
    }

    /// Pop a batch index, blocking if empty. Returns null if closed.
    pub fn pop(self: *CryptoQueue) ?u16 {
        while (true) {
            if (self.tryPop()) |idx| return idx;
            if (self.closed.load(.acquire)) return null;

            self.mutex.lock();
            // Re-check after acquiring lock
            if (self.tryPop()) |idx| {
                self.mutex.unlock();
                return idx;
            }
            if (self.closed.load(.acquire)) {
                self.mutex.unlock();
                return null;
            }
            self.not_empty.wait(&self.mutex);
            self.mutex.unlock();
        }
    }

    /// Close the queue, waking all blocked consumers.
    pub fn close(self: *CryptoQueue) void {
        self.closed.store(true, .release);
        self.mutex.lock();
        self.not_empty.broadcast();
        self.mutex.unlock();
    }
};

/// Per-peer Tx ring buffer for maintaining strict send ordering.
/// TUN reader pushes batch indices in nonce-sequential order.
/// Crypto workers pop and send only when batches are Ready, in order.
pub const PeerTxRing = struct {
    pub const RING_SIZE: usize = 256; // must be power of 2

    ring: [RING_SIZE]u16 align(CACHE_LINE) = undefined,
    head: usize align(CACHE_LINE) = 0, // read by opportunistic sender
    tail: usize align(CACHE_LINE) = 0, // written by TUN reader

    push_lock: std.Thread.Mutex align(CACHE_LINE) = .{}, // TUN reader holds briefly
    send_lock: std.Thread.Mutex align(CACHE_LINE) = .{}, // crypto worker tryLock for Tx

    pub fn push(self: *PeerTxRing, batch_idx: u16) void {
        // push_lock must be held by caller
        self.ring[self.tail % RING_SIZE] = batch_idx;
        self.tail +%= 1;
    }

    pub fn isEmpty(self: *const PeerTxRing) bool {
        return self.head == self.tail;
    }

    pub fn peekHead(self: *const PeerTxRing) u16 {
        return self.ring[self.head % RING_SIZE];
    }

    pub fn advanceHead(self: *PeerTxRing) void {
        self.head +%= 1;
    }
};
