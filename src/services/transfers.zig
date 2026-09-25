//! Reliable, verified application transfers over authenticated 0x50 datagrams.
//!
//! The sender stages bytes locally (XFEROFFER/XFERPUT/XFERSTART), then streams
//! DATA frames under a congestion window with selective acknowledgements and
//! retransmission. The receiver only accepts offers for channels a local
//! application registered with XFERLISTEN, within byte and slot budgets. It
//! verifies the SHA-256 before reporting DONE; the local application then reads
//! the bytes (XFERRECV/XFERGET) and releases them (XFERDONE).
//!
//! State is in memory and bounded. A daemon restart forgets transfers; the
//! sender detects an unknown transfer and re-offers it, and applications that
//! need durability keep their own record of what they have stored.
//!
//! All public methods lock `lock`, so the Windows control thread and the event
//! loop can call in concurrently.

const std = @import("std");
const wire = @import("../protocol/transfer.zig");
const app_channel = @import("../protocol/app_channel.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const ms = std.time.ns_per_ms;

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub const Limits = struct {
    max_transfer_bytes: u64 = 32 * 1024 * 1024,
    max_incoming_bytes: u64 = 96 * 1024 * 1024,
    max_outgoing_bytes: u64 = 96 * 1024 * 1024,
    /// Idle time before an unanswered or stalled transfer fails.
    idle_timeout_ns: i128 = 60 * std.time.ns_per_s,
    /// How long finished transfers stay readable or queryable before being freed.
    retention_ns: i128 = 15 * 60 * std.time.ns_per_s,
    /// Offers created further in the past are refused, bounding replay of old captures.
    max_offer_age_secs: i64 = 60 * 60,
};

pub const MAX_OUTGOING: usize = 8;
pub const MAX_INCOMING: usize = 8;
pub const MAX_LISTENERS: usize = 8;
const FINISHED_MEMORY: usize = 512;
const MAX_BURST_PER_TICK: u32 = 64;
const MIN_CWND: u32 = 4;
const INITIAL_CWND: u32 = 16;
const MAX_CWND: u32 = wire.ACK_WINDOW;
const INITIAL_RTO_NS: i128 = 1000 * ms;
const MIN_RTO_NS: i128 = 200 * ms;
const MAX_RTO_NS: i128 = 4000 * ms;
const OFFER_RETRY_NS: i128 = 500 * ms;
const DONE_PROBE_NS: i128 = 1000 * ms;
const ACK_DELAY_NS: i128 = 10 * ms;
const ACK_EVERY: u32 = 16;
const MAX_RESTARTS: u8 = 3;

pub const SendFn = *const fn (ctx: *anyopaque, peer: [32]u8, plaintext: []const u8) bool;

pub const OutState = enum { staging, sending, delivered, failed };
pub const InState = enum { receiving, complete };

pub const Error = error{
    OutOfMemory,
    InvalidChannel,
    TooLarge,
    Busy,
    UnknownTransfer,
    InvalidState,
    InvalidOffset,
    Incomplete,
    HashMismatch,
};

pub const OutgoingStatus = struct {
    state: OutState,
    size: u64,
    staged: u64,
    acked_chunks: u32,
    chunks: u32,
    retransmits: u64,
    failure: ?[]const u8,
};

pub const IncomingInfo = struct {
    id: [16]u8,
    sender: [32]u8,
    size: u64,
    sha256: [32]u8,
    channel: [app_channel.MAX_CHANNEL_LEN]u8,
    channel_len: usize,
    meta: [wire.MAX_META]u8,
    meta_len: usize,
};

const Outgoing = struct {
    id: [16]u8,
    peer: [32]u8,
    channel: [app_channel.MAX_CHANNEL_LEN]u8,
    channel_len: usize,
    meta: [wire.MAX_META]u8,
    meta_len: usize,
    sha256: [32]u8,
    created_unix: i64,
    data: []u8,
    staged: u64 = 0,
    state: OutState = .staging,
    failure: ?[]const u8 = null,
    chunks: u32,
    acked: std.DynamicBitSetUnmanaged,
    /// Send time of each chunk's latest transmission; 0 = not in flight.
    sent_at: []i128,
    retransmitted: std.DynamicBitSetUnmanaged,
    acked_count: u32 = 0,
    cumulative: u32 = 0,
    next_new: u32 = 0,
    accepted: bool = false,
    cwnd: u32 = INITIAL_CWND,
    cwnd_fraction: u32 = 0,
    ssthresh: u32 = MAX_CWND,
    srtt: i128 = 0,
    rttvar: i128 = 0,
    rto: i128 = INITIAL_RTO_NS,
    last_loss: i128 = 0,
    last_offer: i128 = 0,
    last_progress: i128 = 0,
    finished_at: i128 = 0,
    restarts: u8 = 0,
    retransmits: u64 = 0,

    fn channelSlice(self: *const Outgoing) []const u8 {
        return self.channel[0..self.channel_len];
    }
};

const Incoming = struct {
    id: [16]u8,
    sender: [32]u8,
    channel: [app_channel.MAX_CHANNEL_LEN]u8,
    channel_len: usize,
    meta: [wire.MAX_META]u8,
    meta_len: usize,
    sha256: [32]u8,
    size: u64,
    chunk_size: u16,
    chunks: u32,
    data: []u8,
    received: std.DynamicBitSetUnmanaged,
    received_count: u32 = 0,
    cumulative: u32 = 0,
    state: InState = .receiving,
    last_activity: i128,
    completed_at: i128 = 0,
    unacked: u32 = 0,
    ack_due: i128 = 0,

    fn channelSlice(self: *const Incoming) []const u8 {
        return self.channel[0..self.channel_len];
    }
};

const Listener = struct {
    channel: [app_channel.MAX_CHANNEL_LEN]u8 = undefined,
    channel_len: usize = 0,
    max_bytes: u64 = 0,
    in_use: bool = false,
};

pub const TransferManager = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    send_ctx: ?*anyopaque = null,
    send_fn: ?SendFn = null,
    lock: std.Io.Mutex = .init,
    outgoing: [MAX_OUTGOING]?*Outgoing = @splat(null),
    incoming: [MAX_INCOMING]?*Incoming = @splat(null),
    listeners: [MAX_LISTENERS]Listener = @splat(.{}),
    /// (sender, id) of recently finished incoming transfers: a replayed or
    /// re-sent offer for one of these is answered with DONE, never re-delivered.
    finished: [FINISHED_MEMORY][48]u8 = undefined,
    finished_head: usize = 0,
    finished_count: usize = 0,
    /// Scratch space for one outbound frame; only used while `lock` is held.
    frame_storage: [wire.MAX_FRAME]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) TransferManager {
        return .{ .allocator = allocator, .limits = limits };
    }

    pub fn deinit(self: *TransferManager) void {
        for (&self.outgoing) |*slot| if (slot.*) |out| self.freeOutgoing(slot, out);
        for (&self.incoming) |*slot| if (slot.*) |in| self.freeIncoming(slot, in);
    }

    pub fn setSender(self: *TransferManager, ctx: *anyopaque, send_fn: SendFn) void {
        self.send_ctx = ctx;
        self.send_fn = send_fn;
    }

    // ─── Local application commands ───

    /// Accept incoming offers on `channel` up to `max_bytes` each.
    pub fn listen(self: *TransferManager, channel: []const u8, max_bytes: u64) Error!void {
        if (!app_channel.isValidChannel(channel)) return error.InvalidChannel;
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        const limit = @min(max_bytes, self.limits.max_transfer_bytes);
        var free: ?*Listener = null;
        for (&self.listeners) |*l| {
            if (l.in_use and std.mem.eql(u8, l.channel[0..l.channel_len], channel)) {
                l.max_bytes = limit;
                return;
            }
            if (!l.in_use and free == null) free = l;
        }
        const l = free orelse return error.Busy;
        @memcpy(l.channel[0..channel.len], channel);
        l.* = .{ .channel = l.channel, .channel_len = channel.len, .max_bytes = limit, .in_use = true };
    }

    pub fn offer(self: *TransferManager, peer: [32]u8, channel: []const u8, size: u64, sha256: [32]u8, meta: []const u8, now_unix: i64) Error![16]u8 {
        if (!app_channel.isValidChannel(channel)) return error.InvalidChannel;
        if (size == 0 or size > self.limits.max_transfer_bytes or meta.len > wire.MAX_META) return error.TooLarge;
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        var held: u64 = 0;
        var free: ?*?*Outgoing = null;
        for (&self.outgoing) |*slot| {
            if (slot.*) |out| held += out.data.len else if (free == null) free = slot;
        }
        const slot = free orelse return error.Busy;
        if (held + size > self.limits.max_outgoing_bytes) return error.Busy;

        const chunks = wire.chunkCount(size, wire.CHUNK_SIZE);
        const out = try self.allocator.create(Outgoing);
        errdefer self.allocator.destroy(out);
        const data = try self.allocator.alloc(u8, @intCast(size));
        errdefer self.allocator.free(data);
        const sent_at = try self.allocator.alloc(i128, chunks);
        errdefer self.allocator.free(sent_at);
        @memset(sent_at, 0);
        var acked = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, chunks);
        errdefer acked.deinit(self.allocator);
        const retransmitted = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, chunks);

        var id: [16]u8 = undefined;
        zio().random(&id);
        out.* = .{ .id = id, .peer = peer, .channel = undefined, .channel_len = channel.len, .meta = undefined, .meta_len = meta.len,
            .sha256 = sha256, .created_unix = now_unix, .data = data, .chunks = chunks, .acked = acked, .sent_at = sent_at, .retransmitted = retransmitted };
        @memcpy(out.channel[0..channel.len], channel);
        @memcpy(out.meta[0..meta.len], meta);
        slot.* = out;
        return id;
    }

    /// Append staged bytes. Offsets must be contiguous so retries are detectable.
    pub fn put(self: *TransferManager, id: [16]u8, offset: u64, bytes: []const u8) Error!u64 {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        const out = self.findOutgoing(id) orelse return error.UnknownTransfer;
        if (out.state != .staging) return error.InvalidState;
        // A retried chunk that was already applied is accepted if identical.
        if (offset + bytes.len <= out.staged) {
            if (!std.mem.eql(u8, out.data[@intCast(offset)..][0..bytes.len], bytes)) return error.InvalidOffset;
            return out.staged;
        }
        if (offset != out.staged or offset + bytes.len > out.data.len) return error.InvalidOffset;
        @memcpy(out.data[@intCast(offset)..][0..bytes.len], bytes);
        out.staged += bytes.len;
        return out.staged;
    }

    pub fn start(self: *TransferManager, id: [16]u8, now_ns: i128) Error!void {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        const out = self.findOutgoing(id) orelse return error.UnknownTransfer;
        if (out.state == .sending or out.state == .delivered) return;
        if (out.state != .staging) return error.InvalidState;
        if (out.staged != out.data.len) return error.Incomplete;
        var digest: [32]u8 = undefined;
        Sha256.hash(out.data, &digest, .{});
        if (!std.mem.eql(u8, &digest, &out.sha256)) return error.HashMismatch;
        out.state = .sending;
        out.last_progress = now_ns;
        self.sendOffer(out, now_ns);
    }

    pub fn status(self: *TransferManager, id: [16]u8) ?OutgoingStatus {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        const out = self.findOutgoing(id) orelse return null;
        return .{ .state = out.state, .size = out.data.len, .staged = out.staged, .acked_chunks = out.acked_count,
            .chunks = out.chunks, .retransmits = out.retransmits, .failure = out.failure };
    }

    /// The oldest verified incoming transfer on `channel` that the application has not released.
    pub fn nextComplete(self: *TransferManager, channel: []const u8) ?IncomingInfo {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        var best: ?*Incoming = null;
        for (self.incoming) |slot| if (slot) |in| {
            if (in.state == .complete and std.mem.eql(u8, in.channelSlice(), channel) and (best == null or in.completed_at < best.?.completed_at)) best = in;
        };
        const in = best orelse return null;
        return .{ .id = in.id, .sender = in.sender, .size = in.size, .sha256 = in.sha256, .channel = in.channel,
            .channel_len = in.channel_len, .meta = in.meta, .meta_len = in.meta_len };
    }

    pub fn read(self: *TransferManager, id: [16]u8, offset: u64, out_buf: []u8) Error!usize {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        const in = self.findIncoming(id) orelse return error.UnknownTransfer;
        if (in.state != .complete) return error.Incomplete;
        if (offset > in.data.len) return error.InvalidOffset;
        const n = @min(out_buf.len, in.data.len - @as(usize, @intCast(offset)));
        @memcpy(out_buf[0..n], in.data[@intCast(offset)..][0..n]);
        return n;
    }

    /// Free a verified incoming transfer after the application stored it, or
    /// forget a finished outgoing one. Returns false when the id is unknown.
    pub fn release(self: *TransferManager, id: [16]u8) bool {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        for (&self.incoming) |*slot| if (slot.*) |in| if (std.mem.eql(u8, &in.id, &id) and in.state == .complete) {
            self.freeIncoming(slot, in);
            return true;
        };
        for (&self.outgoing) |*slot| if (slot.*) |out| if (std.mem.eql(u8, &out.id, &id) and out.state != .sending) {
            self.freeOutgoing(slot, out);
            return true;
        };
        return false;
    }

    pub fn cancel(self: *TransferManager, id: [16]u8) bool {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        for (&self.outgoing) |*slot| if (slot.*) |out| if (std.mem.eql(u8, &out.id, &id)) {
            if (out.state == .sending) self.sendFrame(out.peer, wire.encodeCancel(self.frameBuf(), out.id, .cancelled) catch return false);
            self.freeOutgoing(slot, out);
            return true;
        };
        for (&self.incoming) |*slot| if (slot.*) |in| if (std.mem.eql(u8, &in.id, &id)) {
            self.sendFrame(in.sender, wire.encodeCancel(self.frameBuf(), in.id, .cancelled) catch return false);
            self.remember(in.sender, in.id);
            self.freeIncoming(slot, in);
            return true;
        };
        return false;
    }

    // ─── Network ───

    /// Handle one authenticated MGXF1 plaintext from `sender`.
    pub fn handleFrame(self: *TransferManager, sender: [32]u8, data: []const u8, now_ns: i128, now_unix: i64) void {
        const frame = wire.parse(data) catch return;
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        switch (frame.body) {
            .offer => |o| self.onOffer(sender, frame.id, o, now_ns, now_unix),
            .data => |d| self.onData(sender, frame.id, d.index, d.bytes, now_ns),
            .ack => |a| self.onAck(sender, frame.id, a, now_ns),
            .done => |s| self.onDone(sender, frame.id, s, now_ns),
            .cancel => |r| self.onCancel(sender, frame.id, r, now_ns),
        }
    }

    /// Drive retransmission, pacing, acknowledgements, and expiry.
    pub fn tick(self: *TransferManager, now_ns: i128) void {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        for (&self.outgoing) |*slot| if (slot.*) |out| {
            if (out.state == .sending) self.driveOutgoing(out, now_ns);
            if (out.state != .sending and out.state != .staging and now_ns - out.finished_at > self.limits.retention_ns) self.freeOutgoing(slot, out);
            if (out.state == .staging) {
                // Staging has no clock of its own; start one at the first tick and drop abandoned uploads.
                if (out.last_progress == 0) out.last_progress = now_ns else if (now_ns - out.last_progress > self.limits.retention_ns) self.freeOutgoing(slot, out);
            }
        };
        for (&self.incoming) |*slot| if (slot.*) |in| {
            if (in.state == .receiving) {
                if (now_ns - in.last_activity > self.limits.idle_timeout_ns) {
                    self.freeIncoming(slot, in);
                    continue;
                }
                if (in.unacked > 0 and now_ns >= in.ack_due) self.sendAck(in);
            } else if (now_ns - in.completed_at > self.limits.retention_ns) {
                self.freeIncoming(slot, in);
            }
        };
    }

    /// True while any transfer needs periodic ticks (lets idle loops stay idle).
    pub fn active(self: *TransferManager) bool {
        self.lock.lockUncancelable(zio());
        defer self.lock.unlock(zio());
        for (self.outgoing) |slot| if (slot) |out| if (out.state == .sending) return true;
        for (self.incoming) |slot| if (slot) |in| if (in.state == .receiving) return true;
        return false;
    }

    // ─── Receiver ───

    fn onOffer(self: *TransferManager, sender: [32]u8, id: [16]u8, o: wire.Offer, now_ns: i128, now_unix: i64) void {
        if (self.findIncoming(id)) |in| {
            if (!std.mem.eql(u8, &in.sender, &sender)) return;
            if (in.state == .complete) self.sendFrame(sender, wire.encodeDone(self.frameBuf(), id, .verified) catch return) else self.sendAck(in);
            return;
        }
        if (self.wasFinished(sender, id)) {
            self.sendFrame(sender, wire.encodeDone(self.frameBuf(), id, .verified) catch return);
            return;
        }
        const reason: ?wire.Reason = blk: {
            if (now_unix - o.created_unix > self.limits.max_offer_age_secs) break :blk .expired;
            const listener = self.findListener(o.channel) orelse break :blk .no_listener;
            if (o.size > listener.max_bytes) break :blk .too_large;
            if (o.chunk_size != wire.CHUNK_SIZE) break :blk .invalid;
            var held: u64 = 0;
            var free = false;
            for (self.incoming) |slot| {
                if (slot) |in| held += in.data.len else free = true;
            }
            if (!free or held + o.size > self.limits.max_incoming_bytes) break :blk .busy;
            break :blk null;
        };
        if (reason) |r| {
            self.sendFrame(sender, wire.encodeCancel(self.frameBuf(), id, r) catch return);
            return;
        }
        const in = self.createIncoming(sender, id, o, now_ns) catch {
            self.sendFrame(sender, wire.encodeCancel(self.frameBuf(), id, .busy) catch return);
            return;
        };
        self.sendAck(in);
    }

    fn createIncoming(self: *TransferManager, sender: [32]u8, id: [16]u8, o: wire.Offer, now_ns: i128) !*Incoming {
        const slot = for (&self.incoming) |*candidate| {
            if (candidate.* == null) break candidate;
        } else return error.Busy;
        const chunks = wire.chunkCount(o.size, o.chunk_size);
        const in = try self.allocator.create(Incoming);
        errdefer self.allocator.destroy(in);
        const data = try self.allocator.alloc(u8, @intCast(o.size));
        errdefer self.allocator.free(data);
        const received = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, chunks);
        in.* = .{ .id = id, .sender = sender, .channel = undefined, .channel_len = o.channel.len, .meta = undefined, .meta_len = o.meta.len,
            .sha256 = o.sha256, .size = o.size, .chunk_size = o.chunk_size, .chunks = chunks, .data = data, .received = received, .last_activity = now_ns };
        @memcpy(in.channel[0..o.channel.len], o.channel);
        @memcpy(in.meta[0..o.meta.len], o.meta);
        slot.* = in;
        return in;
    }

    fn onData(self: *TransferManager, sender: [32]u8, id: [16]u8, index: u32, bytes: []const u8, now_ns: i128) void {
        const in = self.findIncoming(id) orelse {
            if (self.wasFinished(sender, id)) {
                self.sendFrame(sender, wire.encodeDone(self.frameBuf(), id, .verified) catch return);
            } else {
                // Lost after a restart or expiry: ask the sender to offer again.
                self.sendFrame(sender, wire.encodeCancel(self.frameBuf(), id, .unknown_transfer) catch return);
            }
            return;
        };
        if (!std.mem.eql(u8, &in.sender, &sender)) return;
        if (in.state == .complete) {
            self.sendFrame(sender, wire.encodeDone(self.frameBuf(), id, .verified) catch return);
            return;
        }
        if (index >= in.chunks) return;
        const offset = @as(u64, index) * in.chunk_size;
        const expected: usize = @intCast(@min(@as(u64, in.chunk_size), in.size - offset));
        if (bytes.len != expected) return;
        in.last_activity = now_ns;
        if (!in.received.isSet(index)) {
            @memcpy(in.data[@intCast(offset)..][0..bytes.len], bytes);
            in.received.set(index);
            in.received_count += 1;
            while (in.cumulative < in.chunks and in.received.isSet(in.cumulative)) in.cumulative += 1;
        }
        in.unacked += 1;
        if (in.received_count == in.chunks) {
            var digest: [32]u8 = undefined;
            Sha256.hash(in.data, &digest, .{});
            if (std.mem.eql(u8, &digest, &in.sha256)) {
                in.state = .complete;
                in.completed_at = now_ns;
                self.remember(sender, id);
                self.sendFrame(sender, wire.encodeDone(self.frameBuf(), id, .verified) catch return);
            } else {
                self.sendFrame(sender, wire.encodeDone(self.frameBuf(), id, .hash_mismatch) catch return);
                for (&self.incoming) |*slot| if (slot.* == in) self.freeIncoming(slot, in);
            }
            return;
        }
        // Acknowledge promptly on gaps and periodically otherwise.
        if (index != in.cumulative - 1 or in.unacked >= ACK_EVERY) {
            self.sendAck(in);
        } else if (in.unacked == 1) {
            in.ack_due = now_ns + ACK_DELAY_NS;
        }
    }

    fn sendAck(self: *TransferManager, in: *Incoming) void {
        var bitmap: [wire.ACK_BITMAP_BYTES]u8 = @splat(0);
        var used: usize = 0;
        var i: u32 = 0;
        while (i < wire.ACK_WINDOW and in.cumulative + i < in.chunks) : (i += 1) {
            if (in.received.isSet(in.cumulative + i)) {
                bitmap[i / 8] |= @as(u8, 1) << @intCast(i % 8);
                used = i / 8 + 1;
            }
        }
        in.unacked = 0;
        self.sendFrame(in.sender, wire.encodeAck(self.frameBuf(), in.id, in.cumulative, bitmap[0..used]) catch return);
    }

    // ─── Sender ───

    fn sendOffer(self: *TransferManager, out: *Outgoing, now_ns: i128) void {
        out.last_offer = now_ns;
        self.sendFrame(out.peer, wire.encodeOffer(self.frameBuf(), out.id, .{ .created_unix = out.created_unix, .size = out.data.len,
            .chunk_size = wire.CHUNK_SIZE, .sha256 = out.sha256, .channel = out.channelSlice(), .meta = out.meta[0..out.meta_len] }) catch return);
    }

    fn sendChunk(self: *TransferManager, out: *Outgoing, index: u32, now_ns: i128) void {
        const offset: usize = @as(usize, index) * wire.CHUNK_SIZE;
        const end = @min(offset + wire.CHUNK_SIZE, out.data.len);
        out.sent_at[index] = now_ns;
        self.sendFrame(out.peer, wire.encodeData(self.frameBuf(), out.id, index, out.data[offset..end]) catch return);
    }

    fn driveOutgoing(self: *TransferManager, out: *Outgoing, now_ns: i128) void {
        if (now_ns - out.last_progress > self.limits.idle_timeout_ns) {
            self.fail(out, "receiver did not respond", now_ns);
            return;
        }
        if (!out.accepted) {
            if (now_ns - out.last_offer >= OFFER_RETRY_NS) self.sendOffer(out, now_ns);
            return;
        }
        if (out.acked_count == out.chunks) {
            // Everything is held remotely; wait for the verified DONE and probe if it was lost.
            if (now_ns - out.last_offer >= DONE_PROBE_NS) self.sendOffer(out, now_ns);
            return;
        }
        var budget: u32 = MAX_BURST_PER_TICK;
        var inflight: u32 = 0;
        const window_end = @min(out.next_new, out.cumulative +| wire.ACK_WINDOW);
        var lost = false;
        var i = out.cumulative;
        // Count what is still in flight and retransmit what timed out.
        while (i < window_end) : (i += 1) {
            if (out.acked.isSet(i) or out.sent_at[i] == 0) continue;
            if (now_ns - out.sent_at[i] < out.rto) {
                inflight += 1;
            } else {
                lost = true;
                out.sent_at[i] = 0;
            }
        }
        if (lost and now_ns - out.last_loss > out.rto) {
            out.last_loss = now_ns;
            out.ssthresh = @max(out.cwnd / 2, MIN_CWND);
            out.cwnd = out.ssthresh;
            out.cwnd_fraction = 0;
        }
        // Retransmissions first, oldest first, within the window.
        i = out.cumulative;
        while (i < window_end and inflight < out.cwnd and budget > 0) : (i += 1) {
            if (out.acked.isSet(i) or out.sent_at[i] != 0) continue;
            out.retransmitted.set(i);
            out.retransmits += 1;
            self.sendChunk(out, i, now_ns);
            inflight += 1;
            budget -= 1;
        }
        while (out.next_new < out.chunks and out.next_new < out.cumulative +| wire.ACK_WINDOW and inflight < out.cwnd and budget > 0) {
            self.sendChunk(out, out.next_new, now_ns);
            out.next_new += 1;
            inflight += 1;
            budget -= 1;
        }
    }

    fn onAck(self: *TransferManager, sender: [32]u8, id: [16]u8, ack: wire.Ack, now_ns: i128) void {
        const out = self.findOutgoing(id) orelse return;
        if (!std.mem.eql(u8, &out.peer, &sender) or out.state != .sending) return;
        if (ack.cumulative > out.chunks) return;
        out.accepted = true;
        out.last_progress = now_ns;
        const end = @min(out.chunks, ack.cumulative +| @as(u32, @intCast(ack.bitmap.len * 8)));
        var i = out.cumulative;
        var newly: u32 = 0;
        var highest: u32 = 0;
        while (i < end) : (i += 1) {
            if (ack.has(i)) highest = i;
            if (out.acked.isSet(i) or !ack.has(i)) continue;
            out.acked.set(i);
            out.acked_count += 1;
            newly += 1;
            // Karn: only unambiguous samples update the round-trip estimate.
            if (out.sent_at[i] != 0 and !out.retransmitted.isSet(i)) self.sample(out, now_ns - out.sent_at[i]);
            out.sent_at[i] = 0;
        }
        while (out.cumulative < out.chunks and out.acked.isSet(out.cumulative)) out.cumulative += 1;
        // Fast retransmit: a chunk that three later chunks overtook, sent at least one
        // smoothed round trip ago, is treated as lost without waiting for the timeout.
        const reorder_grace = if (out.srtt > 0) out.srtt else out.rto;
        i = out.cumulative;
        var fast_loss = false;
        while (i + 3 <= highest) : (i += 1) {
            if (out.acked.isSet(i) or out.sent_at[i] == 0 or now_ns - out.sent_at[i] < reorder_grace) continue;
            out.sent_at[i] = 0;
            fast_loss = true;
        }
        if (fast_loss and now_ns - out.last_loss > out.rto) {
            out.last_loss = now_ns;
            out.ssthresh = @max(out.cwnd / 2, MIN_CWND);
            out.cwnd = out.ssthresh;
            out.cwnd_fraction = 0;
        }
        // Slow start below ssthresh, additive increase above it.
        var n = newly;
        while (n > 0) : (n -= 1) {
            if (out.cwnd < out.ssthresh) {
                out.cwnd = @min(out.cwnd + 1, MAX_CWND);
            } else {
                out.cwnd_fraction += 1;
                if (out.cwnd_fraction >= out.cwnd) {
                    out.cwnd_fraction = 0;
                    out.cwnd = @min(out.cwnd + 1, MAX_CWND);
                }
            }
        }
        self.driveOutgoing(out, now_ns);
    }

    fn sample(self: *TransferManager, out: *Outgoing, rtt: i128) void {
        _ = self;
        if (rtt <= 0) return;
        if (out.srtt == 0) {
            out.srtt = rtt;
            out.rttvar = @divTrunc(rtt, 2);
        } else {
            const delta = if (out.srtt > rtt) out.srtt - rtt else rtt - out.srtt;
            out.rttvar = @divTrunc(3 * out.rttvar + delta, 4);
            out.srtt = @divTrunc(7 * out.srtt + rtt, 8);
        }
        out.rto = std.math.clamp(out.srtt + 4 * out.rttvar, MIN_RTO_NS, MAX_RTO_NS);
    }

    fn onDone(self: *TransferManager, sender: [32]u8, id: [16]u8, s: wire.DoneStatus, now_ns: i128) void {
        const out = self.findOutgoing(id) orelse return;
        if (!std.mem.eql(u8, &out.peer, &sender) or out.state != .sending) return;
        switch (s) {
            .verified => {
                out.state = .delivered;
                out.finished_at = now_ns;
            },
            .hash_mismatch => self.fail(out, "receiver hash verification failed", now_ns),
            .rejected => self.fail(out, "receiver rejected the transfer", now_ns),
        }
    }

    fn onCancel(self: *TransferManager, sender: [32]u8, id: [16]u8, reason: wire.Reason, now_ns: i128) void {
        if (self.findOutgoing(id)) |out| {
            if (!std.mem.eql(u8, &out.peer, &sender) or out.state != .sending) return;
            // Every in-flight chunk can draw its own "unknown" reply; one restart covers them all.
            if (reason == .unknown_transfer and !out.accepted) return;
            if (reason == .unknown_transfer and out.restarts < MAX_RESTARTS) {
                // The receiver lost its state (restart or expiry): start over.
                out.restarts += 1;
                out.accepted = false;
                out.acked.unsetAll();
                out.retransmitted.unsetAll();
                @memset(out.sent_at, 0);
                out.acked_count = 0;
                out.cumulative = 0;
                out.next_new = 0;
                out.cwnd = INITIAL_CWND;
                out.last_progress = now_ns;
                self.sendOffer(out, now_ns);
                return;
            }
            self.fail(out, reason.text(), now_ns);
            return;
        }
        for (&self.incoming) |*slot| if (slot.*) |in| {
            if (std.mem.eql(u8, &in.id, &id) and std.mem.eql(u8, &in.sender, &sender) and in.state == .receiving) {
                self.freeIncoming(slot, in);
                return;
            }
        };
    }

    fn fail(self: *TransferManager, out: *Outgoing, reason: []const u8, now_ns: i128) void {
        _ = self;
        out.state = .failed;
        out.failure = reason;
        out.finished_at = now_ns;
    }

    // ─── Helpers ───

    fn frameBuf(self: *TransferManager) []u8 {
        return &self.frame_storage;
    }

    fn sendFrame(self: *TransferManager, peer: [32]u8, frame: []const u8) void {
        const send = self.send_fn orelse return;
        _ = send(self.send_ctx.?, peer, frame);
    }

    fn findOutgoing(self: *TransferManager, id: [16]u8) ?*Outgoing {
        for (self.outgoing) |slot| if (slot) |out| if (std.mem.eql(u8, &out.id, &id)) return out;
        return null;
    }

    fn findIncoming(self: *TransferManager, id: [16]u8) ?*Incoming {
        for (self.incoming) |slot| if (slot) |in| if (std.mem.eql(u8, &in.id, &id)) return in;
        return null;
    }

    fn findListener(self: *TransferManager, channel: []const u8) ?*Listener {
        for (&self.listeners) |*l| if (l.in_use and std.mem.eql(u8, l.channel[0..l.channel_len], channel)) return l;
        return null;
    }

    fn remember(self: *TransferManager, sender: [32]u8, id: [16]u8) void {
        var key: [48]u8 = undefined;
        @memcpy(key[0..32], &sender);
        @memcpy(key[32..48], &id);
        self.finished[self.finished_head] = key;
        self.finished_head = (self.finished_head + 1) % FINISHED_MEMORY;
        if (self.finished_count < FINISHED_MEMORY) self.finished_count += 1;
    }

    fn wasFinished(self: *TransferManager, sender: [32]u8, id: [16]u8) bool {
        for (self.finished[0..self.finished_count]) |key| {
            if (std.mem.eql(u8, key[0..32], &sender) and std.mem.eql(u8, key[32..48], &id)) return true;
        }
        return false;
    }

    fn freeOutgoing(self: *TransferManager, slot: *?*Outgoing, out: *Outgoing) void {
        self.allocator.free(out.data);
        self.allocator.free(out.sent_at);
        out.acked.deinit(self.allocator);
        out.retransmitted.deinit(self.allocator);
        self.allocator.destroy(out);
        slot.* = null;
    }

    fn freeIncoming(self: *TransferManager, slot: *?*Incoming, in: *Incoming) void {
        self.allocator.free(in.data);
        in.received.deinit(self.allocator);
        self.allocator.destroy(in);
        slot.* = null;
    }
};

// ─── Tests: two managers over a simulated lossy network ───

const Net = struct {
    const Packet = struct { to: u8, from: [32]u8, data: [wire.MAX_FRAME]u8, len: usize, deliver_at: i128 };
    packets: std.ArrayList(Packet) = .empty,
    allocator: std.mem.Allocator,
    prng: std.Random.DefaultPrng,
    loss_percent: u8 = 0,
    duplicate_percent: u8 = 0,
    latency_ns: i128 = 20 * ms,
    jitter_ns: i128 = 0,
    now: i128 = 1,
    sent: u64 = 0,
    blackhole: bool = false,

    const Endpoint = struct { net: *Net, index: u8, key: [32]u8 };

    fn send(ctx: *anyopaque, peer: [32]u8, plaintext: []const u8) bool {
        const ep: *Endpoint = @ptrCast(@alignCast(ctx));
        const net = ep.net;
        net.sent += 1;
        if (net.blackhole) return true;
        const random = net.prng.random();
        if (random.uintLessThan(u8, 100) < net.loss_percent) return true;
        const copies: usize = if (random.uintLessThan(u8, 100) < net.duplicate_percent) 2 else 1;
        for (0..copies) |_| {
            var p: Packet = .{ .to = peer[0], .from = ep.key, .data = undefined, .len = plaintext.len, .deliver_at = net.now + net.latency_ns };
            if (net.jitter_ns > 0) p.deliver_at += random.intRangeLessThan(i128, 0, net.jitter_ns);
            @memcpy(p.data[0..plaintext.len], plaintext);
            net.packets.append(net.allocator, p) catch return false;
        }
        return true;
    }

    fn step(net: *Net, managers: []const *TransferManager, dt: i128) void {
        net.now += dt;
        var i: usize = 0;
        while (i < net.packets.items.len) {
            const p = net.packets.items[i];
            if (p.deliver_at <= net.now) {
                _ = net.packets.swapRemove(i);
                managers[p.to].handleFrame(p.from, p.data[0..p.len], net.now, 1_790_000_000);
            } else i += 1;
        }
        for (managers) |m| m.tick(net.now);
    }
};

fn testKey(index: u8) [32]u8 {
    var key: [32]u8 = @splat(0xaa);
    key[0] = index;
    return key;
}

const Pair = struct {
    net: Net,
    a: TransferManager,
    b: TransferManager,
    ea: Net.Endpoint = undefined,
    eb: Net.Endpoint = undefined,

    fn init(self: *Pair, allocator: std.mem.Allocator, limits: Limits) void {
        self.* = .{ .net = .{ .allocator = allocator, .prng = .init(7) }, .a = .init(allocator, limits), .b = .init(allocator, limits) };
        self.ea = .{ .net = &self.net, .index = 0, .key = testKey(0) };
        self.eb = .{ .net = &self.net, .index = 1, .key = testKey(1) };
        self.a.setSender(&self.ea, Net.send);
        self.b.setSender(&self.eb, Net.send);
    }

    fn deinit(self: *Pair) void {
        self.a.deinit();
        self.b.deinit();
        self.net.packets.deinit(self.net.allocator);
    }

    fn managers(self: *Pair) [2]*TransferManager {
        return .{ &self.a, &self.b };
    }

    fn run(self: *Pair, until_ns: i128) void {
        const ms_ = self.managers();
        while (self.net.now < until_ns) self.net.step(&ms_, 5 * ms);
    }

    fn send(self: *Pair, bytes: []const u8, channel: []const u8) ![16]u8 {
        var digest: [32]u8 = undefined;
        Sha256.hash(bytes, &digest, .{});
        const id = try self.a.offer(testKey(1), channel, bytes.len, digest, "{\"name\":\"shot.png\"}", 1_790_000_000);
        var offset: usize = 0;
        while (offset < bytes.len) {
            const n = @min(bytes.len - offset, 48 * 1024);
            _ = try self.a.put(id, offset, bytes[offset..][0..n]);
            offset += n;
        }
        try self.a.start(id, self.net.now);
        return id;
    }

    fn received(self: *Pair, allocator: std.mem.Allocator, channel: []const u8) !?[]u8 {
        const info = self.b.nextComplete(channel) orelse return null;
        const buf = try allocator.alloc(u8, @intCast(info.size));
        _ = try self.b.read(info.id, 0, buf);
        return buf;
    }
};

fn pattern(allocator: std.mem.Allocator, n: usize) ![]u8 {
    const bytes = try allocator.alloc(u8, n);
    var prng: std.Random.DefaultPrng = .init(n);
    prng.random().bytes(bytes);
    return bytes;
}

test "a multi-megabyte transfer arrives verified over a clean link" {
    const allocator = std.testing.allocator;
    var pair: Pair = undefined;
    pair.init(allocator, .{});
    defer pair.deinit();
    try pair.b.listen("meshrooms-files", 16 * 1024 * 1024);
    const bytes = try pattern(allocator, 3 * 1024 * 1024 + 17);
    defer allocator.free(bytes);
    const id = try pair.send(bytes, "meshrooms-files");
    pair.run(20 * std.time.ns_per_s);
    try std.testing.expectEqual(OutState.delivered, pair.a.status(id).?.state);
    const got = (try pair.received(allocator, "meshrooms-files")).?;
    defer allocator.free(got);
    try std.testing.expectEqualSlices(u8, bytes, got);
    const info = pair.b.nextComplete("meshrooms-files").?;
    try std.testing.expectEqualStrings("{\"name\":\"shot.png\"}", info.meta[0..info.meta_len]);
    try std.testing.expect(pair.b.release(info.id));
    try std.testing.expect(pair.b.nextComplete("meshrooms-files") == null);
}

test "loss, duplication, and reordering are repaired by selective retransmission" {
    const allocator = std.testing.allocator;
    var pair: Pair = undefined;
    pair.init(allocator, .{});
    defer pair.deinit();
    pair.net.loss_percent = 15;
    pair.net.duplicate_percent = 5;
    pair.net.jitter_ns = 40 * ms;
    try pair.b.listen("meshrooms-files", 16 * 1024 * 1024);
    const bytes = try pattern(allocator, 1024 * 1024);
    defer allocator.free(bytes);
    const id = try pair.send(bytes, "meshrooms-files");
    pair.run(60 * std.time.ns_per_s);
    const s = pair.a.status(id).?;
    try std.testing.expectEqual(OutState.delivered, s.state);
    try std.testing.expect(s.retransmits > 0);
    const got = (try pair.received(allocator, "meshrooms-files")).?;
    defer allocator.free(got);
    try std.testing.expectEqualSlices(u8, bytes, got);
}

test "receivers refuse channels nobody listens on and sizes over the listener limit" {
    const allocator = std.testing.allocator;
    var pair: Pair = undefined;
    pair.init(allocator, .{});
    defer pair.deinit();
    const bytes = try pattern(allocator, 5000);
    defer allocator.free(bytes);
    const unheard = try pair.send(bytes, "nobody-home");
    try pair.b.listen("small", 1000);
    const large = try pair.send(bytes, "small");
    pair.run(3 * std.time.ns_per_s);
    try std.testing.expectEqual(OutState.failed, pair.a.status(unheard).?.state);
    try std.testing.expectEqualStrings("no receiver is listening on this channel", pair.a.status(unheard).?.failure.?);
    try std.testing.expectEqualStrings("transfer exceeds the receiver limit", pair.a.status(large).?.failure.?);
    try std.testing.expect(pair.b.nextComplete("small") == null);
}

test "staged bytes must match the declared hash before sending" {
    const allocator = std.testing.allocator;
    var pair: Pair = undefined;
    pair.init(allocator, .{});
    defer pair.deinit();
    const id = try pair.a.offer(testKey(1), "files", 4, @splat(0), "", 1_790_000_000);
    try std.testing.expectError(error.Incomplete, pair.a.start(id, 1));
    try std.testing.expectEqual(@as(u64, 2), try pair.a.put(id, 0, "ab"));
    try std.testing.expectEqual(@as(u64, 2), try pair.a.put(id, 0, "ab"));
    try std.testing.expectError(error.InvalidOffset, pair.a.put(id, 3, "d"));
    _ = try pair.a.put(id, 2, "cd");
    try std.testing.expectError(error.HashMismatch, pair.a.start(id, 1));
    try std.testing.expectError(error.TooLarge, pair.a.offer(testKey(1), "files", 64 * 1024 * 1024, @splat(0), "", 0));
}

test "a receiver that lost its state gets the transfer again from the start" {
    const allocator = std.testing.allocator;
    var pair: Pair = undefined;
    pair.init(allocator, .{});
    defer pair.deinit();
    try pair.b.listen("files", 16 * 1024 * 1024);
    const bytes = try pattern(allocator, 400 * 1024);
    defer allocator.free(bytes);
    const id = try pair.send(bytes, "files");
    pair.run(pair.net.now + 60 * ms);
    try std.testing.expectEqual(OutState.sending, pair.a.status(id).?.state);
    // Simulate a receiver restart: all incoming state disappears, listener re-registered.
    pair.b.deinit();
    pair.b = .init(allocator, .{});
    pair.b.setSender(&pair.eb, Net.send);
    try pair.b.listen("files", 16 * 1024 * 1024);
    pair.run(pair.net.now + 20 * std.time.ns_per_s);
    try std.testing.expectEqual(OutState.delivered, pair.a.status(id).?.state);
    const got = (try pair.received(allocator, "files")).?;
    defer allocator.free(got);
    try std.testing.expectEqualSlices(u8, bytes, got);
}

test "a silent receiver fails the transfer after the idle timeout" {
    const allocator = std.testing.allocator;
    var pair: Pair = undefined;
    pair.init(allocator, .{ .idle_timeout_ns = 2 * std.time.ns_per_s });
    defer pair.deinit();
    pair.net.blackhole = true;
    const bytes = try pattern(allocator, 3000);
    defer allocator.free(bytes);
    const id = try pair.send(bytes, "files");
    pair.run(3 * std.time.ns_per_s);
    try std.testing.expectEqual(OutState.failed, pair.a.status(id).?.state);
    try std.testing.expect(pair.a.release(id));
    try std.testing.expect(pair.a.status(id) == null);
}

test "acknowledgements from another peer are ignored and replayed offers are not re-delivered" {
    const allocator = std.testing.allocator;
    var pair: Pair = undefined;
    pair.init(allocator, .{});
    defer pair.deinit();
    try pair.b.listen("files", 1024 * 1024);
    const bytes = try pattern(allocator, 2000);
    defer allocator.free(bytes);
    const id = try pair.send(bytes, "files");
    var buf: [wire.MAX_FRAME]u8 = undefined;
    const forged = try wire.encodeAck(&buf, id, 3, &.{});
    pair.a.handleFrame(testKey(9), forged, pair.net.now, 1_790_000_000);
    try std.testing.expectEqual(@as(u32, 0), pair.a.status(id).?.acked_chunks);
    const forged_done = try wire.encodeDone(&buf, id, .verified);
    pair.a.handleFrame(testKey(9), forged_done, pair.net.now, 1_790_000_000);
    try std.testing.expectEqual(OutState.sending, pair.a.status(id).?.state);

    pair.run(5 * std.time.ns_per_s);
    const info = pair.b.nextComplete("files").?;
    try std.testing.expect(pair.b.release(info.id));
    // Replaying the original offer after release must not recreate the transfer.
    const replay = try wire.encodeOffer(&buf, id, .{ .created_unix = 1_790_000_000, .size = bytes.len, .chunk_size = wire.CHUNK_SIZE, .sha256 = info.sha256, .channel = "files", .meta = "" });
    pair.b.handleFrame(testKey(0), replay, pair.net.now, 1_790_000_000);
    try std.testing.expect(pair.b.nextComplete("files") == null);
    // Stale offers are refused outright.
    const stale = try wire.encodeOffer(&buf, @splat(5), .{ .created_unix = 1_780_000_000, .size = 10, .chunk_size = wire.CHUNK_SIZE, .sha256 = @splat(1), .channel = "files", .meta = "" });
    pair.b.handleFrame(testKey(0), stale, pair.net.now, 1_790_000_000);
    for (pair.b.incoming) |slot| try std.testing.expect(slot == null);
}
