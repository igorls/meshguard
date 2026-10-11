//! 64-bit atomics that also build on 32-bit targets.
//!
//! Zig lowers atomic operations on 64-bit integers only where the target has
//! native 64-bit atomic instructions it supports: on 32-bit ARM (Android
//! armeabi-v7a, arm-linux-gnueabihf) `std.atomic.Value(u64)` does not compile.
//! The types here are plain `std.atomic.Value` (lock-free, the same code as
//! before) on targets with 64-bit pointers, and guard the value with a mutex
//! elsewhere. Every 32-bit target takes the locked path, even one that has
//! 64-bit atomic instructions: it is correct everywhere and only slower.
//!
//! The locked implementations are public so tests can run them on 64-bit hosts.
const std = @import("std");

/// True where the types below are lock-free `std.atomic.Value` wrappers.
pub const lock_free = @bitSizeOf(usize) >= 64;

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// An atomic 64-bit integer (statistics, timestamps). Same API subset as
/// `std.atomic.Value`: `init`, `load`, `store`, `fetchAdd` (wrapping).
pub fn Value(comptime T: type) type {
    return ValueImpl(T, lock_free);
}

pub fn ValueImpl(comptime T: type, comptime use_atomics: bool) type {
    return if (use_atomics) std.atomic.Value(T) else LockedValue(T);
}

/// Mutex-guarded value. The mutex orders every access to `raw`, so each
/// operation is at least as strong as the requested memory order (lock is an
/// acquire, unlock a release).
pub fn LockedValue(comptime T: type) type {
    return struct {
        raw: T,
        mutex: std.Io.Mutex = .init,

        const Self = @This();

        pub fn init(value: T) Self {
            return .{ .raw = value };
        }

        pub fn load(self: *const Self, comptime order: std.builtin.AtomicOrder) T {
            _ = order;
            // Loading takes the lock too; it never changes `raw`.
            const mutex: *std.Io.Mutex = @constCast(&self.mutex);
            mutex.lockUncancelable(zio());
            defer mutex.unlock(zio());
            return self.raw;
        }

        pub fn store(self: *Self, value: T, comptime order: std.builtin.AtomicOrder) void {
            _ = order;
            self.mutex.lockUncancelable(zio());
            defer self.mutex.unlock(zio());
            self.raw = value;
        }

        /// Adds with wraparound and returns the previous value, like
        /// `std.atomic.Value.fetchAdd`.
        pub fn fetchAdd(self: *Self, operand: T, comptime order: std.builtin.AtomicOrder) T {
            _ = order;
            self.mutex.lockUncancelable(zio());
            defer self.mutex.unlock(zio());
            const previous = self.raw;
            self.raw +%= operand;
            return previous;
        }
    };
}

/// A nonce counter that hands out disjoint blocks of 64-bit values, for the
/// WireGuard send counter. `reserve(n)` returns the first of `n` consecutive
/// values no other call received.
pub const NonceCounter = NonceCounterImpl(lock_free);

pub fn NonceCounterImpl(comptime use_atomics: bool) type {
    return if (use_atomics) AtomicNonceCounter else LockedNonceCounter;
}

/// Lock-free: a single `fetchAdd`, exactly what the send path always used, and
/// the same fetch-add-then-check scheme as the kernel WireGuard send path. It
/// wraps, but only after 2^64 reservations: a key's counter starts at 0, so it
/// would take about 1.8e19 sends to reach REJECT_AFTER_MESSAGES (and 2050 more
/// to wrap), while a key is rejected after 180 s (REJECT_AFTER_TIME), which
/// allows under 2e11 sends even at 10^9 packets per second.
pub const AtomicNonceCounter = struct {
    value: std.atomic.Value(u64),

    pub fn init(value: u64) AtomicNonceCounter {
        return .{ .value = .init(value) };
    }

    pub inline fn reserve(self: *AtomicNonceCounter, n: u64) u64 {
        return self.value.fetchAdd(n, .monotonic);
    }

    pub inline fn load(self: *const AtomicNonceCounter) u64 {
        return self.value.load(.monotonic);
    }
};

/// Locked: reads and advances the counter as one step under a mutex, so no
/// two calls see the same value, and saturates instead of wrapping. Every value
/// below maxInt(u64) is handed out at most once; once the counter is exhausted
/// each call returns maxInt(u64), which callers reject (it is above
/// REJECT_AFTER_MESSAGES) and which is never used as a nonce.
pub const LockedNonceCounter = struct {
    next: u64,
    mutex: std.Io.Mutex = .init,

    pub fn init(value: u64) LockedNonceCounter {
        return .{ .next = value };
    }

    pub fn reserve(self: *LockedNonceCounter, n: u64) u64 {
        self.mutex.lockUncancelable(zio());
        defer self.mutex.unlock(zio());
        const start = self.next;
        self.next = start +| n;
        return start;
    }

    pub fn load(self: *const LockedNonceCounter) u64 {
        const mutex: *std.Io.Mutex = @constCast(&self.mutex);
        mutex.lockUncancelable(zio());
        defer mutex.unlock(zio());
        return self.next;
    }
};

// ─── Tests ───

const testing = std.testing;

test "lock_free matches the pointer width" {
    try testing.expectEqual(@bitSizeOf(usize) >= 64, lock_free);
    if (lock_free) {
        try testing.expect(Value(u64) == std.atomic.Value(u64));
        try testing.expect(NonceCounter == AtomicNonceCounter);
    } else {
        try testing.expect(Value(u64) == LockedValue(u64));
        try testing.expect(NonceCounter == LockedNonceCounter);
    }
}

fn expectValueSemantics(comptime use_atomics: bool) !void {
    var v = ValueImpl(u64, use_atomics).init(0);
    try testing.expectEqual(@as(u64, 0), v.load(.acquire));
    try testing.expectEqual(@as(u64, 0), v.fetchAdd(5, .release));
    try testing.expectEqual(@as(u64, 5), v.load(.acquire));
    v.store(std.math.maxInt(u64), .release);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), v.fetchAdd(2, .monotonic));
    try testing.expectEqual(@as(u64, 1), v.load(.monotonic)); // wraps, like @atomicRmw

    var t = ValueImpl(i64, use_atomics).init(0);
    t.store(-42, .release);
    try testing.expectEqual(@as(i64, -42), t.load(.acquire));
    t.store(std.math.maxInt(i64), .release);
    try testing.expectEqual(@as(i64, std.math.maxInt(i64)), t.load(.acquire));
}

test "Value: lock-free and locked implementations agree" {
    try expectValueSemantics(false);
    if (lock_free) try expectValueSemantics(true);
}

fn addMany(v: anytype, iterations: usize) void {
    for (0..iterations) |_| _ = v.fetchAdd(1, .release);
}

test "LockedValue: concurrent fetchAdd loses no increments" {
    const threads = 4;
    const iterations = 20_000;
    var v = LockedValue(u64).init(0);
    var handles: [threads]std.Thread = undefined;
    for (&handles) |*h| h.* = try std.Thread.spawn(.{}, addMany, .{ &v, iterations });
    for (handles) |h| h.join();
    try testing.expectEqual(@as(u64, threads * iterations), v.load(.acquire));
}

test "LockedValue: a 64-bit value is never torn across its halves" {
    // Alternate between two values whose 32-bit halves both differ; a torn
    // read would mix them.
    const a: u64 = 0x0000_0000_FFFF_FFFF;
    const b: u64 = 0xFFFF_FFFF_0000_0000;
    var v = LockedValue(u64).init(a);
    var stop = std.atomic.Value(bool).init(false);
    const Writer = struct {
        fn run(value: *LockedValue(u64), done: *std.atomic.Value(bool)) void {
            var flip = false;
            while (!done.load(.acquire)) : (flip = !flip) value.store(if (flip) a else b, .release);
        }
    };
    const writer = try std.Thread.spawn(.{}, Writer.run, .{ &v, &stop });
    defer writer.join();
    defer stop.store(true, .release);
    for (0..50_000) |_| {
        const seen = v.load(.acquire);
        try testing.expect(seen == a or seen == b);
    }
}

fn reserveMany(counter: anytype, out: []u64, block: u64) void {
    for (out) |*slot| slot.* = counter.reserve(block);
}

fn expectDisjointConcurrentBlocks(comptime C: type) !void {
    const threads = 4;
    const per_thread = 5_000;
    const block = 3;
    var counter = C.init(0);
    var starts: [threads][per_thread]u64 = undefined;
    var handles: [threads]std.Thread = undefined;
    for (&handles, &starts) |*h, *out| h.* = try std.Thread.spawn(.{}, reserveMany, .{ &counter, out, block });
    for (handles) |h| h.join();

    // Every block start is a distinct multiple of the block size, and together
    // they cover [0, threads * per_thread * block) exactly once.
    const all: []u64 = @as([*]u64, @ptrCast(&starts))[0 .. threads * per_thread];
    std.mem.sort(u64, all, {}, std.sort.asc(u64));
    for (all, 0..) |start, i| try testing.expectEqual(@as(u64, i * block), start);
    try testing.expectEqual(@as(u64, threads * per_thread * block), counter.load());
}

test "NonceCounter: concurrent reservations never overlap" {
    try expectDisjointConcurrentBlocks(LockedNonceCounter);
    if (lock_free) try expectDisjointConcurrentBlocks(AtomicNonceCounter);
}

test "LockedNonceCounter: saturates at maxInt instead of wrapping" {
    const max = std.math.maxInt(u64);
    var counter = LockedNonceCounter.init(max - 3);
    try testing.expectEqual(@as(u64, max - 3), counter.reserve(1));
    try testing.expectEqual(@as(u64, max - 2), counter.reserve(10)); // partial block
    try testing.expectEqual(@as(u64, max), counter.load());
    // Exhausted: every caller gets maxInt, never a small (reused) value.
    for (0..4) |_| try testing.expectEqual(@as(u64, max), counter.reserve(1));
    try testing.expectEqual(@as(u64, max), counter.reserve(0));
    try testing.expectEqual(@as(u64, max), counter.load());
}

test "LockedNonceCounter: reserve(0) does not advance" {
    var counter = LockedNonceCounter.init(7);
    try testing.expectEqual(@as(u64, 7), counter.reserve(0));
    try testing.expectEqual(@as(u64, 7), counter.reserve(1));
    try testing.expectEqual(@as(u64, 8), counter.load());
}
