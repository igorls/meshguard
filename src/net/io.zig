//! Event loop abstraction.
//! TODO: Phase 2 — implement epoll/io_uring-based event loop.

const std = @import("std");

pub const EventType = enum {
    readable,
    writable,
    timer,
};

/// Minimal event loop placeholder.
/// Phase 2 will implement this with epoll for the SWIM protocol tick.
pub const EventLoop = struct {
    running: bool,

    pub fn init() EventLoop {
        return .{ .running = false };
    }

    pub fn start(self: *EventLoop) void {
        self.running = true;
        // TODO: Phase 2 — epoll_create, register fds, loop
    }

    pub fn stop(self: *EventLoop) void {
        self.running = false;
    }
};
