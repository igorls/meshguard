//! Minimal FreeBSD kqueue wrapper for userspace TUN/UDP readiness.
const std = @import("std");
const posix = std.posix;

const c = @cImport({
    @cInclude("sys/types.h");
    @cInclude("sys/event.h");
    @cInclude("sys/time.h");
    @cInclude("unistd.h");
});

pub const Kqueue = struct {
    fd: posix.fd_t,

    pub const Event = c.struct_kevent;

    pub fn init() !Kqueue {
        const fd = c.kqueue();
        if (fd < 0) return error.KqueueCreateFailed;
        return .{ .fd = @intCast(fd) };
    }

    pub fn close(self: *Kqueue) void {
        _ = std.c.close(self.fd);
    }

    pub fn addRead(self: *Kqueue, fd: posix.fd_t) !void {
        var change = std.mem.zeroes(Event);
        change.ident = @intCast(fd);
        change.filter = @intCast(c.EVFILT_READ);
        change.flags = @intCast(c.EV_ADD | c.EV_ENABLE);

        const rc = c.kevent(self.fd, &change, 1, null, 0, null);
        if (rc < 0) return error.KqueueRegisterFailed;
    }

    pub fn wait(self: *Kqueue, events: []Event, timeout_ms: i32) !usize {
        const ns_per_ms: c_long = 1_000_000;
        var timeout = c.struct_timespec{
            .tv_sec = @intCast(@divTrunc(timeout_ms, 1000)),
            .tv_nsec = @as(c_long, @intCast(@mod(timeout_ms, 1000))) * ns_per_ms,
        };
        const rc = c.kevent(self.fd, null, 0, events.ptr, @intCast(events.len), &timeout);
        if (rc < 0) return error.KqueueWaitFailed;
        return @intCast(rc);
    }
};
