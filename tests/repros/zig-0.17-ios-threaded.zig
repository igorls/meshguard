const std = @import("std");

export fn seconds() i64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return @intCast(std.Io.Timestamp.now(io, .real).toSeconds());
}
