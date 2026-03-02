const std = @import("std");

pub fn main() !void {
    std.posix.fchmodat(std.fs.cwd().fd, "test.txt", 0o666, 0) catch |err| {
        std.debug.print("err: {}\n", .{err});
    };
}
