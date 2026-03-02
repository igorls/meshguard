const std = @import("std");
pub fn main() !void {
    std.posix.fchmodat(std.fs.cwd().fd, "test_file.txt", 0o666, 0) catch {};
    std.debug.print("chmod ok\n", .{});
}
