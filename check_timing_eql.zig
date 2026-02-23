const std = @import("std");

pub fn main() !void {
    const a = [_]u8{1} ** 16;
    const b = [_]u8{1} ** 16;

    // Attempt 3: std.crypto.eql
    const match3 = std.crypto.eql([16]u8, a, b);
    std.debug.print("Match3: {}\n", .{match3});
}
