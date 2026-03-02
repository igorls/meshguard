const std = @import("std");

pub fn main() !void {
    const data = [_]u8{0xde, 0xad, 0xbe, 0xef};
    var buf: [100]u8 = undefined;
    const str = try std.fmt.bufPrint(&buf, "{s}", .{std.fmt.bytesToHex(data, .lower)});
    std.debug.print("{s}\n", .{str});
}
