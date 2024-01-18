const std = @import("std");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("running: {s}\n", .{"uname -a"});
    const allocator = std.heap.page_allocator;
    const result = try @import("zcmd").run(.{
        .allocator = allocator,
        .commands = &[_][]const []const u8{&.{ "uname", "-a" }},
    });
    defer result.deinit();
    try stdout.print("==== stdout ====\n{?s}\n", .{result.stdout});
}
