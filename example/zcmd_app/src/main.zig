const std = @import("std");
const linux = std.os.linux;

fn print(comptime msg: []const u8) void {
    _ = linux.write(std.posix.STDOUT_FILENO, msg.ptr, msg.len);
}

pub fn main() !void {
    print("running: uname -a\n");
    const allocator = std.heap.page_allocator;
    const result = try @import("zcmd").run(.{
        .allocator = allocator,
        .commands = &[_][]const []const u8{&.{ "uname", "-a" }},
    });
    defer result.deinit();
    result.assertSucceededPanic(.{});
    print("==== stdout ====\n");
    if (result.stdout) |stdout| {
        _ = linux.write(std.posix.STDOUT_FILENO, stdout.ptr, stdout.len);
        print("\n");
    }
}
