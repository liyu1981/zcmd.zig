const std = @import("std");

test "stop test" {
    const rr = try std.ChildProcess.run(.{
        .allocator = @import("std").testing.allocator,
        .argv = &[_][]const u8{"./exit_stop"},
    });
    _ = rr;
}
