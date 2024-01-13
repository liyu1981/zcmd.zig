const std = @import("std");
const testing = std.testing;
const zcmd = @import("zcmd.zig");

test "runCommandAndGetResult no binary panics trigger" {
    const allocator = testing.allocator;
    _ = zcmd.runCommandAndGetResult(.{
        .allocator = allocator,
        // guranteed no binary panic
        .command = &[_][]const u8{"./tests/witherr_exit_zero.sh"},
    }, "test witherr_exit_zero.sh");
}

test "catchers" {
    const allocator = testing.allocator;
    {
        const result = try zcmd.runCommandAndGetResultErr(.{
            .allocator = allocator,
            // guranteed no binary panic
            .command = &[_][]const u8{
                "zig",
                "test",
                "src/panicTest.zig",
                "--test-filter",
                "runCommandAndGetResult no binary panics trigger",
            },
        });
        defer result.deinit();
        try testing.expect(result.stderr.len > 0);
        // std.debug.print("\n{s}\n", .{result.stderr});
        const found = std.mem.indexOf(u8, result.stderr, "Command: { ./tests/witherr_exit_zero.sh } spawn failed error.InvalidExe! Error!");
        try testing.expect(found != null);
        if (found) |pos| {
            try testing.expect(pos > 0);
        }
    }
}
