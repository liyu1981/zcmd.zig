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

test "runCommandAndGetResult exit with sigabrt" {
    const allocator = testing.allocator;
    _ = zcmd.runCommandAndGetResult(.{
        .allocator = allocator,
        // guranteed no binary panic
        .command = &[_][]const u8{"./tests/exit_sigabrt"},
    }, "test exit with sigabrt");
}

test "runCommandAndGetResult exit with not zero" {
    const allocator = testing.allocator;
    _ = zcmd.runCommandAndGetResult(.{
        .allocator = allocator,
        // guranteed no binary panic
        .command = &[_][]const u8{ "ls", "./notexist" },
    }, "test exit with not zero");
}

// test "runCommandAndGetResult exit with stop" {
//     const allocator = testing.allocator;
//     _ = zcmd.runCommandAndGetResult(.{
//         .allocator = allocator,
//         // guranteed no binary panic
//         .command = &[_][]const u8{"./tests/exit_stop"},
//     }, "test exit with stop");
// }

// test "runCommandAndGetResult exit with unknown reason" {
//     const allocator = testing.allocator;
//     _ = zcmd.runCommandAndGetResult(.{
//         .allocator = allocator,
//         // guranteed no binary panic
//         .command = &[_][]const u8{"./tests/exit_unknown"},
//     }, "test exit with unknown reason");
// }

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
        defer {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
        }
        try testing.expect(result.stderr.len > 0);
        // std.debug.print("\n{s}\n", .{result.stderr});
        const found = std.mem.indexOf(u8, result.stderr, "Command: { ./tests/witherr_exit_zero.sh } spawn failed error.InvalidExe! Error!");
        try testing.expect(found != null);
        if (found) |pos| {
            try testing.expect(pos > 0);
        }
    }
    {
        const result = try zcmd.runCommandAndGetResultErr(.{
            .allocator = allocator,
            // guranteed sigabrt panic
            .command = &[_][]const u8{
                "zig",
                "test",
                "src/panicTest.zig",
                "--test-filter",
                "runCommandAndGetResult exit with sigabrt",
            },
        });
        defer {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
        }
        try testing.expect(result.stderr.len > 0);
        // std.debug.print("\n{s}\n", .{result.stderr});
        const found = std.mem.indexOf(u8, result.stderr, "Command: { ./tests/exit_sigabrt } exited with signal 6! Error!");
        try testing.expect(found != null);
        if (found) |pos| {
            try testing.expect(pos > 0);
        }
    }
    {
        const result = try zcmd.runCommandAndGetResultErr(.{
            .allocator = allocator,
            // guranteed sigabrt panic
            .command = &[_][]const u8{
                "zig",
                "test",
                "src/panicTest.zig",
                "--test-filter",
                "runCommandAndGetResult exit with not zero",
            },
        });
        defer {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
        }
        try testing.expect(result.stderr.len > 0);
        // std.debug.print("\n{s}\n", .{result.stderr});
        const found = std.mem.indexOf(u8, result.stderr, "Command: { ls, ./notexist } exited with 1! Error!");
        try testing.expect(found != null);
        if (found) |pos| {
            try testing.expect(pos > 0);
        }
    }
}
