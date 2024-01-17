const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const Zcmd = @import("zcmd.zig");

fn _testIsError(comptime T: type, maybe_value: anyerror!T, expected_error: anyerror) bool {
    if (maybe_value) |_| {
        return false;
    } else |err| {
        return err == expected_error;
    }
}

pub fn main() !u8 {
    const allocator = std.heap.page_allocator;
    // {
    //     const result = try Zcmd.run(allocator, &[_][]const []const u8{
    //         &.{ "uname", "-a" },
    //     });
    //     defer result.deinit();
    //     try testing.expectEqual(result.term.Exited, 0);
    //     try testing.expect(result.stdout.?.len > 0);
    // }
    // {
    //     const result = try Zcmd.run(allocator, &[_][]const []const u8{
    //         &.{ "cat", "./tests/big_input.txt" },
    //         &.{ "wc", "-lw" },
    //         &.{ "wc", "-lw" },
    //     });
    //     defer result.deinit();
    //     try testing.expectEqualSlices(u8, result.stdout.?, "       1       2\n");
    // }
    // {
    //     const result = Zcmd.run(
    //         allocator,
    //         &[_][]const []const u8{
    //             &.{"nonexist"},
    //         },
    //     );
    //     try testing.expectError(error.FileNotFound, result);
    // }
    // {
    //     const result = Zcmd.run(
    //         allocator,
    //         &[_][]const []const u8{
    //             &.{ "find", "nonexist" },
    //             &.{ "wc", "-lw" },
    //         },
    //     );
    //     // std.debug.print("\n{any}\n", .{result});
    //     try testing.expectError(error.FileNotFound, result);
    // }
    // {
    //     try Zcmd._run(allocator, &[_][]const []const u8{
    //         &.{ "find", "tests" },
    //         &.{ "sort-of", "-nr" },
    //         &.{ "wc", "-lw" },
    //     });
    // }
    {
        const result = try Zcmd.run(allocator, &[_][]const []const u8{
            &.{ "find", "tests" },
            &.{ "sort-of", "-nr" },
            &.{ "wc", "-lw" },
        });
        defer result.deinit();
        //std.debug.print("\nstdout: {?s}\nstderr: {?s}\n", .{ result.stdout, result.stderr });
        try testing.expectEqualSlices(u8, result.stdout.?, "       0       0\n");
        try testing.expectEqualSlices(u8, result.stderr.?, "zig: error.FileNotFound: { sort-of, -nr }\n");
    }
    // {
    //     try Zcmd._run(allocator, &[_][]const []const u8{
    //         &.{"nonexist"},
    //         &.{ "wc", "-lw" },
    //     });
    // }
    // {
    //     try Zcmd._run(allocator, &[_][]const []const u8{
    //         &.{ "find", "nonexist" },
    //         &.{ "wc", "-lw" },
    //     });
    // }
    return 0;
}
