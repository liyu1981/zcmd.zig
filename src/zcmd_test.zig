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

test {
    const allocator = std.heap.page_allocator;
    {
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "uname", "-a" },
            },
        });
        defer result.deinit();
        try testing.expectEqual(result.term.Exited, 0);
        try testing.expect(result.stdout.?.len > 0);
    }
}

pub fn main() !u8 {
    const allocator = std.heap.page_allocator;
    {
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "uname", "-a" },
            },
        });
        defer result.deinit();
        try testing.expectEqual(result.term.Exited, 0);
        try testing.expect(result.stdout.?.len > 0);
    }
    {
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "cat", "./tests/big_input.txt" },
                &.{ "wc", "-lw" },
            },
        });
        defer result.deinit();
        try testing.expectEqualSlices(
            u8,
            result.stdout.?,
            "    1302    2604\n",
        );
    }
    {
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "find", "tests" },
                &.{ "sort-of", "-nr" },
                &.{ "wc", "-lw" },
            },
        });
        defer result.deinit();
        try testing.expectEqualSlices(u8, result.stdout.?, "       0       0\n");
        try testing.expectEqualSlices(
            u8,
            result.stderr.?,
            "zig: error.FileNotFound: { sort-of, -nr }\n",
        );
    }
    {
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{"nonexist"},
                &.{ "wc", "-lw" },
            },
        });
        defer result.deinit();
        try testing.expectEqualSlices(u8, result.stdout.?, "       0       0\n");
        try testing.expectEqualSlices(
            u8,
            result.stderr.?,
            "zig: error.FileNotFound: { nonexist }\n",
        );
    }
    {
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "find", "nonexist" },
                &.{ "wc", "-lw" },
            },
        });
        defer result.deinit();
        try testing.expectEqualSlices(u8, result.stdout.?, "       0       0\n");
        try testing.expectEqualSlices(
            u8,
            result.stderr.?,
            "find: nonexist: No such file or directory\n",
        );
    }
    return 0;
}
