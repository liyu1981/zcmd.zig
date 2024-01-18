const std = @import("std");

pub fn build(b: *std.Build) !void {
    _ = b.addModule("zcmd", .{
        .source_file = .{ .path = "src/zcmd.zig" },
    });
}
