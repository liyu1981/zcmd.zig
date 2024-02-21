const std = @import("std");

pub const zcmd = @import("src/zcmd.zig");

pub fn build(b: *std.Build) !void {
    _ = b.addModule("zcmd", .{
        .root_source_file = .{ .path = "src/zcmd.zig" },
    });
}
