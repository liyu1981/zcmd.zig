const std = @import("std");
const buildInfo = @import("build_generated.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Hello!\nversion: {s}\nbuilt os: {s}\n", .{
        buildInfo.version,
        buildInfo.built_os,
    });
}
