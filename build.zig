const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "zcmd",
        .root_source_file = .{ .path = "src/zcmd.zig" },
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(lib);
}
