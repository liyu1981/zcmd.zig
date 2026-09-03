const std = @import("std");

pub const zcmd = @import("src/zcmd.zig");

pub fn build(b: *std.Build) void {
    _ = b.addModule("zcmd", .{
        .root_source_file = b.path("src/zcmd.zig"),
    });

    // Add test step
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zcmd.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
