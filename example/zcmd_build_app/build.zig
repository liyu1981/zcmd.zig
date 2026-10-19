const std = @import("std");

// when import in build.zig, the zcmd is exposed in nested const zcmd
const zcmd = @import("zcmd").zcmd;

fn genBuildInfo(b: *std.Build) []const u8 {
    var aa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer aa.deinit();
    const allocator = aa.allocator();

    const r1 = zcmd.run(.{
        .allocator = allocator,
        .commands = &[_][]const []const u8{&.{ "git", "--git-dir=../../.git", "rev-parse", "--short=8", "HEAD" }},
    }) catch @panic("failed to run git rev-parse");
    defer r1.deinit();
    r1.assertSucceededPanic(.{});

    const r2 = zcmd.run(.{
        .allocator = allocator,
        .commands = &[_][]const []const u8{&.{ "uname", "-a" }},
    }) catch @panic("failed to run uname");
    defer r2.deinit();
    r2.assertSucceededPanic(.{});

    return b.fmt(
        \\pub const version = "{s}";
        \\pub const built_os = "{s}";
        \\
    , .{ r1.trimedStdout(), r2.trimedStdout() });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Generate `build_generated.zig` and expose it as an anonymous module
    // imported by the app as `@import("build_generated")`.
    const build_info = genBuildInfo(b);
    const gen_build_info = b.addWriteFile("build_generated.zig", build_info);

    const exe = b.addExecutable(.{
        .name = "zcmd_build_app",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addAnonymousImport("build_generated", .{
        .root_source_file = gen_build_info.getDirectory().path(b, "build_generated.zig"),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
