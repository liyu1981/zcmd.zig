const std = @import("std");

// when import in build.zig, the zcmd is exposed in nested const zcmd
const zcmd = @import("zcmd").zcmd;

fn genBuildInfoMake(self: *std.Build.Step, prog_node: *std.Progress.Node) anyerror!void {
    _ = prog_node;
    _ = self;
    var aa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer aa.deinit();

    const r1 = try zcmd.run(.{
        .allocator = aa.allocator(),
        .commands = &[_][]const []const u8{&.{ "git", "--git-dir=../../.git", "rev-parse", "--short=8", "HEAD" }},
    });
    defer r1.deinit();
    r1.assertSucceededPanic(.{});

    const r2 = try zcmd.run(.{
        .allocator = aa.allocator(),
        .commands = &[_][]const []const u8{&.{ "uname", "-a" }},
    });
    defer r2.deinit();
    r2.assertSucceededPanic(.{});

    const f = try std.fs.cwd().createFile("src/build_generated.zig", .{});
    defer f.close();
    const tpl =
        \\ pub const version = "{s}";
        \\ pub const built_os = "{s}";
        \\
    ;
    try f.writer().print(tpl, .{ r1.trimedStdout(), r2.trimedStdout() });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const gen_build_info_step = b.step("gen_build_info", "generate build info to src/build_generated.zig");
    gen_build_info_step.makeFn = genBuildInfoMake;

    const exe = b.addExecutable(.{
        .name = "zcmd_build_app",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.step.dependOn(gen_build_info_step);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
