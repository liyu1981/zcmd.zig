const std = @import("std");
const linux = std.os.linux;

// when import in build.zig, the zcmd is exposed in nested const zcmd
const zcmd = @import("zcmd").zcmd;

fn genBuildInfoMake(self: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
    _ = options;
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

    // Write build_generated.zig using low-level file operations
    const file_path = "src/build_generated.zig";
    const fd_result = std.os.linux.openat(std.posix.AT.FDCWD, file_path, std.os.linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (fd_result < 0) return error.WriteFailed;
    const fd: i32 = @intCast(fd_result);
    defer _ = linux.close(fd);

    const version = r1.trimedStdout();
    const built_os = r2.trimedStdout();

    // Format and write the file content
    var buf: [8192]u8 = undefined;
    const content = std.fmt.bufPrint(&buf,
        \\pub const version = "{s}";
        \\pub const built_os = "{s}";
        \\
    , .{ version, built_os }) catch return error.WriteFailed;
    _ = linux.write(fd, content.ptr, content.len);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const gen_build_info_step = b.step("gen_build_info", "generate build info to src/build_generated.zig");
    gen_build_info_step.makeFn = genBuildInfoMake;

    const exe = b.addExecutable(.{
        .name = "zcmd_build_app",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
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
