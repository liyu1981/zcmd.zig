const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const OS_PAGE_SIZE = switch (builtin.os.tag) {
    .linux, .macos => std.mem.page_size,
    else => {
        @compileError("Only linux & macos supported.");
    },
};

pub const MAX_OUTPUT = 8 * 1024 * 1024 * 1024;

const stderr_writer = std.io.getStdErr().writer();

pub const SimpleRunResult = struct {
    allocator: std.mem.Allocator,
    stdout: []const u8,
    stderr: []const u8,

    pub fn deinit(this: *const SimpleRunResult) void {
        this.allocator.free(this.stdout);
        this.allocator.free(this.stderr);
    }
};

/// This one is a simple wrapper of std.ChildProcess.runChildProcess, by providing a little bit of convinience.
/// * it defaults will use cwd if not provided
/// * it increases the default max_output_bytes to 8G!
/// * it can accept a stdin_input: []const u8 as the stdin
/// It will return an error or std.ChildProcess.RunResult, receiver is responsible to free the slices inside
/// `std.ChildProcess.RunResult`
pub fn runCommandAndGetResultErr(args: struct {
    allocator: std.mem.Allocator,
    command: []const []const u8,
    stdin_input: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = MAX_OUTPUT,
    expand_arg0: std.ChildProcess.Arg0Expand = .no_expand,
}) anyerror!std.ChildProcess.RunResult {
    // shameless steal the implementation of runChildProcess from zig source code as I need to customize it a bit
    var child = std.ChildProcess.init(args.command, args.allocator);
    child.stdin_behavior = if (args.stdin_input == null) .Ignore else .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.cwd_dir = brk: {
        if (args.cwd) |cwd_str| break :brk try std.fs.openDirAbsolute(cwd_str, .{});
        if (args.cwd_dir) |cwd| break :brk cwd;
        break :brk std.fs.cwd();
    };
    child.env_map = args.env_map;
    child.expand_arg0 = args.expand_arg0;

    var stdout = std.ArrayList(u8).init(args.allocator);
    var stderr = std.ArrayList(u8).init(args.allocator);
    errdefer {
        stdout.deinit();
        stderr.deinit();
    }

    try child.spawn();

    if (child.stdin_behavior == .Pipe) {
        if (args.stdin_input) |stdin_input| {
            // start a thread to send stdin_input to child process instead of in main thread. This is crucial in cases like
            // chained commands because the child process may have error.FileNotFound(like not find the binary), so that
            // child.stdin pipe is broken, then without a threaded solution we will stuck in the feeding loop.
            var t: std.Thread = try std.Thread.spawn(
                .{},
                sendStdinToCommand,
                .{
                    &child,
                    stdin_input,
                },
            );
            // this is very dangerous as we let our thread on their own, but hopefully we know what's we are doing here
            t.detach();
        }
    }

    try child.collectOutput(&stdout, &stderr, args.max_output_bytes);
    // t.join();

    const rr = std.ChildProcess.RunResult{
        .term = try child.wait(),
        .stdout = try stdout.toOwnedSlice(),
        .stderr = try stderr.toOwnedSlice(),
    };

    return rr;
}

/// This wraps `runCommandAndGetResultErr` to enabled chained commands, such as `ls -la | wc -l`, can be called with
/// ```
/// runChainedCommandsAndGetResultErr(.{ .allocator = allocator, .commands = &[_][]const []const u8{
///     &.{"ls", "la"},
///     &.{"wc", "-l"},
/// }});
/// ```
///
/// It is called chained commands instead of piped commands because foundamentally it does not use unix pipes to
/// implement. Instead it will try to run command one by one and cache the intermediate result in mem, and then feed
/// into next command as stdin. There is currently no good way of writting real piped commands in zig without rewrite
/// std.ChildProcess.
///
/// As a result, it also provides option `stop_on_any_error` and `stop_on_any_stderr` to control the flow a bit
/// * when `stop_on_any_error` is true (default is true), will stop at the first command return `anyerror`,
///   or exit rather than return `0`. In the end return the last command's `std.ChildProcess.RunResult`.
/// * when `stop_on_any_stderr` is true (default is false), will stop at the first command exit with return `0`, but
///   with `stderr` not empty. In the end return the last command's `std.ChildProcess.RunResult`.
pub fn runChainedCommandsAndGetResultErr(args: struct {
    allocator: std.mem.Allocator,
    commands: []const []const []const u8,
    stdin_input: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = MAX_OUTPUT,
    expand_arg0: std.ChildProcess.Arg0Expand = .no_expand,
    trim_stdout: bool = true,
    trim_stderr: bool = true,
    stop_on_any_error: bool = true,
    stop_on_any_stderr: bool = false,
}) anyerror!std.ChildProcess.RunResult {
    var need_free_to_free: bool = false;
    var to_free_result: std.ChildProcess.RunResult = undefined;
    var need_free_last: bool = true;
    var last_run_result: std.ChildProcess.RunResult = undefined;
    for (args.commands, 0..) |command, i| {
        if (i > 0 and need_free_last) {
            to_free_result = last_run_result;
            need_free_to_free = true;
        }
        last_run_result = runCommandAndGetResultErr(.{
            .allocator = args.allocator,
            .command = command,
            .stdin_input = brk: {
                if (i == 0) {
                    if (args.stdin_input) |stdin_input| break :brk stdin_input else break :brk null;
                } else break :brk last_run_result.stdout;
            },
            .cwd = args.cwd,
            .cwd_dir = args.cwd_dir,
            .env_map = args.env_map,
            .max_output_bytes = args.max_output_bytes,
            .expand_arg0 = args.expand_arg0,
        }) catch |err| {
            defer {
                if (i > 0 and need_free_to_free) {
                    args.allocator.free(to_free_result.stdout);
                    args.allocator.free(to_free_result.stderr);
                    need_free_to_free = false;
                }
            }
            if (args.stop_on_any_error) {
                return err;
            }
            last_run_result = std.ChildProcess.RunResult{
                .term = std.ChildProcess.Term{ .Exited = 1 },
                .stdout = "",
                .stderr = "",
            };
            need_free_last = false;
            continue;
        };
        defer {
            if (i > 0 and need_free_to_free) {
                args.allocator.free(to_free_result.stdout);
                args.allocator.free(to_free_result.stderr);
                need_free_to_free = false;
            }
        }
        switch (last_run_result.term) {
            .Exited => |ret| {
                if (ret != 0 and args.stop_on_any_error) {
                    return last_run_result;
                }
                if (last_run_result.stderr.len > 0 and args.stop_on_any_stderr) {
                    return last_run_result;
                }
                need_free_last = true;
                continue;
            },
            else => {
                if (args.stop_on_any_error) {
                    return last_run_result;
                }
                need_free_last = true;
                continue;
            },
        }
    }
    return last_run_result;
}

/// No error version of `runCommandAndGetResultErr`. It will never return a error and instead @panic when some command
/// fails. This is most suitable for script or guranteed execution. It returns SimpleRunResult with caller
/// owned `stdout` and `stderr` slices.
/// * `trim_stdout` and `trim_stderr` can control whether to trim white spaces of `stdout` and `stderr`. Defaultly they
///   are true.
pub fn runCommandAndGetResult(args: struct {
    allocator: std.mem.Allocator,
    command: []const []const u8,
    stdin_input: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = MAX_OUTPUT,
    expand_arg0: std.ChildProcess.Arg0Expand = .no_expand,
    trim_stdout: bool = true,
    trim_stderr: bool = true,
}, comptime panic_msg: []const u8) SimpleRunResult {
    const rr = runCommandAndGetResultErr(.{
        .allocator = args.allocator,
        .command = args.command,
        .cwd = args.cwd,
        .cwd_dir = args.cwd_dir,
        .max_output_bytes = args.max_output_bytes,
        .stdin_input = args.stdin_input,
    }) catch |err| {
        stderr_writer.print("Command: {s} spawn failed {any}! Error!\n", .{ args.command, err }) catch {};
        @panic(panic_msg);
    };
    switch (rr.term) {
        .Exited => |ret| {
            if (ret == 0) {
                return SimpleRunResult{
                    .allocator = args.allocator,
                    .stdout = brk: {
                        if (args.trim_stdout) {
                            defer args.allocator.free(rr.stdout);
                            break :brk _toOwnedSlice(
                                u8,
                                args.allocator,
                                std.mem.trim(u8, rr.stdout, " \t\n\r"),
                            ) catch {
                                @panic("trim stdout OOM!");
                            };
                        } else break :brk rr.stdout;
                    },
                    .stderr = brk: {
                        if (args.trim_stderr) {
                            defer args.allocator.free(rr.stderr);
                            break :brk _toOwnedSlice(
                                u8,
                                args.allocator,
                                std.mem.trim(u8, rr.stderr, " \t\n\r"),
                            ) catch {
                                @panic("trim stderr OOM!");
                            };
                        } else break :brk rr.stderr;
                    },
                };
            } else {
                stderr_writer.print("Command: {s} exited with {d}! Error!\n", .{ args.command, ret }) catch {};
            }
        },
        .Signal => |ret| {
            stderr_writer.print("Command: {s} exited with signal {d}! Error!", .{ args.command, ret }) catch {};
        },
        .Stopped => |_| {
            // stderr_writer.print("Command: {s} stopped with {d}! Error!", .{ args.command, ret }) catch {};
            @panic("never able to reach here until https://github.com/ziglang/zig/issues/18548 resolved.");
        },
        .Unknown => |_| {
            // stderr_writer.print("Command: {s} exited with unknown reason {d}! Error!", .{ args.command, ret }) catch {};
            @panic("never able to reach here until https://github.com/ziglang/zig/issues/18548 resolved.");
        },
    }

    stderr_writer.print("==== stdout ====\n{s}\n==== stderr ====\n{s}\n", .{ rr.stdout, rr.stderr }) catch {};
    // we will go panic in below so no free rr.stdout & rr.stderr
    @panic(panic_msg);
}

/// This wraps `runCommandAndGetResult` to enabled piped commands, such as `ls -la | wc -l`, can be called with
/// ```
/// runChainedCommandAndGetResult(.{ .allocator = allocator, .commands = &[_][]const []const u8{
///     &.{"ls", "la"},
///     &.{"wc", "-l"},
/// }});
/// ```
/// * no `stop_on_any_error` as any error will cause @panic(panic_msg)
/// * when `stop_on_any_stderr` is true (default is false), will stop at the first command exit with `stderr` not empty.
///   In the end return the last command's `std.ChildProcess.RunResult`.
pub fn runChainedCommandAndGetResult(args: struct {
    allocator: std.mem.Allocator,
    commands: []const []const []const u8,
    stdin_input: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = MAX_OUTPUT,
    expand_arg0: std.ChildProcess.Arg0Expand = .no_expand,
    trim_stdout: bool = true,
    trim_stderr: bool = true,
    stop_on_any_stderr: bool = false,
}, comptime panic_msg: []const u8) SimpleRunResult {
    var to_free_result: SimpleRunResult = undefined;
    var last_run_result: SimpleRunResult = undefined;
    for (args.commands, 0..) |command, i| {
        if (i > 0) {
            to_free_result = last_run_result;
        }

        last_run_result = runCommandAndGetResult(.{
            .allocator = args.allocator,
            .command = command,
            .stdin_input = brk: {
                if (i == 0) {
                    if (args.stdin_input) |stdin_input| break :brk stdin_input else break :brk null;
                } else break :brk last_run_result.stdout;
            },
            .cwd = args.cwd,
            .cwd_dir = args.cwd_dir,
            .env_map = args.env_map,
            .max_output_bytes = args.max_output_bytes,
            .expand_arg0 = args.expand_arg0,
        }, panic_msg);

        defer {
            if (i > 0) {
                to_free_result.deinit();
            }
        }

        if (args.stop_on_any_stderr and last_run_result.stderr.len > 0) {
            return last_run_result;
        }
    }
    return last_run_result;
}

// internal functions

fn sendStdinToCommand(command_child_process: *std.ChildProcess, stdin_input: ?[]const u8) void {
    // credit goes to: https://www.reddit.com/r/Zig/comments/13674ed/help_request_using_stdin_with_childprocess/
    if (stdin_input) |si| {
        // std.debug.print("\ninput of {d} bytes\n", .{si.len});
        if (command_child_process.stdin) |stdin| {
            // If want to handle stdin_input.len > PIPE_BUF case (think pipe 1G bytes to our commands), then can not
            // write all stdin_input at once as it will cause broken pipe. Instead, do a more careful write and valid
            // approach here.
            // Since pipe buf limits are different to each system, be very conservative here, use generally page_size
            // as batch_size. Learn pipe buf limits here: https://www.netmeister.org/blog/ipcbufs.html
            const batch_size = OS_PAGE_SIZE;
            var offset: usize = 0;
            var wrote_size: usize = 0;

            var fds: [1]std.os.pollfd = undefined;
            fds[0].fd = stdin.handle;
            fds[0].events = std.os.POLL.OUT;

            var poll_ready_count: usize = 0;

            write_loop: {
                // every pool error or write error see in below is simply ignored because we are in the thread dedicated
                // for feeding stdin_input to child process. If child process have something wrong in its PIPE fd, then
                // definitely means we will see an error in main thread.
                while (offset < si.len) {
                    poll_ready_count = std.os.poll(&fds, -1) catch break :write_loop;
                    if (poll_ready_count == 0) {
                        continue;
                    } else {
                        if (fds[0].revents & std.os.POLL.OUT != 0) {
                            if (offset + batch_size < si.len) {
                                wrote_size = stdin.write(si[offset .. offset + batch_size]) catch break :write_loop;
                            } else {
                                wrote_size = stdin.write(si[offset..]) catch break :write_loop;
                            }
                            offset += wrote_size;
                            // std.debug.print("\nconsumed {d} bytes of input\n", .{offset});
                        } else {
                            continue;
                        }
                    }
                }
            }

            // job done, so close the stdin pipe so that child process knows input is done
            command_child_process.*.stdin.?.close();
            command_child_process.*.stdin = null;
        }
    }
}

fn _toOwnedSlice(comptime T: type, allocator: std.mem.Allocator, src: []const T) anyerror![]T {
    const new_slice = try allocator.alloc(T, src.len);
    @memcpy(new_slice, src);
    return new_slice;
}

fn _testIsError(comptime T: type, maybe_value: anyerror!T, expected_error: anyerror) bool {
    if (maybe_value) |_| {
        return false;
    } else |err| {
        return err == expected_error;
    }
}

// all tests

test "single cmd test" {
    const allocator = std.testing.allocator;
    {
        const result = runCommandAndGetResult(.{
            .allocator = allocator,
            .command = &[_][]const u8{ "uname", "-a" },
        }, "test uname -a");
        defer result.deinit();
        try testing.expect(result.stdout.len > 0);
        try testing.expect(result.stderr.len == 0);
    }
    {
        const result = runCommandAndGetResult(.{
            .allocator = allocator,
            .command = &[_][]const u8{ "bash", "./tests/witherr_exit_zero.sh" },
        }, "test witherr_exit_zero.sh");
        defer result.deinit();
        try testing.expect(result.stdout.len == 0);
        try testing.expect(result.stderr.len > 0);
    }
    {
        const result = runCommandAndGetResult(.{
            .allocator = allocator,
            .command = &[_][]const u8{ "uname", "-a" },
            .trim_stdout = false,
            .trim_stderr = false,
        }, "test uname -a, no trim");
        defer result.deinit();
        try testing.expect(result.stdout.len > 0);
        try testing.expect(result.stderr.len == 0);
    }
    {
        const inputs = try std.fs.cwd().readFileAlloc(allocator, "tests/big_input.txt", MAX_OUTPUT);
        defer allocator.free(inputs);
        const result = try runCommandAndGetResultErr(.{
            .allocator = allocator,
            .command = &[_][]const u8{ "sort", "-n" },
            .stdin_input = inputs,
        });
        defer {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
        }
        try testing.expect(result.term.Exited == 0);
        try testing.expect(result.stdout.len > 0);
        try testing.expect(result.stderr.len == 0);
    }
}

test "pipe cmd test" {
    const allocator = std.testing.allocator;
    // {
    //     const result = try runChainedCommandsAndGetResultErr(.{
    //         .allocator = allocator,
    //         .commands = &[_][]const []const u8{
    //             &.{ "find", "./tests", "-type", "f", "-exec", "stat", "-f", "'%m %N'", "{}", ";" },
    //             &.{ "sort", "-nr" },
    //             &.{"head"},
    //         },
    //     });
    //     defer {
    //         allocator.free(result.stdout);
    //         allocator.free(result.stderr);
    //     }
    //     try testing.expect(result.stdout.len > 0);
    //     try testing.expect(result.stderr.len == 0);
    // }
    // {
    //     var result = runChainedCommandAndGetResult(.{
    //         .allocator = allocator,
    //         .commands = &[_][]const []const u8{
    //             &.{ "find", "./tests", "-type", "f", "-exec", "stat", "-f", "'%m %N'", "{}", ";" },
    //             &.{ "sort", "-nr" },
    //             &.{"head"},
    //         },
    //     }, "recursively find and list the latest modified files in a directory with subdirectories and times");
    //     defer result.deinit();
    //     try testing.expect(result.stdout.len > 0);
    //     try testing.expect(result.stderr.len == 0);
    // }
    {
        const maybe_result = runChainedCommandsAndGetResultErr(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "cat", "./tests/big_input.txt" },
                &.{ "sort-of", "-nr" },
                &.{"head"},
            },
        });
        // std.debug.print("\n{any}\n", .{maybe_result});
        try testing.expect(_testIsError(
            std.ChildProcess.RunResult,
            maybe_result,
            error.FileNotFound,
        ));
    }
    {
        const result = try runChainedCommandsAndGetResultErr(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{"notexist.sh"},
                &.{ "uname", "-a" },
            },
            .stop_on_any_error = false,
        });
        defer {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
        }
        try testing.expect(result.stdout.len > 0);
        try testing.expect(result.stderr.len == 0);
    }
    // {
    //     var result = runChainedCommandAndGetResult(.{
    //         .allocator = allocator,
    //         .commands = &[_][]const []const u8{
    //             &.{ "bash", "./tests/witherr_exit_zero.sh" },
    //             &.{ "uname", "-a" },
    //         },
    //         .stop_on_any_stderr = true,
    //     }, "should stop on ./tests/witherr_exit_zero.sh ");
    //     defer result.deinit();
    //     try testing.expect(result.stdout.len == 0);
    //     try testing.expectEqualSlices(u8, result.stderr, "cat: notexist.txt: No such file or directory");
    // }
    // {
    //     const result = try runChainedCommandsAndGetResultErr(.{
    //         .allocator = allocator,
    //         .commands = &[_][]const []const u8{
    //             &.{"./tests/exit_sigabrt"},
    //             &.{ "uname", "-a" },
    //         },
    //         .stop_on_any_error = true,
    //     });
    //     defer {
    //         allocator.free(result.stdout);
    //         allocator.free(result.stderr);
    //     }
    //     try testing.expectEqual(result.term.Signal, 6); // 6 is SIGABRT
    //     try testing.expect(result.stdout.len == 0);
    //     try testing.expect(result.stderr.len == 0);
    // }
    // {
    //     const result = try runChainedCommandsAndGetResultErr(.{
    //         .allocator = allocator,
    //         .commands = &[_][]const []const u8{
    //             &.{"./tests/exit_sigabrt"},
    //             &.{ "uname", "-a" },
    //         },
    //         .stop_on_any_error = false,
    //     });
    //     defer {
    //         allocator.free(result.stdout);
    //         allocator.free(result.stderr);
    //     }
    //     try testing.expectEqual(result.term.Exited, 0);
    //     try testing.expect(result.stdout.len > 0);
    //     try testing.expect(result.stderr.len == 0);
    // }
}

test "forbidden city" {
    {
        const maybe_value: anyerror!usize = 5;
        try testing.expect(!_testIsError(
            usize,
            maybe_value,
            error.FileNotFound,
        ));
    }
}
