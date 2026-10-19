const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const linux = std.os.linux;

const OS_PAGE_SIZE = switch (builtin.os.tag) {
    .linux, .macos => std.heap.page_size_min,
    else => {
        @compileError("Only linux & macos supported.");
    },
};

const native_os = builtin.os.tag;
const uid_t = if (native_os == .windows or native_os == .wasi) void else std.posix.uid_t;

const MAX_OUTPUT = 8 * 1024 * 1024 * 1024;

pub const Term = union(enum) {
    exited: u8,
    signal: u32,
    stopped: u32,
    unknown: u32,

    pub fn fromStatus(status: u32) Term {
        return if (std.os.linux.W.IFEXITED(status))
            Term{ .exited = std.os.linux.W.EXITSTATUS(status) }
        else if (std.os.linux.W.IFSIGNALED(status))
            Term{ .signal = @intFromEnum(std.os.linux.W.TERMSIG(status)) }
        else if (std.os.linux.W.IFSTOPPED(status))
            unreachable
        else
            unreachable;
    }
};

pub const ZcmdError = error{
    FailedAssertSucceeded,

    StdoutStreamTooLong,

    OutOfMemory,
    UserNotFound,
    NameTooLong,
    WriteFailed,
    Unexpected,
    NetworkDown,
    FileNotFound,
} || RunFnError;

pub const RunResult = struct {
    const WHITE_SPACES = " \t\n\r";

    const AssertOptions = struct {
        check_stdout_not_empty: bool = false,
        check_stdout_not_empty_raw: bool = false,
        check_stderr_empty: bool = true,
        check_stderr_empty_raw: bool = false,
        print_cmd_term: bool = true,
        print_stdout: bool = true,
        print_stderr: bool = true,
        do_panic: bool = false,
    };

    allocator: std.mem.Allocator,

    args: ZcmdArgs,
    term: Term = undefined,
    stdout: ?[]const u8 = null,
    stderr: ?[]const u8 = undefined,

    pub fn deinit(this: *const RunResult) void {
        if (this.stdout) |stdout_slice| this.allocator.free(stdout_slice);
        if (this.stderr) |stderr_slice| this.allocator.free(stderr_slice);
    }

    pub fn assertSucceededPanic(this: *const RunResult, opts: AssertOptions) void {
        var _opts = opts;
        _opts.do_panic = true;
        this.assertSucceeded(_opts) catch {};
    }

    pub fn assertSucceeded(this: *const RunResult, opts: AssertOptions) !void {
        _ = try this._assertSucceededBool(opts);
    }

    fn _assertSucceededBool(this: *const RunResult, opts: AssertOptions) !bool {
        const failed: bool = brk: {
            switch (this.term) {
                .exited => |ret| if (ret != 0) break :brk true,
                else => break :brk true,
            }
            if (opts.check_stdout_not_empty_raw) {
                if (this.stdout == null) break :brk true;
                if (this.stdout.?.len == 0) break :brk true;
            }
            if (!opts.check_stdout_not_empty_raw and opts.check_stdout_not_empty) {
                if (this.stdout == null) break :brk true;
                if (this.stdout) |so| {
                    const trimed = std.mem.trim(u8, so, WHITE_SPACES);
                    if (trimed.len == 0) break :brk true;
                }
            }
            if (opts.check_stderr_empty_raw) {
                if (this.stderr) |se| if (se.len > 0) break :brk true;
            }
            if (!opts.check_stderr_empty_raw and opts.check_stderr_empty) {
                if (this.stderr) |se| {
                    const trimed = std.mem.trim(u8, se, WHITE_SPACES);
                    if (trimed.len > 0) break :brk true;
                }
            }
            break :brk false;
        };

        if (failed) {
            if (!builtin.is_test) {
                const stderr_fd = std.posix.STDERR_FILENO;
                if (opts.print_cmd_term) {
                    _ = linux.write(stderr_fd, ">> assert command execution succeeded failed!\n".ptr, 46);
                    _ = linux.write(stderr_fd, ">> Term: ".ptr, 9);
                    // Write term info
                    switch (this.term) {
                        .exited => |code| {
                            var buf: [32]u8 = undefined;
                            const s = std.fmt.bufPrint(&buf, "Exited({d})\n", .{code}) catch return true;
                            _ = linux.write(stderr_fd, s.ptr, s.len);
                        },
                        .signal => |sig| {
                            var buf: [32]u8 = undefined;
                            const s = std.fmt.bufPrint(&buf, "Signal({d})\n", .{sig}) catch return true;
                            _ = linux.write(stderr_fd, s.ptr, s.len);
                        },
                        .stopped => |sig| {
                            var buf: [32]u8 = undefined;
                            const s = std.fmt.bufPrint(&buf, "Stopped({d})\n", .{sig}) catch return true;
                            _ = linux.write(stderr_fd, s.ptr, s.len);
                        },
                        .unknown => |status| {
                            var buf: [32]u8 = undefined;
                            const s = std.fmt.bufPrint(&buf, "Unknown({d})\n", .{status}) catch return true;
                            _ = linux.write(stderr_fd, s.ptr, s.len);
                        },
                    }
                }
                if (opts.print_stdout) {
                    var buf: [128]u8 = undefined;
                    const len_str = if (this.stdout == null) "0" else "";
                    const header = std.fmt.bufPrint(&buf, ">> stdout({s}{d}bytes):\n", .{ len_str, if (this.stdout) |so| so.len else 0 }) catch return true;
                    _ = linux.write(stderr_fd, header.ptr, header.len);
                    if (this.stdout) |so| {
                        _ = linux.write(stderr_fd, so.ptr, so.len);
                        _ = linux.write(stderr_fd, "\n".ptr, 1);
                    } else {
                        _ = linux.write(stderr_fd, "(null)\n".ptr, 7);
                    }
                }
                if (opts.print_stderr) {
                    var buf: [128]u8 = undefined;
                    const len_str = if (this.stderr == null) "0" else "";
                    const header = std.fmt.bufPrint(&buf, ">> stderr({s}{d}bytes):\n", .{ len_str, if (this.stderr) |se| se.len else 0 }) catch return true;
                    _ = linux.write(stderr_fd, header.ptr, header.len);
                    if (this.stderr) |se| {
                        _ = linux.write(stderr_fd, se.ptr, se.len);
                        _ = linux.write(stderr_fd, "\n".ptr, 1);
                    } else {
                        _ = linux.write(stderr_fd, "(null)\n".ptr, 7);
                    }
                }
            }
            if (opts.do_panic) {
                @panic("assert command succeeded failed!");
            } else {
                return ZcmdError.FailedAssertSucceeded;
            }
        }

        return true;
    }

    pub fn trimedStdout(this: *const RunResult) []const u8 {
        return std.mem.trim(u8, this.stdout.?, WHITE_SPACES);
    }

    pub fn trimedStderr(this: *const RunResult) []const u8 {
        return std.mem.trim(u8, this.stderr.?, WHITE_SPACES);
    }
};

const Zcmd = @This();

pub const ZcmdArgs = struct {
    allocator: std.mem.Allocator,
    commands: []const []const []const u8,
    stdin_input: ?[]const u8 = null,
    user_name: ?[]const u8 = null,
    uid: ?uid_t = null,
    gid: ?uid_t = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.Io.Dir = null,
    env_map: ?*const std.process.Environ.Map = null,
    max_output_bytes: usize = MAX_OUTPUT,
};

/// provides an almost identical API like `std.process.run`, but with the ability of running pipeline like `bash`.
pub fn run(args: struct {
    allocator: std.mem.Allocator,
    commands: []const []const []const u8,
    stdin_input: ?[]const u8 = null,
    user_name: ?[]const u8 = null,
    uid: ?uid_t = null,
    gid: ?uid_t = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.Io.Dir = null,
    env_map: ?*const std.process.Environ.Map = null,
    max_output_bytes: usize = MAX_OUTPUT,
}) ZcmdError!RunResult {
    var has_stdin_pipe: bool = false;
    const stdin_pipe = brk: {
        if (args.stdin_input != null) {
            has_stdin_pipe = true;
            break :brk try linuxPipe2(.{});
        } else break :brk undefined;
    };
    const stdout_pipe = try linuxPipe2(.{});
    const stderr_pipe = try linuxPipe2(.{});
    const err_pipe = try linuxPipe2(.{});

    var _args: ZcmdArgs = ZcmdArgs{
        .allocator = args.allocator,
        .commands = args.commands,
        .stdin_input = args.stdin_input,
        .user_name = args.user_name,
        .uid = args.uid,
        .gid = args.gid,
        .cwd = args.cwd,
        .cwd_dir = args.cwd_dir,
        .env_map = args.env_map,
        .max_output_bytes = args.max_output_bytes,
    };

    if (args.user_name != null and args.uid != null and args.gid != null) {
        @panic("set either user_name or uid+gid, not the same time!");
    }
    if ((args.uid != null and args.gid == null) or (args.uid == null and args.gid != null)) {
        @panic("set uid and gid same time or leave both as null!");
    }
    if (args.user_name) |user_name| {
        const user_info = try getUserInfoSimple(args.allocator, user_name);
        _args.user_name = null;
        _args.uid = user_info.uid;
        _args.gid = user_info.gid;
    }

    if (args.cwd != null and args.cwd_dir != null) {
        @panic("set either cwd or cwd_dir, not the same time!");
    }
    if (args.cwd != null and !std.fs.path.isAbsolute(args.cwd.?)) {
        @panic("if set cwd, must be absolute path!");
    }

    const pid_result = try linuxFork();
    if (pid_result == 0) {
        // we are child
        _ = linux.close(err_pipe[0]);
        defer _ = linux.close(err_pipe[1]);

        if (has_stdin_pipe) {
            linuxDup2(stdin_pipe[0], std.posix.STDIN_FILENO) catch |err| forkChildErrReport(err_pipe[1], err);
        }
        linuxDup2(stdout_pipe[1], std.posix.STDOUT_FILENO) catch |err| forkChildErrReport(err_pipe[1], err);
        linuxDup2(stderr_pipe[1], std.posix.STDERR_FILENO) catch |err| forkChildErrReport(err_pipe[1], err);
        if (has_stdin_pipe) {
            _ = linux.close(stdin_pipe[0]);
            _ = linux.close(stdin_pipe[1]);
        }
        _ = linux.close(stdout_pipe[0]);
        _ = linux.close(stdout_pipe[1]);
        _ = linux.close(stderr_pipe[0]);
        _ = linux.close(stderr_pipe[1]);

        if (args.uid) |uid| {
            if (args.gid) |gid| {
                linuxSetGid(gid) catch |err| forkChildErrReport(err_pipe[1], err);
                linuxSetUid(uid) catch |err| forkChildErrReport(err_pipe[1], err);
            }
        }

        if (args.cwd_dir) |cwd_dir| {
            linuxFchdir(cwd_dir.handle) catch |err| forkChildErrReport(err_pipe[1], err);
        } else if (args.cwd) |cwd| {
            linuxChdir(cwd) catch |err| forkChildErrReport(err_pipe[1], err);
        }

        Zcmd._run(_args) catch |err| forkChildErrReport(err_pipe[1], err);
        linux.exit(0);
    } else {
        // we are parent
        errdefer {
            std.posix.kill(pid_result, std.posix.SIG.TERM) catch |err| switch (err) {
                error.ProcessNotFound => {},
                else => {
                    std.posix.kill(pid_result, std.posix.SIG.KILL) catch {};
                },
            };
        }

        if (has_stdin_pipe) {
            _ = linux.close(stdin_pipe[0]);
        }
        _ = linux.close(stdout_pipe[1]);
        _ = linux.close(stderr_pipe[1]);

        if (has_stdin_pipe) {
            try _feedStdinInput(stdin_pipe[1], args.stdin_input.?);
        }

        // Collect stdout and stderr using manual read loop with poll
        var stdout_array = std.array_list.AlignedManaged(u8, null).init(args.allocator);
        errdefer stdout_array.deinit();
        var stderr_array = std.array_list.AlignedManaged(u8, null).init(args.allocator);
        errdefer stderr_array.deinit();

        var fds: [2]std.posix.pollfd = undefined;
        fds[0] = .{ .fd = stdout_pipe[0], .events = @as(i16, @intCast(std.posix.POLL.IN)), .revents = 0 };
        fds[1] = .{ .fd = stderr_pipe[0], .events = @as(i16, @intCast(std.posix.POLL.IN)), .revents = 0 };

        var stdout_done = false;
        var stderr_done = false;

        while (!stdout_done or !stderr_done) {
            _ = try std.posix.poll(&fds, -1);

            if (!stdout_done and fds[0].revents & (@as(i16, @intCast(std.posix.POLL.IN | std.posix.POLL.HUP))) != 0) {
                var buf: [4096]u8 = undefined;
                const n = std.posix.read(stdout_pipe[0], &buf) catch break;
                if (n == 0) {
                    stdout_done = true;
                } else {
                    try stdout_array.appendSlice(buf[0..n]);
                    if (stdout_array.items.len > args.max_output_bytes)
                        return error.StdoutStreamTooLong;
                }
            }
            if (fds[0].revents & (@as(i16, @intCast(std.posix.POLL.ERR))) != 0) {
                stdout_done = true;
            }

            if (!stderr_done and fds[1].revents & (@as(i16, @intCast(std.posix.POLL.IN | std.posix.POLL.HUP))) != 0) {
                var buf: [4096]u8 = undefined;
                const n = std.posix.read(stderr_pipe[0], &buf) catch break;
                if (n == 0) {
                    stderr_done = true;
                } else {
                    try stderr_array.appendSlice(buf[0..n]);
                    if (stderr_array.items.len > args.max_output_bytes)
                        return error.StdoutStreamTooLong;
                }
            }
            if (fds[1].revents & (@as(i16, @intCast(std.posix.POLL.ERR))) != 0) {
                stderr_done = true;
            }

            // Check if both fds are closed (HUP with no data)
            if (stdout_done and stderr_done) break;
        }

        try writeIntFd(err_pipe[1], std.math.maxInt(ErrInt));
        const err_int = try readIntFd(err_pipe[0]);
        defer {
            _ = linux.close(err_pipe[0]);
            _ = linux.close(err_pipe[1]);
        }
        if (err_int != std.math.maxInt(ErrInt)) {
            return @as(ZcmdError, @errorCast(@errorFromInt(err_int)));
        }

        const result = try linuxWaitpid(pid_result, 0);
        return RunResult{
            .allocator = args.allocator,
            .args = _args,
            .term = Term.fromStatus(result.status),
            .stdout = try stdout_array.toOwnedSlice(),
            .stderr = try stderr_array.toOwnedSlice(),
        };
    }
}

/// a version of using `std.heap.page_allocator`, so no worry about bringing your allocator, just remember to
/// `defer result.deinit()`
pub fn runSelfManaged(args: struct {
    commands: []const []const []const u8,
    stdin_input: ?[]const u8 = null,
    user_name: ?[]const u8 = null,
    uid: ?uid_t = null,
    gid: ?uid_t = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.Io.Dir = null,
    env_map: ?*const std.process.Environ.Map = null,
    max_output_bytes: usize = MAX_OUTPUT,
}) anyerror!RunResult {
    return run(.{
        .allocator = std.heap.page_allocator,
        .commands = args.commands,
        .stdin_input = args.stdin_input,
        .user_name = args.user_name,
        .uid = args.uid,
        .gid = args.gid,
        .cwd = args.cwd,
        .cwd_dir = args.cwd_dir,
        .env_map = args.env_map,
        .max_output_bytes = args.max_output_bytes,
    });
}

/// provide runSingle with same args to `std.process.run`. It is a thin wrapper to `run`.
pub fn runSingle(args: struct {
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.Io.Dir = null,
    env_map: ?*const std.process.Environ.Map = null,
    max_output_bytes: usize = 50 * 1024,
}) ZcmdError!RunResult {
    return run(.{
        .allocator = args.allocator,
        .commands = &[_][]const []const u8{args.argv},
        .cwd = args.cwd,
        .cwd_dir = args.cwd_dir,
        .env_map = args.env_map,
        .max_output_bytes = args.max_output_bytes,
    });
}

fn _feedStdinInput(fd: linux.fd_t, stdin_input: []const u8) !void {
    const batch_size = OS_PAGE_SIZE;
    var offset: usize = 0;
    var wrote_size: usize = 0;

    var fds: [1]std.posix.pollfd = undefined;
    fds[0].fd = fd;
    fds[0].events = @as(i16, @intCast(std.posix.POLL.OUT));

    var poll_ready_count: usize = 0;

    while (offset < stdin_input.len) {
        poll_ready_count = try std.posix.poll(&fds, -1);
        if (poll_ready_count == 0) {
            continue;
        } else {
            if (fds[0].revents & (@as(i16, @intCast(std.posix.POLL.OUT))) != 0) {
                if (offset + batch_size < stdin_input.len) {
                    wrote_size = linux.write(fd, stdin_input[offset .. offset + batch_size].ptr, batch_size);
                } else {
                    wrote_size = linux.write(fd, stdin_input[offset..].ptr, stdin_input.len - offset);
                }
                if (wrote_size == 0 or wrote_size > stdin_input.len - offset) {
                    return error.WriteFailed;
                }
                offset += wrote_size;
            } else {
                continue;
            }
        }
    }

    _ = linux.close(fd);
}

fn _run(args: ZcmdArgs) !void {
    for (args.commands, 0..) |next_command, i| {
        var pipe = try linuxPipe2(.{});
        const pid_result = try linuxFork();
        if (pid_result == 0) {
            // we are child
            if (i + 1 == args.commands.len) {
                _ = linux.close(pipe[0]);
                _ = linux.close(pipe[1]);
                linux.exit(0);
            }
            linuxDup2(pipe[0], std.posix.STDIN_FILENO) catch return error.ExecFailed;
            _ = linux.close(pipe[0]);
            _ = linux.close(pipe[1]);
            pipe = try linuxPipe2(.{});
        } else {
            // we are parent
            if (i + 1 != args.commands.len) {
                linuxDup2(pipe[1], std.posix.STDOUT_FILENO) catch return error.ExecFailed;
            }
            _ = linux.close(pipe[0]);
            _ = linux.close(pipe[1]);

            Zcmd.executeCommand(
                args.allocator,
                next_command,
                args.env_map,
            ) catch |err| {
                // Write error to stderr using low-level write
                _ = linux.write(std.posix.STDERR_FILENO, "zig: ".ptr, 5);
                var err_buf: [64]u8 = undefined;
                const err_str = std.fmt.bufPrint(&err_buf, "{any}", .{err}) catch "?";
                _ = linux.write(std.posix.STDERR_FILENO, err_str.ptr, err_str.len);
                _ = linux.write(std.posix.STDERR_FILENO, ": ".ptr, 2);
                // Write command representation
                _ = linux.write(std.posix.STDERR_FILENO, "{ ".ptr, 2);
                for (next_command, 0..) |arg, j| {
                    if (j > 0) _ = linux.write(std.posix.STDERR_FILENO, ", ".ptr, 2);
                    _ = linux.write(std.posix.STDERR_FILENO, arg.ptr, arg.len);
                }
                _ = linux.write(std.posix.STDERR_FILENO, "}\n".ptr, 2);
                linux.exit(1);
            };
        }
    }
}

fn executeCommand(
    allocator: std.mem.Allocator,
    command: []const []const u8,
    env_map: ?*const std.process.Environ.Map,
) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const argv_buf = try arena.allocSentinel(?[*:0]const u8, command.len, null);
    for (command, 0..) |arg, i| {
        const duped = try arena.dupeSentinel(u8, arg, 0);
        argv_buf[i] = duped.ptr;
    }

    const envp: [*:null]const ?[*:0]const u8 = if (env_map) |em| blk: {
        const envp_buf = try createNullDelimitedEnvMap(arena, em);
        break :blk envp_buf.ptr;
    } else blk: {
        // When no env_map is provided, pass an empty null-terminated array
        break :blk &[_:null]?[*:0]const u8{};
    };

    // Use execve directly with PATH resolution
    // First, check if the command has a slash (absolute or relative path)
    const cmd_name_z = argv_buf.ptr[0].?;
    const cmd_name = std.mem.span(cmd_name_z);
    const has_slash = for (cmd_name) |c| {
        if (c == '/') break true;
    } else false;

    if (has_slash) {
        // Direct execve with the provided path
        _ = linux.execve(cmd_name, argv_buf.ptr, envp);
        return error.ExecFailed;
    }

    // Need to search PATH
    const path_env = blk: {
        if (env_map) |em| {
            break :blk em.get("PATH") orelse "/usr/local/bin:/usr/bin:/bin";
        } else {
            // Default PATH
            break :blk "/usr/local/bin:/usr/bin:/bin";
        }
    };

    var path_iter = std.mem.splitScalar(u8, path_env, ':');
    while (path_iter.next()) |dir| {
        var path_buf: [4096]u8 = undefined;
        const full_path = std.fmt.bufPrintSentinel(&path_buf, "{s}/{s}", .{ dir, cmd_name }, 0) catch continue;
        const result = linux.execve(full_path.ptr, argv_buf.ptr, envp);
        // If execve failed, check errno
        const err = linux.errno(result);
        if (err != .NOENT) {
            return error.ExecFailed;
        }
    }
    return error.ExecFailed;
}

// Thin wrappers around std.os.linux syscalls that return proper error unions

fn linuxPipe2(flags: std.os.linux.O) ![2]linux.fd_t {
    var fds: [2]linux.fd_t = undefined;
    const result = linux.pipe2(&fds, flags);
    if (result != 0) {
        return error.SystemResources;
    }
    return fds;
}

fn linuxFork() !linux.pid_t {
    const result = linux.fork();
    if (result > @as(usize, @intCast(@as(isize, @intCast(std.math.maxInt(isize))))) - 4096) {
        return error.ForkFailed;
    }
    return @intCast(result);
}

fn linuxDup2(old: linux.fd_t, new: linux.fd_t) !void {
    const result = linux.dup2(old, new);
    if (result > @as(usize, @intCast(@as(isize, @intCast(std.math.maxInt(isize))))) - 4096) {
        return error.Dup2Failed;
    }
}

fn linuxSetGid(gid: linux.gid_t) !void {
    const result = linux.setgid(gid);
    if (result != 0) {
        return error.SetGidFailed;
    }
}

fn linuxSetUid(uid: linux.uid_t) !void {
    const result = linux.setuid(uid);
    if (result != 0) {
        return error.SetUidFailed;
    }
}

fn linuxChdir(path: []const u8) !void {
    const pathZ = try std.posix.toPosixPath(path);
    const result = linux.chdir(&pathZ);
    if (result != 0) {
        return error.ChdirFailed;
    }
}

fn linuxFchdir(fd: linux.fd_t) !void {
    const result = linux.fchdir(fd);
    if (result != 0) {
        return error.FchdirFailed;
    }
}

const WaitResult = struct {
    pid: linux.pid_t,
    status: u32,
};

fn linuxWaitpid(pid: linux.pid_t, flags: u32) !WaitResult {
    var status: i32 = undefined;
    const result = linux.waitpid(pid, &status, flags);
    if (linux.errno(result) != .SUCCESS) {
        return error.WaitFailed;
    }
    return .{ .pid = @intCast(result), .status = @bitCast(status) };
}

// util functions needed for child process

const ErrInt = @Int(.unsigned, @sizeOf(anyerror) * 8);

fn writeIntFd(fd: linux.fd_t, value: ErrInt) !void {
    const bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, @intCast(value)));
    var written: usize = 0;
    while (written < bytes.len) {
        const n = linux.write(fd, bytes[written..].ptr, bytes.len - written);
        if (n == 0 or n > bytes.len) return error.SystemResources;
        written += n;
    }
}

fn readIntFd(fd: linux.fd_t) !ErrInt {
    var bytes: [@sizeOf(u64)]u8 = undefined;
    var read_total: usize = 0;
    while (read_total < bytes.len) {
        const n = std.posix.read(fd, bytes[read_total..]) catch return error.SystemResources;
        if (n == 0) return error.SystemResources;
        read_total += n;
    }
    return @as(ErrInt, @intCast(std.mem.littleToNative(u64, std.mem.bytesAsValue(u64, &bytes).*)));
}

// Child of fork calls this to report an error to the fork parent.
// Then the child exits.
fn forkChildErrReport(fd: linux.fd_t, err: ZcmdError) noreturn {
    writeIntFd(fd, @as(ErrInt, @intFromError(err))) catch {};
    if (builtin.link_libc) {
        std.c._exit(1);
    }
    linux.exit(1);
}

const UserInfoSimple = struct {
    uid: std.posix.uid_t,
    gid: std.posix.gid_t,
};

/// Simple user info lookup using getent command (works on most Linux systems)
fn getUserInfoSimple(allocator: std.mem.Allocator, name: []const u8) !UserInfoSimple {
    // Use 'id' command to get uid and gid for a user
    var argv_buf: [3][]const u8 = undefined;
    argv_buf[0] = "id";
    argv_buf[1] = "-u";
    argv_buf[2] = name;

    // Execute 'id -u <name>' to get uid
    const uid_result = try runSingle(.{
        .allocator = allocator,
        .argv = &argv_buf,
    });
    defer uid_result.deinit();

    if (uid_result.term.exited != 0) return error.UserNotFound;
    const uid_str = std.mem.trim(u8, uid_result.stdout.?, " \t\n\r");
    const uid = std.fmt.parseInt(std.posix.uid_t, uid_str, 10) catch return error.UserNotFound;

    // Execute 'id -g <name>' to get gid
    argv_buf[1] = "-g";
    const gid_result = try runSingle(.{
        .allocator = allocator,
        .argv = &argv_buf,
    });
    defer gid_result.deinit();

    if (gid_result.term.exited != 0) return error.UserNotFound;
    const gid_str = std.mem.trim(u8, gid_result.stdout.?, " \t\n\r");
    const gid = std.fmt.parseInt(std.posix.gid_t, gid_str, 10) catch return error.UserNotFound;

    return UserInfoSimple{ .uid = uid, .gid = gid };
}

fn createNullDelimitedEnvMap(arena: std.mem.Allocator, env_map: *const std.process.Environ.Map) ![:null]?[*:0]u8 {
    const envp_count = env_map.count();
    const envp_buf = try arena.allocSentinel(?[*:0]u8, envp_count, null);
    {
        var it = env_map.iterator();
        var i: usize = 0;
        while (it.next()) |pair| : (i += 1) {
            const env_buf = try arena.allocSentinel(u8, pair.key_ptr.len + pair.value_ptr.len + 1, 0);
            @memcpy(env_buf[0..pair.key_ptr.len], pair.key_ptr.*);
            env_buf[pair.key_ptr.len] = '=';
            @memcpy(env_buf[pair.key_ptr.len + 1 ..][0..pair.value_ptr.len], pair.value_ptr.*);
            envp_buf[i] = env_buf.ptr;
        }
        std.debug.assert(i == envp_count);
    }
    return envp_buf;
}

pub const RunFnError = error{
    OOM,
    IOError,
    ParamsInValid,
    InternalError,
    ExecFailed,
    ForkFailed,
    Dup2Failed,
    SetGidFailed,
    SetUidFailed,
    ChdirFailed,
    FchdirFailed,
    WaitFailed,
    SystemResources,
};

pub fn forkAndRun(
    arena: std.mem.Allocator,
    comptime PayloadType: type,
    runFn: *const fn (payload: PayloadType) RunFnError!void,
    payload: PayloadType,
) !RunResult {
    const stdout_pipe = try linuxPipe2(.{});
    const stderr_pipe = try linuxPipe2(.{});
    const err_pipe = try linuxPipe2(.{});
    const pid_result = try linuxFork();

    if (pid_result == 0) {
        // we are child
        _ = linux.close(err_pipe[0]);
        defer _ = linux.close(err_pipe[1]);

        linuxDup2(stdout_pipe[1], std.posix.STDOUT_FILENO) catch |err| forkChildErrReport(err_pipe[1], err);
        linuxDup2(stderr_pipe[1], std.posix.STDERR_FILENO) catch |err| forkChildErrReport(err_pipe[1], err);
        _ = linux.close(stdout_pipe[0]);
        _ = linux.close(stdout_pipe[1]);
        _ = linux.close(stderr_pipe[0]);
        _ = linux.close(stderr_pipe[1]);

        runFn(payload) catch |err| {
            forkChildErrReport(err_pipe[1], err);
            linux.exit(1);
        };

        linux.exit(0);
    }

    // we are parent
    _ = linux.close(stdout_pipe[1]);
    _ = linux.close(stderr_pipe[1]);

    const max_output_bytes = 8 * 1024 * 1024 * 1024;

    // Collect stdout and stderr using manual read loop with poll
    var stdout_array = std.array_list.AlignedManaged(u8, null).init(arena);
    errdefer stdout_array.deinit();
    var stderr_array = std.array_list.AlignedManaged(u8, null).init(arena);
    errdefer stderr_array.deinit();

    var fds: [2]std.posix.pollfd = undefined;
    fds[0] = .{ .fd = stdout_pipe[0], .events = @as(i16, @intCast(std.posix.POLL.IN)), .revents = 0 };
    fds[1] = .{ .fd = stderr_pipe[0], .events = @as(i16, @intCast(std.posix.POLL.IN)), .revents = 0 };

    var stdout_done = false;
    var stderr_done = false;

    while (!stdout_done or !stderr_done) {
        _ = try std.posix.poll(&fds, -1);

        if (!stdout_done and fds[0].revents & (@as(i16, @intCast(std.posix.POLL.IN | std.posix.POLL.HUP))) != 0) {
            var buf: [4096]u8 = undefined;
            const n = std.posix.read(stdout_pipe[0], &buf) catch break;
            if (n == 0) {
                stdout_done = true;
            } else {
                try stdout_array.appendSlice(buf[0..n]);
                if (stdout_array.items.len > max_output_bytes)
                    return error.StdoutStreamTooLong;
            }
        }
        if (fds[0].revents & (@as(i16, @intCast(std.posix.POLL.ERR))) != 0) {
            stdout_done = true;
        }

        if (!stderr_done and fds[1].revents & (@as(i16, @intCast(std.posix.POLL.IN | std.posix.POLL.HUP))) != 0) {
            var buf: [4096]u8 = undefined;
            const n = std.posix.read(stderr_pipe[0], &buf) catch break;
            if (n == 0) {
                stderr_done = true;
            } else {
                try stderr_array.appendSlice(buf[0..n]);
                if (stderr_array.items.len > max_output_bytes)
                    return error.StdoutStreamTooLong;
            }
        }
        if (fds[1].revents & (@as(i16, @intCast(std.posix.POLL.ERR))) != 0) {
            stderr_done = true;
        }

        if (stdout_done and stderr_done) break;
    }

    try writeIntFd(err_pipe[1], std.math.maxInt(ErrInt));
    const err_int = try readIntFd(err_pipe[0]);
    defer {
        _ = linux.close(err_pipe[0]);
        _ = linux.close(err_pipe[1]);
    }
    if (err_int != std.math.maxInt(ErrInt)) {
        return @as(ZcmdError, @errorCast(@errorFromInt(err_int)));
    }

    const result = try linuxWaitpid(pid_result, 0);
    return RunResult{
        .allocator = arena,
        .args = .{ .allocator = arena, .commands = &[_][]const []const u8{&[_][]const u8{@typeName(PayloadType)}} },
        .term = Term.fromStatus(result.status),
        .stdout = try stdout_array.toOwnedSlice(),
        .stderr = try stderr_array.toOwnedSlice(),
    };
}

// internals and tests

fn _testIsError(comptime T: type, maybe_value: anyerror!T, expected_error: anyerror) bool {
    if (maybe_value) |_| {
        return false;
    } else |err| {
        return err == expected_error;
    }
}

fn _extractNumbers(comptime NumberType: type, input: []const u8, dest: []NumberType) !void {
    var it = std.mem.tokenizeAny(u8, input, &std.ascii.whitespace);
    var count: usize = 0;
    while (it.next()) |s| {
        if (count >= dest.len) {
            return error.OutOfCapacity;
        }
        if (s.len == 0)
            continue;
        dest[count] = try std.fmt.parseInt(NumberType, s, 10);
        count += 1;
    }
}

test "normal cases" {
    const allocator = std.testing.allocator;
    {
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "uname", "-a" },
            },
        });
        defer result.deinit();
        try testing.expectEqual(result.term.exited, 0);
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
        var rbuf: [2]usize = undefined;
        try _extractNumbers(usize, result.stdout.?, rbuf[0..]);
        try testing.expectEqualDeep(rbuf, [2]usize{ 1302, 2604 });
    }
    {
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "find", ".", "-type", "f", "-exec", "stat", "-f", "'%m %N'", "{}", ";" },
                &.{ "sort", "-nr" },
                &.{ "head", "-1" },
            },
        });
        defer result.deinit();
        try testing.expect(result.stdout.?.len > 0);
    }
    {
        // Read test file using cat command
        const cat_result = try Zcmd.runSingle(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "cat", "./tests/big_input.txt" },
            .max_output_bytes = MAX_OUTPUT,
        });
        defer cat_result.deinit();
        try testing.expect(cat_result.term.exited == 0);
        const content = cat_result.stdout.?;
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{"cat"},
                &.{ "wc", "-lw" },
            },
            .stdin_input = content,
        });
        defer result.deinit();
        var rbuf: [2]usize = undefined;
        try _extractNumbers(usize, result.stdout.?, rbuf[0..]);
        try testing.expectEqualDeep(rbuf, [2]usize{ 1302, 2604 });
    }
    {
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "cat", "./tests/big_input.txt" },
                &.{ "wc", "-lw" },
            },
            .user_name = "root",
        });
        defer result.deinit();
        var rbuf: [2]usize = undefined;
        try _extractNumbers(usize, result.stdout.?, rbuf[0..]);
        try testing.expectEqualDeep(rbuf, [2]usize{ 1302, 2604 });
    }
    {
        // Test using cwd - use pwd command to get current directory
        const pwd_result = try Zcmd.runSingle(.{
            .allocator = allocator,
            .argv = &[_][]const u8{"pwd"},
        });
        defer pwd_result.deinit();
        const abs_path = std.mem.trim(u8, pwd_result.stdout.?, " \t\n\r");
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "cat", "./tests/big_input.txt" },
                &.{ "wc", "-lw" },
            },
            .cwd = abs_path,
        });
        defer result.deinit();
        var rbuf: [2]usize = undefined;
        try _extractNumbers(usize, result.stdout.?, rbuf[0..]);
        try testing.expectEqualDeep(rbuf, [2]usize{ 1302, 2604 });
    }
    {
        var envmap = std.process.Environ.Map.init(allocator);
        defer envmap.deinit();
        try envmap.put("ZCMD_TEST_ENV1", "hello");
        const result = try Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{"printenv"},
                &.{ "grep", "ZCMD_TEST_ENV1" },
            },
            .env_map = &envmap,
        });
        defer result.deinit();
        try testing.expectEqualSlices(
            u8,
            result.stdout.?,
            "ZCMD_TEST_ENV1=hello\n",
        );
    }
    {
        const result = try Zcmd.runSingle(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "uname", "-a" },
        });
        defer result.deinit();
        try testing.expectEqual(result.term.exited, 0);
        try testing.expect(result.stdout.?.len > 0);
    }
    {
        const result = try Zcmd.runSelfManaged(.{
            .commands = &[_][]const []const u8{
                &.{ "cat", "./tests/big_input.txt" },
                &.{ "wc", "-lw" },
            },
        });
        defer result.deinit();
        var rbuf: [2]usize = undefined;
        try _extractNumbers(usize, result.stdout.?, rbuf[0..]);
        try testing.expectEqualDeep(rbuf, [2]usize{ 1302, 2604 });
    }
}

test "all failures" {
    const allocator = std.testing.allocator;
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
        var rbuf: [2]usize = undefined;
        try _extractNumbers(usize, result.stdout.?, rbuf[0..]);
        try testing.expectEqualDeep(rbuf, [2]usize{ 0, 0 });
        try testing.expectEqualSlices(
            u8,
            result.stderr.?,
            "zig: error.ExecFailed: { sort-of, -nr}\n",
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
        var rbuf: [2]usize = undefined;
        try _extractNumbers(usize, result.stdout.?, rbuf[0..]);
        try testing.expectEqualDeep(rbuf, [2]usize{ 0, 0 });
        try testing.expectEqualSlices(
            u8,
            result.stderr.?,
            "zig: error.ExecFailed: { nonexist}\n",
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
        var rbuf: [2]usize = undefined;
        try _extractNumbers(usize, result.stdout.?, rbuf[0..]);
        try testing.expectEqualDeep(rbuf, [2]usize{ 0, 0 });
        switch (builtin.os.tag) {
            .linux => {
                try testing.expectEqualSlices(
                    u8,
                    result.stderr.?,
                    "find: 'nonexist': No such file or directory\n",
                );
            },
            .macos => {
                try testing.expectEqualSlices(
                    u8,
                    result.stderr.?,
                    "find: nonexist: No such file or directory\n",
                );
            },
            else => {},
        }
    }
    {
        const maybe_result = Zcmd.run(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "cat", "./tests/big_input.txt" },
            },
            .max_output_bytes = 1_000,
        });
        try testing.expect(_testIsError(RunResult, maybe_result, error.StdoutStreamTooLong));
    }
}

test "RunResult" {
    const allocator = testing.allocator;
    {
        const result = try Zcmd.runSingle(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "uname", "-a" },
        });
        defer result.deinit();
        try result.assertSucceeded(.{});
        try result.assertSucceeded(.{ .check_stderr_empty = true });
    }
    {
        const result = try Zcmd.runSingle(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "echo", "-n" },
        });
        defer result.deinit();
        try testing.expect(_testIsError(bool, result._assertSucceededBool(.{ .check_stdout_not_empty = true }), ZcmdError.FailedAssertSucceeded));
    }
    {
        const result = try Zcmd.runSingle(.{
            .allocator = allocator,
            .argv = &[_][]const u8{"echo"},
        });
        defer result.deinit();
        try result.assertSucceeded(.{ .check_stdout_not_empty_raw = true });
    }
    {
        const result = try Zcmd.runSingle(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "echo", "-n", "hello" },
        });
        defer result.deinit();
        try result.assertSucceeded(.{ .check_stderr_empty_raw = true });
    }
    {
        const result = try Zcmd.runSingle(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "find", "nonexist" },
        });
        defer result.deinit();
        try testing.expect(_testIsError(bool, result._assertSucceededBool(.{ .check_stderr_empty_raw = true }), ZcmdError.FailedAssertSucceeded));
    }
    {
        const result = try Zcmd.runSingle(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "bash", "tests/witherr_exit_zero.sh" },
        });
        defer result.deinit();
        try testing.expect(_testIsError(bool, result._assertSucceededBool(.{ .check_stderr_empty_raw = true }), ZcmdError.FailedAssertSucceeded));
    }
}

const TestPayload = struct {
    hello: []const u8,
};

fn _testForkAndRun(payload: TestPayload) RunFnError!void {
    const bytes = payload.hello;
    var written: usize = 0;
    while (written < bytes.len) {
        const n = linux.write(std.posix.STDOUT_FILENO, bytes[written..].ptr, bytes.len - written);
        if (n == 0 or n > bytes.len) return RunFnError.IOError;
        written += n;
    }
}

test "forkAndRun" {
    var aa = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer aa.deinit();
    const arena = aa.allocator();

    const result = try forkAndRun(arena, TestPayload, _testForkAndRun, .{ .hello = "world" });
    defer result.deinit();
    try result.assertSucceeded(.{});
    try testing.expectEqualSlices(u8, result.stdout.?, "world");
}
