const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const OS_PAGE_SIZE = switch (builtin.os.tag) {
    .linux, .macos, .windows => std.mem.page_size,
    else => {
        // this is also our os_selector for implementation :)
        @compileError("Only linux & macos supported.");
    },
};

const MAX_OUTPUT = 8 * 1024 * 1024 * 1024;

pub const Term = union(enum) {
    Exited: u8,
    Signal: u32,
    Stopped: u32,
    Unknown: u32,

    pub fn fromStatus(status: u32) Term {
        return if (std.os.W.IFEXITED(status))
            Term{ .Exited = std.os.W.EXITSTATUS(status) }
        else if (std.os.W.IFSIGNALED(status))
            Term{ .Signal = std.os.W.TERMSIG(status) }
        else if (std.os.W.IFSTOPPED(status))
            // Term{ .Stopped = std.os.W.STOPSIG(status) }
            unreachable
        else
            // Term{ .Unknown = status };
            unreachable;
    }
};

pub const ZcmdError = error{
    FailedAssertSucceeded,

    StdoutStreamTooLong,

    OutOfMemory,
    CorruptPasswordFile,
    UserNotFound,
} || RunFnError ||
    std.fs.File.OpenError ||
    std.fs.File.WriteError ||
    std.os.AccessError ||
    std.os.ChangeCurDirError ||
    std.os.ExecveError ||
    std.os.PipeError ||
    std.os.ReadError ||
    std.os.SetIdError ||
    std.os.ShutdownError ||
    std.os.windows.CreateProcessError ||
    std.posix.windows.WaitForSingleObjectError;

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
                .Exited => |ret| if (ret != 0) break :brk true,
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
                const stderr_writer = std.io.getStdErr().writer();
                if (opts.print_cmd_term) {
                    try stderr_writer.print(">> assert command `{s}` exeuction succeeded failed!\n", .{this.args.commands});
                    try stderr_writer.print(">> Term: {any}\n", .{this.term});
                }
                if (opts.print_stdout) {
                    try stderr_writer.print(">> stdout({d}bytes):\n{?s}\n", .{
                        if (this.stdout == null) 0 else this.stdout.?.len,
                        this.stdout,
                    });
                }
                if (opts.print_stderr) {
                    try stderr_writer.print(">> stderr({d}bytes):\n{?s}\n", .{
                        if (this.stderr == null) 0 else this.stderr.?.len,
                        this.stderr,
                    });
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
    uid: if (builtin.os.tag == .windows) ?void else ?std.os.uid_t = null,
    gid: if (builtin.os.tag == .windows) ?void else ?std.os.uid_t = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = MAX_OUTPUT,
    expand_arg0: std.ChildProcess.Arg0Expand = .no_expand,
};

/// provides an almost identical API like `std.childProcess.run`, but with the ability of running pipeline like `bash`.
/// Example like execution of single command (replacement of zig's `std.childProcess.run`)
///
/// ```zig
/// const result = try Zcmd.run(.{
///     .allocator = allocator,
///     .commands = &[_][]const []const u8{
///         &.{ "uname", "-a" },
///     },
/// });
/// ```
///
/// the differences to `std.childProcess.run` is it will take `commands` instead of single `command`.
///
/// It can run a `bash` like pipeline like follows (_to recursively find and list the latest modified files in a
/// directory with subdirectories and times_)
///
/// ```zig
/// const result = try Zcmd.run(.{
///     .allocator = allocator,
///     .commands = &[_][]const []const u8{
///         &.{ "find", ".", "-type", "f", "-exec", "stat", "-f", "'%m %N'", "{}", ";" },
///         &.{ "sort", "-nr" },
///         &.{ "head", "-1" },
///     },
/// });
/// ```
///
/// It can also accept an input from outside as stdin to command or command pipeline, like follows
///
/// ```zig
/// const f = try std.fs.cwd().openFile("tests/big_input.txt", .{});
/// defer f.close();
/// const content = try f.readToEndAlloc(allocator, MAX_OUTPUT);
/// defer allocator.free(content);
/// const result = try Zcmd.run(.{
///     .allocator = allocator,
///     .commands = &[_][]const []const u8{
///         &.{"cat"},
///         &.{ "wc", "-lw" },
///     },
///     .stdin_input = content,
/// });
/// ```
pub fn run(args: struct {
    allocator: std.mem.Allocator,
    commands: []const []const []const u8,
    stdin_input: ?[]const u8 = null,
    user_name: ?[]const u8 = null,
    uid: if (builtin.os.tag == .windows) ?void else ?std.os.uid_t = null,
    gid: if (builtin.os.tag == .windows) ?void else ?std.os.uid_t = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = MAX_OUTPUT,
    expand_arg0: std.ChildProcess.Arg0Expand = .no_expand,
}) ZcmdError!RunResult {
    switch (builtin.os.tag) {
        .linux, .macos => return runPosix(.{
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
            .expand_arg0 = args.expand_arg0,
        }),
        .windows => return runWindows(.{
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
            .expand_arg0 = args.expand_arg0,
        }),
        else => {
            @compileError("Only linux/macos/windows supported.");
        },
    }
}

fn runPosix(args: struct {
    allocator: std.mem.Allocator,
    commands: []const []const []const u8,
    stdin_input: ?[]const u8 = null,
    user_name: ?[]const u8 = null,
    uid: if (builtin.os.tag == .windows) ?void else ?std.os.uid_t = null,
    gid: if (builtin.os.tag == .windows) ?void else ?std.os.uid_t = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = MAX_OUTPUT,
    expand_arg0: std.ChildProcess.Arg0Expand = .no_expand,
}) ZcmdError!RunResult {
    const pipe_flags = .{};
    var has_stdin_pipe: bool = false;
    const stdin_pipe = brk: {
        if (args.stdin_input != null) {
            has_stdin_pipe = true;
            break :brk try std.os.pipe2(pipe_flags);
        } else break :brk undefined;
    };
    const stdout_pipe = try std.os.pipe2(pipe_flags);
    const stderr_pipe = try std.os.pipe2(pipe_flags);
    const err_pipe = try std.os.pipe2(pipe_flags);

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
        .expand_arg0 = args.expand_arg0,
    };

    if (args.user_name != null and args.uid != null and args.gid != null) {
        @panic("set either user_name or uid+gid, not the same time!");
    }
    if ((args.uid != null and args.gid == null) or (args.uid == null and args.gid != null)) {
        @panic("set uid and gid same time or leave both as null!");
    }
    if (args.user_name) |user_name| {
        const user_info = try std.process.getUserInfo(user_name);
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

    const pid_result = try std.os.fork();
    if (pid_result == 0) {
        // we are child
        // our wrapper to pipeline, setup all necessary cwd,uid,gid,stdin,stdout,stderr,err here so that we can get
        // result in main process
        std.os.close(err_pipe[0]);
        defer std.os.close(err_pipe[1]);

        if (has_stdin_pipe) {
            std.os.dup2(stdin_pipe[0], std.os.STDIN_FILENO) catch |err| forkChildErrReport(err_pipe[1], err);
        }
        std.os.dup2(stdout_pipe[1], std.os.STDOUT_FILENO) catch |err| forkChildErrReport(err_pipe[1], err);
        std.os.dup2(stderr_pipe[1], std.os.STDERR_FILENO) catch |err| forkChildErrReport(err_pipe[1], err);
        if (has_stdin_pipe) {
            std.os.close(stdin_pipe[0]);
            std.os.close(stdin_pipe[1]);
        }
        std.os.close(stdout_pipe[0]);
        std.os.close(stdout_pipe[1]);
        std.os.close(stderr_pipe[0]);
        std.os.close(stderr_pipe[1]);

        if (args.uid) |uid| {
            if (args.gid) |gid| {
                std.os.setregid(gid, gid) catch |err| forkChildErrReport(err_pipe[1], err);
                std.os.setreuid(uid, uid) catch |err| forkChildErrReport(err_pipe[1], err);
            }
        }

        if (args.cwd_dir) |cwd_dir| {
            std.os.fchdir(cwd_dir.fd) catch |err| forkChildErrReport(err_pipe[1], err);
        } else if (args.cwd) |cwd| {
            std.os.chdir(cwd) catch |err| forkChildErrReport(err_pipe[1], err);
        }

        Zcmd.runPipelinePosix(_args) catch |err| forkChildErrReport(err_pipe[1], err);
        std.os.exit(0);
    } else {
        // we are parent
        // listen to forked child (pipeline), get its stdout,stderr,err incase there is problem
        // feed stdin_input if there is

        errdefer {
            // make sure that we terminate pipeline process if return from error
            std.os.kill(pid_result, std.os.SIG.TERM) catch |err| switch (err) {
                // if already gone, let it be
                error.ProcessNotFound => {},
                else => {
                    // otherwise Cool Guys Don't Look At Explosions
                    std.os.kill(pid_result, std.os.SIG.KILL) catch {};
                },
            };
        }

        if (has_stdin_pipe) {
            std.os.close(stdin_pipe[0]);
        }
        std.os.close(stdout_pipe[1]);
        std.os.close(stderr_pipe[1]);

        if (has_stdin_pipe) {
            try feedStdinInputPosix(stdin_pipe[1], args.stdin_input.?);
        }

        var poller = std.io.poll(args.allocator, enum { stdout, stderr }, .{
            .stdout = std.fs.File{ .handle = stdout_pipe[0] },
            .stderr = std.fs.File{ .handle = stderr_pipe[0] },
        });
        defer poller.deinit();
        while (try poller.poll()) {
            if (poller.fifo(.stdout).count > args.max_output_bytes)
                return error.StdoutStreamTooLong;
            if (poller.fifo(.stderr).count > args.max_output_bytes)
                return error.StdoutStreamTooLong;
        }
        var stdout_array = fifoToOwnedArrayList(poller.fifo(.stdout));
        var stderr_array = fifoToOwnedArrayList(poller.fifo(.stderr));

        try writeIntFdPosix(err_pipe[1], std.math.maxInt(ErrInt));
        const err_int = try readIntFdPosix(err_pipe[0]);
        defer {
            std.os.close(err_pipe[0]);
            std.os.close(err_pipe[1]);
        }
        if (err_int != std.math.maxInt(ErrInt)) {
            return @as(ZcmdError, @errorCast(@errorFromInt(err_int)));
        }

        const result = std.os.waitpid(pid_result, 0);
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
    uid: if (builtin.os.tag == .windows) ?void else ?std.os.uid_t = null,
    gid: if (builtin.os.tag == .windows) ?void else ?std.os.uid_t = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = MAX_OUTPUT,
    expand_arg0: std.ChildProcess.Arg0Expand = .no_expand,
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
        .expand_arg0 = args.expand_arg0,
    });
}

/// provide runSingle with same args to `std.ChildProcess.run`. It is a thin wrapper to `run`.
pub fn runSingle(args: struct {
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = 50 * 1024,
    expand_arg0: std.ChildProcess.Arg0Expand = .no_expand,
}) ZcmdError!RunResult {
    return run(.{
        .allocator = args.allocator,
        .commands = &[_][]const []const u8{args.argv},
        .cwd = args.cwd,
        .cwd_dir = args.cwd_dir,
        .env_map = args.env_map,
        .max_output_bytes = args.max_output_bytes,
        .expand_arg0 = args.expand_arg0,
    });
}

fn feedStdinInputPosix(fd: std.os.system.fd_t, stdin_input: []const u8) !void {
    // credit goes to: https://www.reddit.com/r/Zig/comments/13674ed/help_request_using_stdin_with_childprocess/
    const stdin = std.fs.File{ .handle = fd };

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

    while (offset < stdin_input.len) {
        poll_ready_count = try std.os.poll(&fds, -1);
        if (poll_ready_count == 0) {
            continue;
        } else {
            if (fds[0].revents & std.os.POLL.OUT != 0) {
                if (offset + batch_size < stdin_input.len) {
                    wrote_size = try stdin.write(stdin_input[offset .. offset + batch_size]);
                } else {
                    wrote_size = try stdin.write(stdin_input[offset..]);
                }
                offset += wrote_size;
                // std.debug.print("\nconsumed {d} bytes of input\n", .{offset});
            } else {
                continue;
            }
        }
    }

    // job done, close the stdin pipe so that child process knows input is done
    stdin.close();
}

fn runPipelinePosix(args: ZcmdArgs) !void {
    // here we create a pipe then fork a copy of ourself, but instead of executing command, we do it in parent, and
    // let child to prepare for next environment. Using an example command pipelien
    // `cat ./tests/big_input.txt | wc -lw | wc-lw`, we will
    // 1. fork and let ourself do next command (which is `cat ...`)
    // 2. let forked children to bridge STDIN <-> pipe[0] then go to step (next command then become `wc` then `wc`
    //    then nothing so we get out of for loop)
    // the whole pipeline still use STDIN as input and STDOUT as output, so if we wrap this again, we can capture
    // the io streams
    for (args.commands, 0..) |next_command, i| {
        const pipe_flags = .{};
        var pipe = try std.os.pipe2(pipe_flags);
        const pid_result = try std.os.fork();
        if (pid_result == 0) {
            // we are child
            if (i + 1 == args.commands.len) {
                // at the end just clean up and exit
                std.os.close(pipe[0]);
                std.os.close(pipe[1]);
                std.os.exit(0);
            }
            try std.os.dup2(pipe[0], std.os.STDIN_FILENO);
            std.os.close(pipe[0]);
            std.os.close(pipe[1]);
            pipe = try std.os.pipe2(pipe_flags);
        } else {
            // we are parent

            // std.debug.print("\nwill run command: {s}:{d}\n", .{ next_command, i });
            if (i + 1 != args.commands.len) {
                try std.os.dup2(pipe[1], std.os.STDOUT_FILENO);
            }
            // timing is critical, so do not use defer for closing the pipe
            std.os.close(pipe[0]);
            std.os.close(pipe[1]);

            Zcmd.executeCommandPosix(
                args.allocator,
                next_command,
                args.env_map,
                args.expand_arg0,
            ) catch |err| {
                std.io.getStdErr().writer().print("zig: {any}: {s}\n", .{ err, next_command }) catch {};
                std.os.exit(1);
            };
            // no way back after this :)
        }
    }
}

fn executeCommandPosix(
    allocator: std.mem.Allocator,
    command: []const []const u8,
    env_map: ?*const std.process.EnvMap,
    expand_arg0: std.ChildProcess.Arg0Expand,
) !void {
    // most of codes are from std.ChildProcess :)
    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    // The POSIX standard does not allow malloc() between fork() and execve(),
    // and `self.allocator` may be a libc allocator.
    // I have personally observed the child process deadlocking when it tries
    // to call malloc() due to a heap allocation between fork() and execve(),
    // in musl v1.1.24.
    // Additionally, we want to reduce the number of possible ways things
    // can fail between fork() and execve().
    // Therefore, we do all the allocation for the execve() before the fork().
    // This means we must do the null-termination of argv and env vars here.
    const argv_buf = try arena.allocSentinel(?[*:0]const u8, command.len, null);
    for (command, 0..) |arg, i| {
        const duped = try arena.dupeZ(u8, arg);
        argv_buf[i] = duped.ptr;
    }

    // same logic to std.ChildProcess, so same TODOs :)
    const envp = m: {
        if (env_map) |em| {
            const envp_buf = try createNullDelimitedEnvMap(arena, em);
            break :m envp_buf.ptr;
        } else if (builtin.link_libc) {
            break :m std.c.environ;
        } else if (builtin.output_mode == .Exe) {
            // Then we have Zig start code and this works.
            // TODO type-safety for null-termination of `os.environ`.
            break :m @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.environ.ptr));
        } else {
            // TODO come up with a solution for this.
            @compileError("missing std lib enhancement: ChildProcess implementation has no way to collect the environment variables to forward to the child process");
        }
    };

    const exec_error = switch (expand_arg0) {
        .expand => std.os.execvpeZ_expandArg0(
            .expand,
            argv_buf.ptr[0].?,
            argv_buf.ptr,
            envp,
        ),
        .no_expand => std.os.execvpeZ_expandArg0(
            .no_expand,
            argv_buf.ptr[0].?,
            argv_buf.ptr,
            envp,
        ),
    };
    return exec_error;
}

// util functions needed for child process
// unfortunately below functions are not exposed from std.child_process.zig source code, have to copy it here.

const ErrInt = std.meta.Int(.unsigned, @sizeOf(anyerror) * 8);

fn writeIntFdPosix(fd: i32, value: ErrInt) !void {
    const file = std.fs.File{
        .handle = fd,
        // .capable_io_mode = .blocking,
        // .intended_io_mode = .blocking,
    };
    file.writer().writeInt(u64, @intCast(value), .little) catch return error.SystemResources;
}

fn readIntFdPosix(fd: i32) !ErrInt {
    const file = std.fs.File{
        .handle = fd,
        // .capable_io_mode = .blocking,
        // .intended_io_mode = .blocking,
    };
    return @as(ErrInt, @intCast(file.reader().readInt(u64, .little) catch return error.SystemResources));
}

// Child of fork calls this to report an error to the fork parent.
// Then the child exits.
fn forkChildErrReport(fd: i32, err: ZcmdError) noreturn {
    writeIntFdPosix(fd, @as(ErrInt, @intFromError(err))) catch {};
    // If we're linking libc, some naughty applications may have registered atexit handlers
    // which we really do not want to run in the fork child. I caught LLVM doing this and
    // it caused a deadlock instead of doing an exit syscall. In the words of Avril Lavigne,
    // "Why'd you have to go and make things so complicated?"
    if (builtin.link_libc) {
        // The _exit(2) function does nothing but make the exit syscall, unlike exit(3)
        std.c._exit(1);
    }
    std.os.exit(1);
}

fn fifoToOwnedArrayList(fifo: *std.io.PollFifo) std.ArrayList(u8) {
    if (fifo.head > 0) {
        @memcpy(fifo.buf[0..fifo.count], fifo.buf[fifo.head..][0..fifo.count]);
    }
    const result = std.ArrayList(u8){
        .items = fifo.buf[0..fifo.count],
        .capacity = fifo.buf.len,
        .allocator = fifo.allocator,
    };
    fifo.* = std.io.PollFifo.init(fifo.allocator);
    return result;
}

fn createNullDelimitedEnvMap(arena: std.mem.Allocator, env_map: *const std.process.EnvMap) ![:null]?[*:0]u8 {
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
};

pub fn forkAndRun(
    arena: std.mem.Allocator,
    comptime PayloadType: type,
    runFn: *const fn (payload: PayloadType) RunFnError!void,
    payload: PayloadType,
) !RunResult {
    switch (builtin.os.tag) {
        .linux, .macos => return forkAndRunPosix(arena, runFn, payload),
        .windows => unreachable,
        else => {
            @compileError("Only linux/macos/windows supported.");
        },
    }
}

fn forkAndRunPosix(
    arena: std.mem.Allocator,
    comptime PayloadType: type,
    runFn: *const fn (payload: PayloadType) RunFnError!void,
    payload: PayloadType,
) !RunResult {
    const stdout_pipe = try std.os.pipe();
    const stderr_pipe = try std.os.pipe();
    const err_pipe = try std.os.pipe();
    const pid_result = try std.os.fork();

    if (pid_result == 0) {
        // we are child

        std.os.close(err_pipe[0]);
        defer std.os.close(err_pipe[1]);

        std.os.dup2(stdout_pipe[1], std.os.STDOUT_FILENO) catch |err| forkChildErrReport(err_pipe[1], err);
        std.os.dup2(stderr_pipe[1], std.os.STDERR_FILENO) catch |err| forkChildErrReport(err_pipe[1], err);
        std.os.close(stdout_pipe[0]);
        std.os.close(stdout_pipe[1]);
        std.os.close(stderr_pipe[0]);
        std.os.close(stderr_pipe[1]);

        runFn(payload) catch |err| {
            forkChildErrReport(err_pipe[1], err);
            std.os.exit(1);
        };

        std.os.exit(0);
    }

    // we are parent

    std.os.close(stdout_pipe[1]);
    std.os.close(stderr_pipe[1]);

    const max_output_bytes = 8 * 1024 * 1024 * 1024;

    var poller = std.io.poll(arena, enum { stdout, stderr }, .{
        .stdout = std.fs.File{ .handle = stdout_pipe[0] },
        .stderr = std.fs.File{ .handle = stderr_pipe[0] },
    });
    defer poller.deinit();
    while (try poller.poll()) {
        if (poller.fifo(.stdout).count > max_output_bytes)
            return error.StdoutStreamTooLong;
        if (poller.fifo(.stderr).count > max_output_bytes)
            return error.StdoutStreamTooLong;
    }
    var stdout_array = fifoToOwnedArrayList(poller.fifo(.stdout));
    var stderr_array = fifoToOwnedArrayList(poller.fifo(.stderr));

    try writeIntFdPosix(err_pipe[1], std.math.maxInt(ErrInt));
    const err_int = try readIntFdPosix(err_pipe[0]);
    defer {
        std.os.close(err_pipe[0]);
        std.os.close(err_pipe[1]);
    }
    if (err_int != std.math.maxInt(ErrInt)) {
        return @as(ZcmdError, @errorCast(@errorFromInt(err_int)));
    }

    const result = std.os.waitpid(pid_result, 0);
    return RunResult{
        .allocator = arena,
        .args = .{ .allocator = arena, .commands = &[_][]const []const u8{&[_][]const u8{@typeName(PayloadType)}} },
        .term = Term.fromStatus(result.status),
        .stdout = try stdout_array.toOwnedSlice(),
        .stderr = try stderr_array.toOwnedSlice(),
    };
}

// windows support: pipes on windows is a mess... and copied a lot of fns from std.ChildProcess :(

const windows = std.posix.windows;

fn runWindows(args: struct {
    allocator: std.mem.Allocator,
    commands: []const []const []const u8,
    stdin_input: ?[]const u8 = null,
    user_name: ?[]const u8 = null,
    uid: if (builtin.os.tag == .windows) ?void else ?std.os.uid_t = null,
    gid: if (builtin.os.tag == .windows) ?void else ?std.os.uid_t = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = MAX_OUTPUT,
    expand_arg0: std.ChildProcess.Arg0Expand = .no_expand,
}) ZcmdError!RunResult {
    const pipe_flags = windows.SECURITY_ATTRIBUTES{
        .nLength = @sizeOf(windows.SECURITY_ATTRIBUTES),
        .bInheritHandle = windows.TRUE,
        .lpSecurityDescriptor = null,
    };
    var has_stdin_pipe: bool = false;
    const stdin_pipe = brk: {
        var pipes: [2]windows.HANDLE = undefined;
        if (args.stdin_input != null) {
            has_stdin_pipe = true;
            try windows.CreatePipe(&pipes[0], &pipes[1], &pipe_flags);
        }
        break :brk pipes;
    };
    const stdout_pipe = brk: {
        var pipes: [2]windows.HANDLE = undefined;
        try windows.CreatePipe(&pipes[0], &pipes[1], &pipe_flags);
        break :brk pipes;
    };
    const stderr_pipe = brk: {
        var pipes: [2]windows.HANDLE = undefined;
        try windows.CreatePipe(&pipes[0], &pipes[1], &pipe_flags);
        break :brk pipes;
    };

    // in windows, args.uid & args.gid has no effect

    if (args.cwd_dir != null) {
        @panic("windows only support use cwd, not support cwd_dir.");
    }
    if (args.cwd != null and !std.fs.path.isAbsolute(args.cwd.?)) {
        @panic("if set cwd, must be absolute path!");
    }

    // windows is different as createProcess function will not copy the current process env and state
    // so below our impl is totally different
    var pinfo = try spawnWindows(.{
        .allocator = args.allocator,
        .argv = args.commands[0],
        .stdin_handle = stdin_pipe[0],
        .stdout_handle = stdout_pipe[1],
        .stderr_handle = stderr_pipe[1],
        .cwd = args.cwd.?,
        .env_map = args.env_map,
    });

    try waitUnwrappedWindows(&pinfo);

    return RunResult{
        .allocator = args.allocator,
        .args = ZcmdArgs{
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
            .expand_arg0 = args.expand_arg0,
        },
        .term = pinfo.term.?,
        .stdout = null,
        .stderr = null,
    };
}

const PInfoWindows = struct {
    id: windows.HANDLE,
    thread_handle: windows.HANDLE,
    term: ?Term,
};

fn spawnWindows(args: struct {
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    stdin_handle: ?windows.HANDLE,
    stdout_handle: ?windows.HANDLE,
    stderr_handle: ?windows.HANDLE,
    cwd: ?[]const u8,
    env_map: ?*const std.process.EnvMap,
}) !PInfoWindows {
    var siStartInfo = windows.STARTUPINFOW{
        .cb = @sizeOf(windows.STARTUPINFOW),
        .hStdError = args.stderr_handle,
        .hStdOutput = args.stdout_handle,
        .hStdInput = args.stdin_handle,
        .dwFlags = windows.STARTF_USESTDHANDLES,
        .lpReserved = null,
        .lpDesktop = null,
        .lpTitle = null,
        .dwX = 0,
        .dwY = 0,
        .dwXSize = 0,
        .dwYSize = 0,
        .dwXCountChars = 0,
        .dwYCountChars = 0,
        .dwFillAttribute = 0,
        .wShowWindow = 0,
        .cbReserved2 = 0,
        .lpReserved2 = null,
    };
    var piProcInfo: windows.PROCESS_INFORMATION = undefined;

    const cwd_w = if (args.cwd) |cwd| try std.unicode.wtf8ToWtf16LeAllocZ(args.allocator, cwd) else null;
    defer if (cwd_w) |cwd| args.allocator.free(cwd);
    const cwd_w_ptr = if (cwd_w) |cwd| cwd.ptr else null;

    const maybe_envp_buf = if (args.env_map) |env_map| try createWindowsEnvBlock(args.allocator, env_map) else null;
    defer if (maybe_envp_buf) |envp_buf| args.allocator.free(envp_buf);
    const envp_ptr = if (maybe_envp_buf) |envp_buf| envp_buf.ptr else null;

    const app_name_wtf8 = args.argv[0];
    const app_name_is_absolute = std.fs.path.isAbsolute(app_name_wtf8);

    // the cwd set in ChildProcess is in effect when choosing the executable path
    // to match posix semantics
    var cwd_path_w_needs_free = false;
    const cwd_path_w = x: {
        // If the app name is absolute, then we need to use its dirname as the cwd
        if (app_name_is_absolute) {
            cwd_path_w_needs_free = true;
            const dir = std.fs.path.dirname(app_name_wtf8).?;
            break :x try std.unicode.wtf8ToWtf16LeAllocZ(args.allocator, dir);
        } else if (args.cwd) |cwd| {
            cwd_path_w_needs_free = true;
            break :x try std.unicode.wtf8ToWtf16LeAllocZ(args.allocator, cwd);
        } else {
            break :x &[_:0]u16{}; // empty for cwd
        }
    };
    defer if (cwd_path_w_needs_free) args.allocator.free(cwd_path_w);

    // If the app name has more than just a filename, then we need to separate that
    // into the basename and dirname and use the dirname as an addition to the cwd
    // path. This is because NtQueryDirectoryFile cannot accept FileName params with
    // path separators.
    const app_basename_wtf8 = std.fs.path.basename(app_name_wtf8);
    // If the app name is absolute, then the cwd will already have the app's dirname in it,
    // so only populate app_dirname if app name is a relative path with > 0 path separators.
    const maybe_app_dirname_wtf8 = if (!app_name_is_absolute) std.fs.path.dirname(app_name_wtf8) else null;
    const app_dirname_w: ?[:0]u16 = x: {
        if (maybe_app_dirname_wtf8) |app_dirname_wtf8| {
            break :x try std.unicode.wtf8ToWtf16LeAllocZ(args.allocator, app_dirname_wtf8);
        }
        break :x null;
    };
    defer if (app_dirname_w != null) args.allocator.free(app_dirname_w.?);

    const app_name_w = try std.unicode.wtf8ToWtf16LeAllocZ(args.allocator, app_basename_wtf8);
    defer args.allocator.free(app_name_w);

    const cmd_line_w = argvToCommandLineWindows(args.allocator, args.argv) catch |err| switch (err) {
        // argv[0] contains unsupported characters that will never resolve to a valid exe.
        error.InvalidArg0 => return error.FileNotFound,
        else => |e| return e,
    };
    defer args.allocator.free(cmd_line_w);

    run: {
        const PATH: [:0]const u16 = std.os.getenvW(std.unicode.utf8ToUtf16LeStringLiteral("PATH")) orelse &[_:0]u16{};
        const PATHEXT: [:0]const u16 = std.os.getenvW(std.unicode.utf8ToUtf16LeStringLiteral("PATHEXT")) orelse &[_:0]u16{};

        var app_buf = std.ArrayListUnmanaged(u16){};
        defer app_buf.deinit(args.allocator);

        try app_buf.appendSlice(args.allocator, app_name_w);

        var dir_buf = std.ArrayListUnmanaged(u16){};
        defer dir_buf.deinit(args.allocator);

        if (cwd_path_w.len > 0) {
            try dir_buf.appendSlice(args.allocator, cwd_path_w);
        }
        if (app_dirname_w) |app_dir| {
            if (dir_buf.items.len > 0) try dir_buf.append(args.allocator, std.fs.path.sep);
            try dir_buf.appendSlice(args.allocator, app_dir);
        }
        if (dir_buf.items.len > 0) {
            // Need to normalize the path, openDirW can't handle things like double backslashes
            const normalized_len = windows.normalizePath(u16, dir_buf.items) catch return error.BadPathName;
            dir_buf.shrinkRetainingCapacity(normalized_len);
        }

        windowsCreateProcessPathExt(args.allocator, &dir_buf, &app_buf, PATHEXT, cmd_line_w.ptr, envp_ptr, cwd_w_ptr, &siStartInfo, &piProcInfo) catch |no_path_err| {
            const original_err = switch (no_path_err) {
                error.FileNotFound, error.InvalidExe, error.AccessDenied => |e| e,
                error.UnrecoverableInvalidExe => return error.InvalidExe,
                else => |e| return e,
            };

            // If the app name had path separators, that disallows PATH searching,
            // and there's no need to search the PATH if the app name is absolute.
            // We still search the path if the cwd is absolute because of the
            // "cwd set in ChildProcess is in effect when choosing the executable path
            // to match posix semantics" behavior--we don't want to skip searching
            // the PATH just because we were trying to set the cwd of the child process.
            if (app_dirname_w != null or app_name_is_absolute) {
                return original_err;
            }

            var it = std.mem.tokenizeScalar(u16, PATH, ';');
            while (it.next()) |search_path| {
                dir_buf.clearRetainingCapacity();
                try dir_buf.appendSlice(args.allocator, search_path);
                // Need to normalize the path, some PATH values can contain things like double
                // backslashes which openDirW can't handle
                const normalized_len = windows.normalizePath(u16, dir_buf.items) catch continue;
                dir_buf.shrinkRetainingCapacity(normalized_len);

                if (windowsCreateProcessPathExt(args.allocator, &dir_buf, &app_buf, PATHEXT, cmd_line_w.ptr, envp_ptr, cwd_w_ptr, &siStartInfo, &piProcInfo)) {
                    break :run;
                } else |err| switch (err) {
                    error.FileNotFound, error.AccessDenied, error.InvalidExe => continue,
                    error.UnrecoverableInvalidExe => return error.InvalidExe,
                    else => |e| return e,
                }
            } else {
                return original_err;
            }
        };
    }

    return .{
        .id = piProcInfo.hProcess,
        .thread_handle = piProcInfo.hThread,
        .term = null,
    };
}

/// Serializes `argv` to a Windows command-line string suitable for passing to a child process and
/// parsing by the `CommandLineToArgvW` algorithm. The caller owns the returned slice.
pub fn argvToCommandLineWindows(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
) ![:0]u16 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    if (argv.len != 0) {
        const arg0 = argv[0];
        // The first argument must be quoted if it contains spaces or ASCII control characters
        // (excluding DEL). It also follows special quoting rules where backslashes have no special
        // interpretation, which makes it impossible to pass certain first arguments containing
        // double quotes to a child process without characters from the first argument leaking into
        // subsequent ones (which could have security implications).
        //
        // Empty arguments technically don't need quotes, but we quote them anyway for maximum
        // compatibility with different implementations of the 'CommandLineToArgvW' algorithm.
        //
        // Double quotes are illegal in paths on Windows, so for the sake of simplicity we reject
        // all first arguments containing double quotes, even ones that we could theoretically
        // serialize in unquoted form.
        var needs_quotes = arg0.len == 0;
        for (arg0) |c| {
            if (c <= ' ') {
                needs_quotes = true;
            } else if (c == '"') {
                return error.InvalidArg0;
            }
        }
        if (needs_quotes) {
            try buf.append('"');
            try buf.appendSlice(arg0);
            try buf.append('"');
        } else {
            try buf.appendSlice(arg0);
        }

        for (argv[1..]) |arg| {
            try buf.append(' ');
            // Subsequent arguments must be quoted if they contain spaces, tabs or double quotes,
            // or if they are empty. For simplicity and for maximum compatibility with different
            // implementations of the 'CommandLineToArgvW' algorithm, we also quote all ASCII
            // control characters (again, excluding DEL).
            needs_quotes = for (arg) |c| {
                if (c <= ' ' or c == '"') {
                    break true;
                }
            } else arg.len == 0;
            if (!needs_quotes) {
                try buf.appendSlice(arg);
                continue;
            }

            try buf.append('"');
            var backslash_count: usize = 0;
            for (arg) |byte| {
                switch (byte) {
                    '\\' => {
                        backslash_count += 1;
                    },
                    '"' => {
                        try buf.appendNTimes('\\', backslash_count * 2 + 1);
                        try buf.append('"');
                        backslash_count = 0;
                    },
                    else => {
                        try buf.appendNTimes('\\', backslash_count);
                        try buf.append(byte);
                        backslash_count = 0;
                    },
                }
            }
            try buf.appendNTimes('\\', backslash_count * 2);
            try buf.append('"');
        }
    }

    return try std.unicode.wtf8ToWtf16LeAllocZ(allocator, buf.items);
}

/// Caller must free result.
pub fn createWindowsEnvBlock(allocator: std.mem.Allocator, env_map: *const std.process.EnvMap) ![]u16 {
    // count bytes needed

    const max_chars_needed = x: {
        var max_chars_needed: usize = 4; // 4 for the final 4 null bytes

        var it = env_map.iterator();
        while (it.next()) |pair| {
            // +1 for '='
            // +1 for null byte
            max_chars_needed += pair.key_ptr.len + pair.value_ptr.len + 2;
        }
        break :x max_chars_needed;
    };
    const result = try allocator.alloc(u16, max_chars_needed);
    errdefer allocator.free(result);

    var it = env_map.iterator();
    var i: usize = 0;
    while (it.next()) |pair| {
        i += try std.unicode.wtf8ToWtf16Le(result[i..], pair.key_ptr.*);
        result[i] = '=';
        i += 1;
        i += try std.unicode.wtf8ToWtf16Le(result[i..], pair.value_ptr.*);
        result[i] = 0;
        i += 1;
    }
    result[i] = 0;
    i += 1;
    result[i] = 0;
    i += 1;
    result[i] = 0;
    i += 1;
    result[i] = 0;
    i += 1;
    return try allocator.realloc(result, i);
}

/// Expects `app_buf` to contain exactly the app name, and `dir_buf` to contain exactly the dir path.
/// After return, `app_buf` will always contain exactly the app name and `dir_buf` will always contain exactly the dir path.
/// Note: `app_buf` should not contain any leading path separators.
/// Note: If the dir is the cwd, dir_buf should be empty (len = 0).
fn windowsCreateProcessPathExt(
    allocator: std.mem.Allocator,
    dir_buf: *std.ArrayListUnmanaged(u16),
    app_buf: *std.ArrayListUnmanaged(u16),
    pathext: [:0]const u16,
    cmd_line: [*:0]u16,
    envp_ptr: ?[*]u16,
    cwd_ptr: ?[*:0]u16,
    lpStartupInfo: *windows.STARTUPINFOW,
    lpProcessInformation: *windows.PROCESS_INFORMATION,
) !void {
    const app_name_len = app_buf.items.len;
    const dir_path_len = dir_buf.items.len;

    if (app_name_len == 0) return error.FileNotFound;

    defer app_buf.shrinkRetainingCapacity(app_name_len);
    defer dir_buf.shrinkRetainingCapacity(dir_path_len);

    // The name of the game here is to avoid CreateProcessW calls at all costs,
    // and only ever try calling it when we have a real candidate for execution.
    // Secondarily, we want to minimize the number of syscalls used when checking
    // for each PATHEXT-appended version of the app name.
    //
    // An overview of the technique used:
    // - Open the search directory for iteration (either cwd or a path from PATH)
    // - Use NtQueryDirectoryFile with a wildcard filename of `<app name>*` to
    //   check if anything that could possibly match either the unappended version
    //   of the app name or any of the versions with a PATHEXT value appended exists.
    // - If the wildcard NtQueryDirectoryFile call found nothing, we can exit early
    //   without needing to use PATHEXT at all.
    //

    // This allows us to use a <open dir, NtQueryDirectoryFile, close dir> sequence
    // for any directory that doesn't contain any possible matches, instead of having
    // to use a separate look up for each individual filename combination (unappended +
    // each PATHEXT appended). For directories where the wildcard *does* match something,
    // we iterate the matches and take note of any that are either the unappended version,
    // or a version with a supported PATHEXT appended. We then try calling CreateProcessW
    // with the found versions in the appropriate order.

    var dir = dir: {
        // needs to be null-terminated

        try dir_buf.append(allocator, 0);
        defer dir_buf.shrinkRetainingCapacity(dir_path_len);
        const dir_path_z = dir_buf.items[0 .. dir_buf.items.len - 1 :0];
        const prefixed_path = try windows.wToPrefixedFileW(null, dir_path_z);
        break :dir std.fs.cwd().openDirW(prefixed_path.span().ptr, .{ .iterate = true }) catch
            return error.FileNotFound;
    };
    defer dir.close();

    // Add wildcard and null-terminator

    try app_buf.append(allocator, '*');
    try app_buf.append(allocator, 0);
    const app_name_wildcard = app_buf.items[0 .. app_buf.items.len - 1 :0];

    // This 2048 is arbitrary, we just want it to be large enough to get multiple FILE_DIRECTORY_INFORMATION entries

    // returned per NtQueryDirectoryFile call.

    var file_information_buf: [2048]u8 align(@alignOf(std.os.windows.FILE_DIRECTORY_INFORMATION)) = undefined;
    const file_info_maximum_single_entry_size = @sizeOf(windows.FILE_DIRECTORY_INFORMATION) + (windows.NAME_MAX * 2);
    if (file_information_buf.len < file_info_maximum_single_entry_size) {
        @compileError("file_information_buf must be large enough to contain at least one maximum size FILE_DIRECTORY_INFORMATION entry");
    }
    var io_status: windows.IO_STATUS_BLOCK = undefined;

    const num_supported_pathext = @typeInfo(CreateProcessSupportedExtension).Enum.fields.len;
    var pathext_seen = [_]bool{false} ** num_supported_pathext;
    var any_pathext_seen = false;
    var unappended_exists = false;

    // Fully iterate the wildcard matches via NtQueryDirectoryFile and take note of all versions
    // of the app_name we should try to spawn.
    // Note: This is necessary because the order of the files returned is filesystem-dependent:
    //       On NTFS, `blah.exe*` will always return `blah.exe` first if it exists.
    //       On FAT32, it's possible for something like `blah.exe.obj` to be returned first.
    while (true) {
        const app_name_len_bytes = std.math.cast(u16, app_name_wildcard.len * 2) orelse return error.NameTooLong;
        var app_name_unicode_string = windows.UNICODE_STRING{
            .Length = app_name_len_bytes,
            .MaximumLength = app_name_len_bytes,
            .Buffer = @constCast(app_name_wildcard.ptr),
        };
        const rc = windows.ntdll.NtQueryDirectoryFile(
            dir.fd,
            null,
            null,
            null,
            &io_status,
            &file_information_buf,
            file_information_buf.len,
            .FileDirectoryInformation,
            windows.FALSE, // single result

            &app_name_unicode_string,
            windows.FALSE, // restart iteration

        );

        // If we get nothing with the wildcard, then we can just bail out
        // as we know appending PATHEXT will not yield anything.
        switch (rc) {
            .SUCCESS => {},
            .NO_SUCH_FILE => return error.FileNotFound,
            .NO_MORE_FILES => break,
            .ACCESS_DENIED => return error.AccessDenied,
            else => return windows.unexpectedStatus(rc),
        }

        // According to the docs, this can only happen if there is not enough room in the
        // buffer to write at least one complete FILE_DIRECTORY_INFORMATION entry.
        // Therefore, this condition should not be possible to hit with the buffer size we use.
        std.debug.assert(io_status.Information != 0);

        var it = windows.FileInformationIterator(windows.FILE_DIRECTORY_INFORMATION){ .buf = &file_information_buf };
        while (it.next()) |info| {
            // Skip directories

            if (info.FileAttributes & windows.FILE_ATTRIBUTE_DIRECTORY != 0) continue;
            const filename = @as([*]u16, @ptrCast(&info.FileName))[0 .. info.FileNameLength / 2];
            // Because all results start with the app_name since we're using the wildcard `app_name*`,
            // if the length is equal to app_name then this is an exact match
            if (filename.len == app_name_len) {
                // Note: We can't break early here because it's possible that the unappended version
                //       fails to spawn, in which case we still want to try the PATHEXT appended versions.
                unappended_exists = true;
            } else if (windowsCreateProcessSupportsExtension(filename[app_name_len..])) |pathext_ext| {
                pathext_seen[@intFromEnum(pathext_ext)] = true;
                any_pathext_seen = true;
            }
        }
    }

    const unappended_err = unappended: {
        if (unappended_exists) {
            if (dir_path_len != 0) switch (dir_buf.items[dir_buf.items.len - 1]) {
                '/', '\\' => {},
                else => try dir_buf.append(allocator, std.fs.path.sep),
            };
            try dir_buf.appendSlice(allocator, app_buf.items[0..app_name_len]);
            try dir_buf.append(allocator, 0);
            const full_app_name = dir_buf.items[0 .. dir_buf.items.len - 1 :0];

            if (windowsCreateProcess(full_app_name.ptr, cmd_line, envp_ptr, cwd_ptr, lpStartupInfo, lpProcessInformation)) |_| {
                return;
            } else |err| switch (err) {
                error.FileNotFound,
                error.AccessDenied,
                => break :unappended err,
                error.InvalidExe => {
                    // On InvalidExe, if the extension of the app name is .exe then
                    // it's treated as an unrecoverable error. Otherwise, it'll be
                    // skipped as normal.
                    const app_name = app_buf.items[0..app_name_len];
                    const ext_start = std.mem.lastIndexOfScalar(u16, app_name, '.') orelse break :unappended err;
                    const ext = app_name[ext_start..];
                    if (windows.eqlIgnoreCaseWTF16(ext, std.unicode.utf8ToUtf16LeStringLiteral(".EXE"))) {
                        return error.UnrecoverableInvalidExe;
                    }
                    break :unappended err;
                },
                else => return err,
            }
        }
        break :unappended error.FileNotFound;
    };

    if (!any_pathext_seen) return unappended_err;

    // Now try any PATHEXT appended versions that we've seen
    var ext_it = std.mem.tokenizeScalar(u16, pathext, ';');
    while (ext_it.next()) |ext| {
        const ext_enum = windowsCreateProcessSupportsExtension(ext) orelse continue;
        if (!pathext_seen[@intFromEnum(ext_enum)]) continue;

        dir_buf.shrinkRetainingCapacity(dir_path_len);
        if (dir_path_len != 0) switch (dir_buf.items[dir_buf.items.len - 1]) {
            '/', '\\' => {},
            else => try dir_buf.append(allocator, std.fs.path.sep),
        };
        try dir_buf.appendSlice(allocator, app_buf.items[0..app_name_len]);
        try dir_buf.appendSlice(allocator, ext);
        try dir_buf.append(allocator, 0);
        const full_app_name = dir_buf.items[0 .. dir_buf.items.len - 1 :0];

        if (windowsCreateProcess(full_app_name.ptr, cmd_line, envp_ptr, cwd_ptr, lpStartupInfo, lpProcessInformation)) |_| {
            return;
        } else |err| switch (err) {
            error.FileNotFound => continue,
            error.AccessDenied => continue,
            error.InvalidExe => {
                // On InvalidExe, if the extension of the app name is .exe then
                // it's treated as an unrecoverable error. Otherwise, it'll be
                // skipped as normal.
                if (windows.eqlIgnoreCaseWTF16(ext, std.unicode.utf8ToUtf16LeStringLiteral(".EXE"))) {
                    return error.UnrecoverableInvalidExe;
                }
                continue;
            },
            else => return err,
        }
    }

    return unappended_err;
}

// Should be kept in sync with `windowsCreateProcessSupportsExtension`
const CreateProcessSupportedExtension = enum {
    bat,
    cmd,
    com,
    exe,
};

/// Case-insensitive WTF-16 lookup
fn windowsCreateProcessSupportsExtension(ext: []const u16) ?CreateProcessSupportedExtension {
    if (ext.len != 4) return null;
    const State = enum {
        start,
        dot,
        b,
        ba,
        c,
        cm,
        co,
        e,
        ex,
    };
    var state: State = .start;
    for (ext) |c| switch (state) {
        .start => switch (c) {
            '.' => state = .dot,
            else => return null,
        },
        .dot => switch (c) {
            'b', 'B' => state = .b,
            'c', 'C' => state = .c,
            'e', 'E' => state = .e,
            else => return null,
        },
        .b => switch (c) {
            'a', 'A' => state = .ba,
            else => return null,
        },
        .c => switch (c) {
            'm', 'M' => state = .cm,
            'o', 'O' => state = .co,
            else => return null,
        },
        .e => switch (c) {
            'x', 'X' => state = .ex,
            else => return null,
        },
        .ba => switch (c) {
            't', 'T' => return .bat,
            else => return null,
        },
        .cm => switch (c) {
            'd', 'D' => return .cmd,
            else => return null,
        },
        .co => switch (c) {
            'm', 'M' => return .com,
            else => return null,
        },
        .ex => switch (c) {
            'e', 'E' => return .exe,
            else => return null,
        },
    };
    return null;
}

fn windowsCreateProcess(app_name: [*:0]u16, cmd_line: [*:0]u16, envp_ptr: ?[*]u16, cwd_ptr: ?[*:0]u16, lpStartupInfo: *windows.STARTUPINFOW, lpProcessInformation: *windows.PROCESS_INFORMATION) !void {
    // TODO the docs for environment pointer say:
    // > A pointer to the environment block for the new process. If this parameter
    // > is NULL, the new process uses the environment of the calling process.
    // > ...
    // > An environment block can contain either Unicode or ANSI characters. If
    // > the environment block pointed to by lpEnvironment contains Unicode
    // > characters, be sure that dwCreationFlags includes CREATE_UNICODE_ENVIRONMENT.
    // > If this parameter is NULL and the environment block of the parent process
    // > contains Unicode characters, you must also ensure that dwCreationFlags
    // > includes CREATE_UNICODE_ENVIRONMENT.
    // This seems to imply that we have to somehow know whether our process parent passed
    // CREATE_UNICODE_ENVIRONMENT if we want to pass NULL for the environment parameter.
    // Since we do not know this information that would imply that we must not pass NULL
    // for the parameter.
    // However this would imply that programs compiled with -DUNICODE could not pass
    // environment variables to programs that were not, which seems unlikely.
    // More investigation is needed.
    return windows.CreateProcessW(
        app_name,
        cmd_line,
        null,
        null,
        windows.TRUE,
        windows.CREATE_UNICODE_ENVIRONMENT,
        @as(?*anyopaque, @ptrCast(envp_ptr)),
        cwd_ptr,
        lpStartupInfo,
        lpProcessInformation,
    );
}

fn waitUnwrappedWindows(pinfo: *PInfoWindows) !void {
    const result = windows.WaitForSingleObjectEx(pinfo.id, windows.INFINITE, false);

    pinfo.term = x: {
        var exit_code: windows.DWORD = undefined;
        if (windows.kernel32.GetExitCodeProcess(pinfo.id, &exit_code) == 0) {
            break :x Term{ .Unknown = 0 };
        } else {
            break :x Term{ .Exited = @as(u8, @truncate(exit_code)) };
        }
    };

    std.os.close(pinfo.id);
    std.os.close(pinfo.thread_handle);
    return result;
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
    switch (builtin.os.tag) {
        .linux, .macos => {
            {
                const result = try Zcmd.run(.{
                    .allocator = allocator,
                    .commands = &[_][]const []const u8{
                        &.{ "uname", "-a" },
                    },
                });
                defer result.deinit();
                try testing.expectEqual(result.term.Exited, 0);
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
                const f = try std.fs.cwd().openFile("tests/big_input.txt", .{});
                defer f.close();
                const content = try f.readToEndAlloc(allocator, MAX_OUTPUT);
                defer allocator.free(content);
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
                var buf: [4096]u8 = undefined;
                var paths: [2][]const u8 = undefined;
                paths[0] = try std.process.getCwd(&buf);
                paths[1] = "tests";
                const abs_path = try std.fs.path.join(allocator, &paths);
                defer allocator.free(abs_path);
                const result = try Zcmd.run(.{
                    .allocator = allocator,
                    .commands = &[_][]const []const u8{
                        &.{ "cat", "./big_input.txt" },
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
                var test_dir = try std.fs.cwd().openDir("tests", .{});
                defer test_dir.close();
                const result = try Zcmd.run(.{
                    .allocator = allocator,
                    .commands = &[_][]const []const u8{
                        &.{ "cat", "./big_input.txt" },
                        &.{ "wc", "-lw" },
                    },
                    .cwd_dir = test_dir,
                });
                defer result.deinit();
                var rbuf: [2]usize = undefined;
                try _extractNumbers(usize, result.stdout.?, rbuf[0..]);
                try testing.expectEqualDeep(rbuf, [2]usize{ 1302, 2604 });
            }
            {
                var envmap = std.process.EnvMap.init(allocator);
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
                var envmap = std.process.EnvMap.init(allocator);
                defer envmap.deinit();
                try envmap.put("ZCMD_TEST_ENV1", "hello");
                const result = try Zcmd.run(.{
                    .allocator = allocator,
                    .commands = &[_][]const []const u8{
                        &.{"printenv"},
                        &.{ "grep", "ZCMD_TEST_ENV1" },
                    },
                    .env_map = &envmap,
                    .expand_arg0 = .expand,
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
                try testing.expectEqual(result.term.Exited, 0);
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
        },

        .windows => {
            {
                const result = try Zcmd.run(.{
                    .allocator = allocator,
                    .commands = &[_][]const []const u8{
                        &.{ "Get-CimInstance", "Win32_OperatingSystem" },
                    },
                });
                defer result.deinit();
                try testing.expectEqual(result.term.Exited, 0);
                try testing.expect(result.stdout.?.len > 0);
            }
        },

        else => {
            @compileError("Only linux/macos/windows supported.");
        },
    }
}

test "all failures" {
    const allocator = std.testing.allocator;
    switch (builtin.os.tag) {
        .linux, .macos => {
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
                    "zig: error.FileNotFound: { sort-of, -nr }\n",
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
                    "zig: error.FileNotFound: { nonexist }\n",
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
                            "find: ‘nonexist’: No such file or directory\n",
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
        },

        .windows => unreachable,

        else => {
            @compileError("Only linux/macos/windows supported.");
        },
    }
}

test "RunResult" {
    const allocator = testing.allocator;
    // std.debug.print("\nstdout: {d}bytes: {?s}\n", .{ if (result.stdout == null) 0 else result.stdout.?.len, result.stdout.? });
    // std.debug.print("\nstderr: {d}bytes: {?s}\n", .{ if (result.stderr == null) 0 else result.stderr.?.len, result.stderr.? });
    switch (builtin.os.tag) {
        .linux, .macos => {
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
        },

        .windows => unreachable,

        else => {
            @compileError("Only linux/macos/windows supported.");
        },
    }
}

const TestPayload = struct {
    hello: []const u8,
};

fn _testForkAndRun(payload: TestPayload) RunFnError!void {
    std.io.getStdOut().writer().print("{s}", .{payload.hello}) catch {
        return RunFnError.IOError;
    };
}

test "forkAndRun" {
    var aa = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer aa.deinit();
    const arena = aa.allocator();

    switch (builtin.os.tag) {
        .linux, .macos => {
            {
                const result = try forkAndRun(arena, TestPayload, _testForkAndRun, .{ .hello = "world" });
                defer result.deinit();
                try result.assertSucceeded(.{});
                try testing.expectEqualSlices(u8, result.stdout.?, "world");
            }
        },

        .windows => unreachable,

        else => {
            @compileError("Only linux/macos/windows supported.");
        },
    }
}
