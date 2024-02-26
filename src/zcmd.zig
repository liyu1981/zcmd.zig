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
    std.os.ShutdownError;

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
        .linux, .macos => return runPosix(args),
        .windows => unreachable,
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
        const pipe_flags = switch (builtin.os.tag) {
            .linux, .macos => .{},
            .windows => .{},
            else => {
                @compileError("Only linux & macos supported.");
            },
        };
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

        .windows => unreachable,

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
