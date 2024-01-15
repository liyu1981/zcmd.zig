const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const os_selector = switch (builtin.os.tag) {
    .linux, .macos => void,
    else => {
        @compileError("Only linux & macos supported.");
    },
};

const OS_PAGE_SIZE = switch (builtin.os.tag) {
    .linux, .macos => std.mem.page_size,
    else => {
        @compileError("Only linux & macos supported.");
    },
};

pub const MAX_OUTPUT = 8 * 1024 * 1024 * 1024;

const stderr_writer = std.io.getStdErr().writer();

pub const RunResult = struct {
    allocator: std.mem.Allocator,

    term: Term,
    stdout: []const u8,
    stderr: []const u8,

    pub fn deinit(this: *const RunResult) void {
        this.allocator.free(this.stdout);
        this.allocator.free(this.stderr);
    }
};

pub fn runCommandsErr(args: struct {
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
}) anyerror!RunResult {
    // var need_free_to_free: bool = false;
    // var to_free_result: std.ChildProcess.RunResult = undefined;
    // var need_free_last: bool = true;
    var last_run_result: RunResult = undefined;
    // for (args.commands, 0..) |command, i| {
    //     if (i > 0 and need_free_last) {
    //         to_free_result = last_run_result;
    //         need_free_to_free = true;
    //     }
    last_run_result = try runCommandErr(.{
        .allocator = args.allocator,
        .command = args.commands[0],
        .stdin_input = brk: {
            //if (i == 0) {
            if (args.stdin_input) |stdin_input| break :brk stdin_input else break :brk null;
            //} else break :brk last_run_result.stdout;
        },
        .cwd = args.cwd,
        .cwd_dir = args.cwd_dir,
        .env_map = args.env_map,
        .max_output_bytes = args.max_output_bytes,
        .expand_arg0 = args.expand_arg0,
    });
    return last_run_result;
    //     }) catch |err| {
    //         defer {
    //             if (i > 0 and need_free_to_free) {
    //                 args.allocator.free(to_free_result.stdout);
    //                 args.allocator.free(to_free_result.stderr);
    //                 need_free_to_free = false;
    //             }
    //         }
    //         if (args.stop_on_any_error) {
    //             return err;
    //         }
    //         last_run_result = std.ChildProcess.RunResult{
    //             .term = std.ChildProcess.Term{ .Exited = 1 },
    //             .stdout = "",
    //             .stderr = "",
    //         };
    //         need_free_last = false;
    //         continue;
    //     };
    //     defer {
    //         if (i > 0 and need_free_to_free) {
    //             args.allocator.free(to_free_result.stdout);
    //             args.allocator.free(to_free_result.stderr);
    //             need_free_to_free = false;
    //         }
    //     }
    //     switch (last_run_result.term) {
    //         .Exited => |ret| {
    //             if (ret != 0 and args.stop_on_any_error) {
    //                 return last_run_result;
    //             }
    //             if (last_run_result.stderr.len > 0 and args.stop_on_any_stderr) {
    //                 return last_run_result;
    //             }
    //             need_free_last = true;
    //             continue;
    //         },
    //         else => {
    //             if (args.stop_on_any_error) {
    //                 return last_run_result;
    //             }
    //             need_free_last = true;
    //             continue;
    //         },
    //     }
    // }
    // return last_run_result;
}

pub fn runCommandErr(args: struct {
    allocator: std.mem.Allocator,
    command: []const []const u8,
    stdin_input: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = MAX_OUTPUT,
    expand_arg0: ChildProcess.Arg0Expand = .no_expand,
}) anyerror!RunResult {
    // shameless steal the implementation of runChildProcess from zig source code as I need to customize it a bit
    var child = ChildProcess.init(args.command, args.allocator);
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

    // credit goes to: https://www.reddit.com/r/Zig/comments/13674ed/help_request_using_stdin_with_childprocess/
    if (args.stdin_input) |si| {
        // std.debug.print("\ninput of {d} bytes\n", .{si.len});
        if (child.stdin) |stdin| {
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
            child.stdin.?.close();
            child.stdin = null;
        }
    }

    try child.collectOutput(&stdout, &stderr, args.max_output_bytes);

    const rr = RunResult{
        .allocator = args.allocator,
        .term = try child.wait(),
        .stdout = try stdout.toOwnedSlice(),
        .stderr = try stderr.toOwnedSlice(),
    };

    return rr;
}

// internal functions

pub const SpawnError = error{
    OutOfMemory,

    /// POSIX-only. `StdIo.Ignore` was selected and opening `/dev/null` returned ENODEV.
    NoDevice,

    /// Windows-only. One of:
    /// * `cwd` was provided and it could not be re-encoded into UTF16LE, or
    /// * The `PATH` or `PATHEXT` environment variable contained invalid UTF-8.
    InvalidUtf8,

    /// Windows-only. `cwd` was provided, but the path did not exist when spawning the child process.
    CurrentWorkingDirectoryUnlinked,
} ||
    std.os.ExecveError ||
    std.os.SetIdError ||
    std.os.ChangeCurDirError;

pub const Term = union(enum) {
    Exited: u8,
    Signal: u32,
    Stopped: u32,
    Unknown: u32,
};

pub const StdIo = enum {
    Inherit,
    Ignore,
    Pipe,
    Close,
};

// borrow just too many code from zig std.ChildProcess, but necessary
pub const ChildProcess = struct {
    pub const Id = std.os.pid_t;

    /// Available after calling `spawn()`. This becomes `undefined` after calling `wait()`.
    /// On Windows this is the hProcess.
    /// On POSIX this is the pid.
    id: Id,

    allocator: std.mem.Allocator,

    stdin: ?std.fs.File,
    stdout: ?std.fs.File,
    stderr: ?std.fs.File,

    term: ?(SpawnError!Term),

    argv: []const []const u8,

    /// Leave as null to use the current env map using the supplied allocator.
    env_map: ?*const std.process.EnvMap,

    stdin_behavior: StdIo,
    stdout_behavior: StdIo,
    stderr_behavior: StdIo,

    /// Set to change the user id when spawning the child process.
    uid: ?std.os.uid_t,

    /// Set to change the group id when spawning the child process.
    gid: ?std.os.gid_t,

    /// Set to change the current working directory when spawning the child process.
    cwd: ?[]const u8,
    /// Set to change the current working directory when spawning the child process.
    /// This is not yet implemented for Windows. See https://github.com/ziglang/zig/issues/5190
    /// Once that is done, `cwd` will be deprecated in favor of this field.
    cwd_dir: ?std.fs.Dir = null,

    err_pipe: ?[2]std.os.fd_t,

    expand_arg0: Arg0Expand,

    /// Darwin-only. Disable ASLR for the child process.
    disable_aslr: bool = false,

    /// Darwin-only. Start child process in suspended state as if SIGSTOP was sent.
    start_suspended: bool = false,

    /// Set to true to obtain rusage information for the child process.
    /// Depending on the target platform and implementation status, the
    /// requested statistics may or may not be available. If they are
    /// available, then the `resource_usage_statistics` field will be populated
    /// after calling `wait`.
    /// On Linux and Darwin, this obtains rusage statistics from wait4().
    request_resource_usage_statistics: bool = false,

    /// This is available after calling wait if
    /// `request_resource_usage_statistics` was set to `true` before calling
    /// `spawn`.
    resource_usage_statistics: ResourceUsageStatistics = .{},

    pub const ResourceUsageStatistics = struct {
        rusage: @TypeOf(rusage_init) = rusage_init,

        /// Returns the peak resident set size of the child process, in bytes, if available.
        pub inline fn getMaxRss(rus: ResourceUsageStatistics) ?usize {
            switch (builtin.os.tag) {
                .linux => {
                    if (rus.rusage) |ru| {
                        return @as(usize, @intCast(ru.maxrss)) * 1024;
                    } else {
                        return null;
                    }
                },
                .macos, .ios => {
                    if (rus.rusage) |ru| {
                        // Darwin oddly reports in bytes instead of kilobytes.
                        return @as(usize, @intCast(ru.maxrss));
                    } else {
                        return null;
                    }
                },
                else => return null,
            }
        }

        const rusage_init = switch (builtin.os.tag) {
            .linux, .macos, .ios => @as(?std.os.rusage, null),
            else => {},
        };
    };

    pub const Arg0Expand = std.os.Arg0Expand;

    /// First argument in argv is the executable.
    pub fn init(argv: []const []const u8, allocator: std.mem.Allocator) ChildProcess {
        return .{
            .allocator = allocator,
            .argv = argv,
            .id = undefined,
            .err_pipe = null,
            .term = null,
            .env_map = null,
            .cwd = null,
            .uid = null,
            .gid = null,
            .stdin = null,
            .stdout = null,
            .stderr = null,
            .stdin_behavior = StdIo.Inherit,
            .stdout_behavior = StdIo.Inherit,
            .stderr_behavior = StdIo.Inherit,
            .expand_arg0 = .no_expand,
        };
    }

    pub fn setUserName(self: *ChildProcess, name: []const u8) !void {
        const user_info = try std.process.getUserInfo(name);
        self.uid = user_info.uid;
        self.gid = user_info.gid;
    }

    /// On success must call `kill` or `wait`.
    /// After spawning the `id` is available.
    pub fn spawn(self: *ChildProcess) SpawnError!void {
        if (!std.process.can_spawn) {
            @compileError("the target operating system cannot spawn processes");
        }

        if (builtin.os.tag == .windows) {
            return self.spawnWindows();
        } else {
            return self.spawnPosix();
        }
    }

    pub fn spawnAndWait(self: *ChildProcess) SpawnError!Term {
        try self.spawn();
        return self.wait();
    }

    /// Forcibly terminates child process and then cleans up all resources.
    pub inline fn kill(self: *ChildProcess) !Term {
        return self.killPosix();
    }

    pub fn killPosix(self: *ChildProcess) !Term {
        if (self.term) |term| {
            self.cleanupStreams();
            return term;
        }
        std.os.kill(self.id, std.os.SIG.TERM) catch |err| switch (err) {
            error.ProcessNotFound => return error.AlreadyTerminated,
            else => return err,
        };
        try self.waitUnwrapped();
        return self.term.?;
    }

    /// Blocks until child process terminates and then cleans up all resources.
    pub inline fn wait(self: *ChildProcess) !Term {
        const term = try self.waitPosix();
        self.id = undefined;
        return term;
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

    /// Collect the output from the process's stdout and stderr. Will return once all output
    /// has been collected. This does not mean that the process has ended. `wait` should still
    /// be called to wait for and clean up the process.
    ///
    /// The process must be started with stdout_behavior and stderr_behavior == .Pipe
    pub fn collectOutput(
        child: ChildProcess,
        stdout: *std.ArrayList(u8),
        stderr: *std.ArrayList(u8),
        max_output_bytes: usize,
    ) !void {
        std.debug.assert(child.stdout_behavior == .Pipe);
        std.debug.assert(child.stderr_behavior == .Pipe);

        // we could make this work with multiple allocators but YAGNI
        if (stdout.allocator.ptr != stderr.allocator.ptr or
            stdout.allocator.vtable != stderr.allocator.vtable)
            @panic("ChildProcess.collectOutput only supports 1 allocator");

        var poller = std.io.poll(stdout.allocator, enum { stdout, stderr }, .{
            .stdout = child.stdout.?,
            .stderr = child.stderr.?,
        });
        defer poller.deinit();

        while (try poller.poll()) {
            if (poller.fifo(.stdout).count > max_output_bytes)
                return error.StdoutStreamTooLong;
            if (poller.fifo(.stderr).count > max_output_bytes)
                return error.StderrStreamTooLong;
        }

        stdout.* = fifoToOwnedArrayList(poller.fifo(.stdout));
        stderr.* = fifoToOwnedArrayList(poller.fifo(.stderr));
    }

    pub const RunError = std.os.GetCwdError || std.os.ReadError || SpawnError || std.os.PollError || error{
        StdoutStreamTooLong,
        StderrStreamTooLong,
    };

    /// Spawns a child process, waits for it, collecting stdout and stderr, and then returns.
    /// If it succeeds, the caller owns result.stdout and result.stderr memory.
    pub fn run(args: struct {
        allocator: std.mem.Allocator,
        argv: []const []const u8,
        cwd: ?[]const u8 = null,
        cwd_dir: ?std.fs.Dir = null,
        env_map: ?*const std.process.EnvMap = null,
        max_output_bytes: usize = 50 * 1024,
        expand_arg0: Arg0Expand = .no_expand,
    }) RunError!RunResult {
        var child = ChildProcess.init(args.argv, args.allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        child.cwd = args.cwd;
        child.cwd_dir = args.cwd_dir;
        child.env_map = args.env_map;
        child.expand_arg0 = args.expand_arg0;

        var stdout = std.ArrayList(u8).init(args.allocator);
        var stderr = std.ArrayList(u8).init(args.allocator);
        errdefer {
            stdout.deinit();
            stderr.deinit();
        }

        try child.spawn();
        try child.collectOutput(&stdout, &stderr, args.max_output_bytes);

        return RunResult{
            .term = try child.wait(),
            .stdout = try stdout.toOwnedSlice(),
            .stderr = try stderr.toOwnedSlice(),
        };
    }

    fn waitPosix(self: *ChildProcess) !Term {
        if (self.term) |term| {
            self.cleanupStreams();
            return term;
        }

        try self.waitUnwrapped();
        return self.term.?;
    }

    fn waitUnwrapped(self: *ChildProcess) !void {
        const res: std.os.WaitPidResult = res: {
            if (self.request_resource_usage_statistics) {
                switch (builtin.os.tag) {
                    .linux, .macos, .ios => {
                        var ru: std.os.rusage = undefined;
                        const res = std.os.wait4(self.id, 0, &ru);
                        self.resource_usage_statistics.rusage = ru;
                        break :res res;
                    },
                    else => {},
                }
            }

            break :res std.os.waitpid(self.id, 0);
        };
        const status = res.status;
        self.cleanupStreams();
        self.handleWaitResult(status);
    }

    fn handleWaitResult(self: *ChildProcess, status: u32) void {
        self.term = self.cleanupAfterWait(status);
    }

    fn cleanupStreams(self: *ChildProcess) void {
        if (self.stdin) |*stdin| {
            stdin.close();
            self.stdin = null;
        }
        if (self.stdout) |*stdout| {
            stdout.close();
            self.stdout = null;
        }
        if (self.stderr) |*stderr| {
            stderr.close();
            self.stderr = null;
        }
    }

    fn cleanupAfterWait(self: *ChildProcess, status: u32) !Term {
        if (self.err_pipe) |err_pipe| {
            defer destroyPipe(err_pipe);

            if (builtin.os.tag == .linux) {
                var fd = [1]std.os.pollfd{std.os.pollfd{
                    .fd = err_pipe[0],
                    .events = std.os.POLL.IN,
                    .revents = undefined,
                }};

                // Check if the eventfd buffer stores a non-zero value by polling
                // it, that's the error code returned by the child process.
                _ = std.os.poll(&fd, 0) catch unreachable;

                // According to eventfd(2) the descriptor is readable if the counter
                // has a value greater than 0
                if ((fd[0].revents & std.os.POLL.IN) != 0) {
                    const err_int = try readIntFd(err_pipe[0]);
                    return @as(SpawnError, @errorCast(@errorFromInt(err_int)));
                }
            } else {
                // Write maxInt(ErrInt) to the write end of the err_pipe. This is after
                // waitpid, so this write is guaranteed to be after the child
                // pid potentially wrote an error. This way we can do a blocking
                // read on the error pipe and either get maxInt(ErrInt) (no error) or
                // an error code.
                try writeIntFd(err_pipe[1], std.math.maxInt(ErrInt));
                const err_int = try readIntFd(err_pipe[0]);
                // Here we potentially return the fork child's error from the parent
                // pid.
                if (err_int != std.math.maxInt(ErrInt)) {
                    return @as(SpawnError, @errorCast(@errorFromInt(err_int)));
                }
            }
        }

        return statusToTerm(status);
    }

    fn statusToTerm(status: u32) Term {
        return if (std.os.W.IFEXITED(status))
            Term{ .Exited = std.os.W.EXITSTATUS(status) }
        else if (std.os.W.IFSIGNALED(status))
            Term{ .Signal = std.os.W.TERMSIG(status) }
        else if (std.os.W.IFSTOPPED(status))
            Term{ .Stopped = std.os.W.STOPSIG(status) }
        else
            Term{ .Unknown = status };
    }

    fn spawnPosix(self: *ChildProcess) SpawnError!void {
        const pipe_flags = if (std.io.is_async) std.os.O.NONBLOCK else 0;
        const stdin_pipe = if (self.stdin_behavior == StdIo.Pipe) try std.os.pipe2(pipe_flags) else undefined;
        errdefer if (self.stdin_behavior == StdIo.Pipe) {
            destroyPipe(stdin_pipe);
        };

        const stdout_pipe = if (self.stdout_behavior == StdIo.Pipe) try std.os.pipe2(pipe_flags) else undefined;
        errdefer if (self.stdout_behavior == StdIo.Pipe) {
            destroyPipe(stdout_pipe);
        };

        const stderr_pipe = if (self.stderr_behavior == StdIo.Pipe) try std.os.pipe2(pipe_flags) else undefined;
        errdefer if (self.stderr_behavior == StdIo.Pipe) {
            destroyPipe(stderr_pipe);
        };

        const any_ignore = (self.stdin_behavior == StdIo.Ignore or self.stdout_behavior == StdIo.Ignore or self.stderr_behavior == StdIo.Ignore);
        const dev_null_fd = if (any_ignore)
            std.os.openZ("/dev/null", std.os.O.RDWR, 0) catch |err| switch (err) {
                error.PathAlreadyExists => unreachable,
                error.NoSpaceLeft => unreachable,
                error.FileTooBig => unreachable,
                error.DeviceBusy => unreachable,
                error.FileLocksNotSupported => unreachable,
                error.BadPathName => unreachable, // Windows-only
                error.InvalidHandle => unreachable, // WASI-only
                error.WouldBlock => unreachable,
                error.NetworkNotFound => unreachable, // Windows-only
                else => |e| return e,
            }
        else
            undefined;
        defer {
            if (any_ignore) std.os.close(dev_null_fd);
        }

        var arena_allocator = std.heap.ArenaAllocator.init(self.allocator);
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
        const argv_buf = try arena.allocSentinel(?[*:0]const u8, self.argv.len, null);
        for (self.argv, 0..) |arg, i| argv_buf[i] = (try arena.dupeZ(u8, arg)).ptr;

        const envp = m: {
            if (self.env_map) |env_map| {
                const envp_buf = try createNullDelimitedEnvMap(arena, env_map);
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

        // This pipe is used to communicate errors between the time of fork
        // and execve from the child process to the parent process.
        const err_pipe = blk: {
            if (builtin.os.tag == .linux) {
                const fd = try std.os.eventfd(0, std.os.linux.EFD.CLOEXEC);
                // There's no distinction between the readable and the writeable
                // end with eventfd
                break :blk [2]std.os.fd_t{ fd, fd };
            } else {
                break :blk try std.os.pipe2(std.os.O.CLOEXEC);
            }
        };
        errdefer destroyPipe(err_pipe);

        const pid_result = try std.os.fork();
        if (pid_result == 0) {
            // we are the child
            setUpChildIo(self.stdin_behavior, stdin_pipe[0], std.os.STDIN_FILENO, dev_null_fd) catch |err| forkChildErrReport(err_pipe[1], err);
            setUpChildIo(self.stdout_behavior, stdout_pipe[1], std.os.STDOUT_FILENO, dev_null_fd) catch |err| forkChildErrReport(err_pipe[1], err);
            setUpChildIo(self.stderr_behavior, stderr_pipe[1], std.os.STDERR_FILENO, dev_null_fd) catch |err| forkChildErrReport(err_pipe[1], err);

            if (self.stdin_behavior == .Pipe) {
                std.os.close(stdin_pipe[0]);
                std.os.close(stdin_pipe[1]);
            }
            if (self.stdout_behavior == .Pipe) {
                std.os.close(stdout_pipe[0]);
                std.os.close(stdout_pipe[1]);
            }
            if (self.stderr_behavior == .Pipe) {
                std.os.close(stderr_pipe[0]);
                std.os.close(stderr_pipe[1]);
            }

            if (self.cwd_dir) |cwd| {
                std.os.fchdir(cwd.fd) catch |err| forkChildErrReport(err_pipe[1], err);
            } else if (self.cwd) |cwd| {
                std.os.chdir(cwd) catch |err| forkChildErrReport(err_pipe[1], err);
            }

            if (self.gid) |gid| {
                std.os.setregid(gid, gid) catch |err| forkChildErrReport(err_pipe[1], err);
            }

            if (self.uid) |uid| {
                std.os.setreuid(uid, uid) catch |err| forkChildErrReport(err_pipe[1], err);
            }

            const err = switch (self.expand_arg0) {
                .expand => std.os.execvpeZ_expandArg0(.expand, argv_buf.ptr[0].?, argv_buf.ptr, envp),
                .no_expand => std.os.execvpeZ_expandArg0(.no_expand, argv_buf.ptr[0].?, argv_buf.ptr, envp),
            };
            forkChildErrReport(err_pipe[1], err);
        }

        // we are the parent
        const pid = @as(i32, @intCast(pid_result));
        if (self.stdin_behavior == StdIo.Pipe) {
            self.stdin = std.fs.File{ .handle = stdin_pipe[1] };
        } else {
            self.stdin = null;
        }
        if (self.stdout_behavior == StdIo.Pipe) {
            self.stdout = std.fs.File{ .handle = stdout_pipe[0] };
        } else {
            self.stdout = null;
        }
        if (self.stderr_behavior == StdIo.Pipe) {
            self.stderr = std.fs.File{ .handle = stderr_pipe[0] };
        } else {
            self.stderr = null;
        }

        self.id = pid;
        self.err_pipe = err_pipe;
        self.term = null;

        if (self.stdin_behavior == StdIo.Pipe) {
            std.os.close(stdin_pipe[0]);
        }
        if (self.stdout_behavior == StdIo.Pipe) {
            std.os.close(stdout_pipe[1]);
        }
        if (self.stderr_behavior == StdIo.Pipe) {
            std.os.close(stderr_pipe[1]);
        }
    }

    fn setUpChildIo(stdio: StdIo, pipe_fd: i32, std_fileno: i32, dev_null_fd: i32) !void {
        switch (stdio) {
            .Pipe => try std.os.dup2(pipe_fd, std_fileno),
            .Close => std.os.close(std_fileno),
            .Inherit => {},
            .Ignore => try std.os.dup2(dev_null_fd, std_fileno),
        }
    }
};

fn destroyPipe(pipe: [2]std.os.fd_t) void {
    std.os.close(pipe[0]);
    if (pipe[0] != pipe[1]) std.os.close(pipe[1]);
}

// Child of fork calls this to report an error to the fork parent.
// Then the child exits.
fn forkChildErrReport(fd: i32, err: SpawnError) noreturn {
    writeIntFd(fd, @as(ErrInt, @intFromError(err))) catch {};
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

const ErrInt = std.meta.Int(.unsigned, @sizeOf(anyerror) * 8);

fn writeIntFd(fd: i32, value: ErrInt) !void {
    const file = std.fs.File{
        .handle = fd,
        .capable_io_mode = .blocking,
        .intended_io_mode = .blocking,
    };
    file.writer().writeInt(u64, @intCast(value), .little) catch return error.SystemResources;
}

fn readIntFd(fd: i32) !ErrInt {
    const file = std.fs.File{
        .handle = fd,
        .capable_io_mode = .blocking,
        .intended_io_mode = .blocking,
    };
    return @as(ErrInt, @intCast(file.reader().readInt(u64, .little) catch return error.SystemResources));
}

pub fn createNullDelimitedEnvMap(arena: std.mem.Allocator, env_map: *const std.process.EnvMap) ![:null]?[*:0]u8 {
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

test "default" {
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
        const result = try runCommandsErr(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "cat", "./tests/big_input.txt" },
            },
        });
        defer {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
        }
        try testing.expect(result.stdout.len > 0);
        try testing.expect(result.stderr.len == 0);
    }
    // {
    //     const result = try runChainedCommandsAndGetResultErr(.{
    //         .allocator = allocator,
    //         .commands = &[_][]const []const u8{
    //             &.{"notexist.sh"},
    //             &.{ "uname", "-a" },
    //         },
    //         .stop_on_any_error = false,
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
