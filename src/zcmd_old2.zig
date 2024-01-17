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

const PipeFd = [2]std.os.system.fd_t;

const stderr_writer = std.io.getStdErr().writer();

pub const SingleRunResult = struct {
    allocator: std.mem.Allocator,

    term: Term = undefined,
    stdout: ?[]const u8 = null,
    stderr: []const u8 = undefined,

    pub fn deinit(this: *const SingleRunResult) void {
        if (this.stdout) |stdout| this.allocator.free(stdout);
        this.allocator.free(this.stderr);
    }
};

pub const RunResult = struct {
    allocator: std.mem.Allocator,

    term: Term = undefined, // simply a copy of last command term
    stdout: []const u8 = undefined, // point to same last command stdout
    stderr: []const u8 = undefined, // point to same last command stderr
    all_results: ?std.ArrayList(SingleRunResult),

    pub fn deinit(this: *const RunResult) void {
        // this.stdout & this.stderr will point to same allocated buf of all_results[last], no need to free them
        if (this.all_results) |all_results| {
            for (0..all_results.items.len) |i| {
                all_results.items[i].deinit();
            }
            all_results.deinit();
        }
    }
};

pub const ZCmd = struct {
    allocator: std.mem.Allocator,
    last_command: CommandProcess = undefined,
    result: ?RunResult = null,

    pub fn deinit(this: *const ZCmd) void {
        this.result.?.deinit();
    }

    pub fn runErr(args: struct {
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
    }) anyerror!ZCmd {
        var zcmd = ZCmd{ .allocator = args.allocator };
        zcmd.last_command = CommandProcess.spawn(.{
            .allocator = args.allocator,
            .zcmd_ = &zcmd,
            .command = args.commands[args.commands.len - 1],
            .upstream_commands = args.commands[0 .. args.commands.len - 1],
            .stdin_input = args.stdin_input,
            .cwd = args.cwd,
            .cwd_dir = args.cwd_dir,
            .evn_map = args.env_map,
            .max_output_bytes = args.max_output_bytes,
            .expand_arg0 = args.expand_arg0,
            .trim_stdout = args.trim_stdout,
            .trim_stderr = args.trim_stderr,
            .stop_on_any_error = args.stop_on_any_error,
            .stop_on_any_stderr = args.stop_on_any_stderr,
        });
        try zcmd.last_command.wait();
        zcmd.result = zcmd.last_command.collectResults();
        return zcmd;
    }

    fn createPipe(this: *ZCmd) anyerror!PipeFd {
        const pipe_flags = 0;
        const p = try std.os.pipe2(pipe_flags);
        std.debug.print("\ncreated pipe= {any}\n", .{p});
        return p;
    }

    fn closeFd(this: *ZCmd, fd: std.os.system.fd_t) anyerror!void {
        std.debug.print("\nclose fd= {d}\n", .{fd});
        std.os.close(fd);
    }
};

const CommandProcess = struct {
    allocator: std.mem.Allocator,
    zcmd_: *ZCmd,
    child_process: CommandChildProcess = undefined,
    stdin_input: ?[]const u8 = null,
    err_pipe: PipeFd = undefined,
    stdout_array: std.ArrayList(u8),
    stderr_array: std.ArrayList(u8),
    max_output_bytes: usize = MAX_OUTPUT,

    pub fn spawn(args: struct {
        allocator: std.mem.Allocator,
        zcmd_: *ZCmd,
        command: []const []const u8,
        upstream_commands: []const []const []const u8,
        stdin_input: ?[]const u8 = null,
        stdin_pipe: ?PipeFd = null,
        stdout_pipe: ?PipeFd = null,
        stderr_pipe: PipeFd,
        err_pipe: PipeFd,
        cwd: ?[]const u8 = null,
        cwd_dir: ?std.fs.Dir = null,
        env_map: ?*const std.process.EnvMap = null,
        max_output_bytes: usize = MAX_OUTPUT,
        expand_arg0: CommandChildProcess.Arg0Expand = .no_expand,
    }) anyerror!void {
        var cmd = CommandProcess{
            .allocator = args.allocator,
            .zcmd_ = args.zcmd_,
            .stdin_input = args.stdin_inputs,
            .stdout_array = std.ArrayList(u8).init(args.allocator),
            .stderr_array = std.ArrayList(u8).init(args.allocator),
            .max_output_bytes = args.max_output_bytes,
        };
        var child = CommandChildProcess.init(
            args.command,
            args.allocator,
            args.zcmd_,
        );
        cmd.child_process = child;

        child.upstream_commands = args.upstream_commands;

        child.stdin_behavior = brk: {
            if (args.child_commands.len > 0) {
                break :brk .Pipeline;
            } else if (args.child_commands.len == 0 and args.stdin_input != null) {
                break :brk .Pipe;
            } else {
                break :brk .Ignore;
            }
        };

        child.stdin_pipe = brk: {
            switch (child.stdin_behavior) {
                .Pipeline => break :brk try args.zcmd_.createPipe(),
                .Pipe => break :brk try args.zcmd_.createPipe(),
                else => break :brk undefined,
            }
        };

        child.stdout_pipe = if (args.stdout_pipe != null) args.stdout_pipe else try args.zcmd_.createPipe();
        child.stderr_pipe = args.stderr_pipe;
        child.err_pipe = args.err_pipe;
        child.cwd_dir = brk: {
            if (args.cwd) |cwd_str| break :brk try std.fs.openDirAbsolute(cwd_str, .{});
            if (args.cwd_dir) |cwd| break :brk cwd;
            break :brk std.fs.cwd();
        };
        child.env_map = args.env_map;
        child.expand_arg0 = args.expand_arg0;

        try cmd.child_process.spawn();
        try cmd.feedStdinInput(cmd.stdin_inputs);
        return cmd;
    }

    pub fn feedStdinInput(this: *CommandProcess, stdin_input: ?[]const u8) !void {
        // credit goes to: https://www.reddit.com/r/Zig/comments/13674ed/help_request_using_stdin_with_childprocess/
        if (stdin_input) |si| {
            // std.debug.print("\ninput of {d} bytes\n", .{si.len});
            const stdin = std.fs.File{ .handle = this.child_process.stdin_pipe[1] };
            std.debug.print("\ninput fd={d}\n", .{stdin.handle});
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

            while (offset < si.len) {
                poll_ready_count = try std.os.poll(&fds, -1);
                if (poll_ready_count == 0) {
                    continue;
                } else {
                    if (fds[0].revents & std.os.POLL.OUT != 0) {
                        if (offset + batch_size < si.len) {
                            wrote_size = try stdin.write(si[offset .. offset + batch_size]);
                        } else {
                            wrote_size = try stdin.write(si[offset..]);
                        }
                        offset += wrote_size;
                        std.debug.print("\nconsumed {d} bytes of input\n", .{offset});
                    } else {
                        continue;
                    }
                }
            }

            // job done, close the stdin pipe so that child process knows input is done
            try this.zcmd_.closeFd(stdin.handle);
        }
    }

    pub fn wait(this: *const CommandProcess) !void {
        return this.child_process.wait();
    }

    pub fn collectResults(this: *const CommandProcess) !RunResults {}
};

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
    Pipeline,
    Pipe,
    Close,
};

// borrow just too many code from zig std.ChildProcess, but necessary
pub const CommandChildProcess = struct {
    pub const Id = std.os.pid_t;

    zcmd_: *ZCmd,

    upstream_commands: []const []const []const u8,

    /// Available after calling `spawn()`. This becomes `undefined` after calling `wait()`.
    /// On Windows this is the hProcess.
    /// On POSIX this is the pid.
    id: Id,

    allocator: std.mem.Allocator,

    stdin_behavior: StdIo,
    stdin_pipe: PipeFd,

    stdout_pipe: PipeFd,
    stderr_pipe: PipeFd,

    // This pipe is used to communicate errors between the time of fork
    // and execve from the child process to the parent process.
    err_pipe: PipeFd,

    term: ?(SpawnError!Term),

    argv: []const []const u8,

    /// Leave as null to use the current env map using the supplied allocator.
    env_map: ?*const std.process.EnvMap,

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
    pub fn init(argv: []const []const u8, allocator: std.mem.Allocator, zcmd_: *ZCmd) CommandChildProcess {
        return .{
            .zcmd_ = zcmd_,
            .allocator = allocator,
            .argv = argv,
            .id = undefined,
            .term = null,
            .stdin_behavior = StdIo.Inherit,
            .stdin_pipe = undefined,
            .stdout_pipe = undefined,
            .stderr_pipe = undefined,
            .err_pipe = undefined,
            .env_map = null,
            .cwd = null,
            .uid = null,
            .gid = null,
            .expand_arg0 = .no_expand,
        };
    }

    pub fn setUserName(self: *CommandChildProcess, name: []const u8) !void {
        const user_info = try std.process.getUserInfo(name);
        self.uid = user_info.uid;
        self.gid = user_info.gid;
    }

    /// On success must call `kill` or `wait`.
    /// After spawning the `id` is available.
    pub inline fn spawn(self: *CommandChildProcess) SpawnError!void {
        if (!std.process.can_spawn) {
            @compileError("the target operating system cannot spawn processes");
        }
        return self.spawnPosix();
    }

    /// Forcibly terminates child process and then cleans up all resources.
    pub inline fn kill(self: *CommandChildProcess) !Term {
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
    pub inline fn wait(self: *CommandChildProcess) !Term {
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
        child: CommandChildProcess,
        skip_fds: []std.os.system.fd_t,
        stdout_array: *std.ArrayList(u8),
        stderr_array: *std.ArrayList(u8),
        max_output_bytes: usize,
    ) !void {
        // we could make this work with multiple allocators but YAGNI
        if (stdout_array.allocator.ptr != stderr_array.allocator.ptr or
            stdout_array.allocator.vtable != stderr_array.allocator.vtable)
            @panic("ChildProcess.collectOutput only supports 1 allocator");

        const need_stdout = brk: {
            const fd = child.stdout_pipe[0];
            const index = std.mem.indexOfScalar(std.os.system.fd_t, skip_fds, fd);
            break :brk index == null and fd > 2; // can not be stdin/stdout/stderr
        };
        const need_stderr = brk: {
            const fd = child.stderr_pipe[0];
            const index = std.mem.indexOfScalar(std.os.system.fd_t, skip_fds, fd);
            break :brk index == null and fd > 2; // can not be stdin/stdout/stderr
        };

        if (need_stdout and need_stderr) {
            std.debug.print("\nneed_stdout and need_stderr, fd={any},{any}\n", .{ child.stdout_pipe[0], child.stderr_pipe[0] });
            const res = std.os.waitpid(child.id, std.os.linux.W.NOHANG);
            if (std.os.W.IFEXITED(res.status) or std.os.W.IFSIGNALED(res.status)) {
                std.debug.print("\nalready exited, read left\n", .{});
                const stdout_f = std.fs.File{ .handle = child.stdout_pipe[0] };
                const stderr_f = std.fs.File{ .handle = child.stderr_pipe[0] };
                // write one more byte to stdout and stderr in case there is nothing
                try writeByteFd(child.stdout_pipe[1], 4);
                try writeByteFd(child.stderr_pipe[1], 4);
                std.debug.print("\nalready exited, start read left\n", .{});
                while (true) {
                    var buf: [1]u8 = undefined;
                    const r = stdout_f.read(&buf) catch break;
                    if (r > 0) {
                        try stdout_array.append(buf[0]);
                    } else break;
                }
                std.debug.print("\nalready exited, read left {d}bytes stdout\n", .{stdout_array.items.len});
                while (true) {
                    var buf: [1]u8 = undefined;
                    const r = stderr_f.read(&buf) catch break;
                    if (r > 0) {
                        try stderr_array.append(buf[0]);
                    } else break;
                }
                std.debug.print("\nalready exited, read left {d}bytes stderr\n", .{stderr_array.items.len});
            } else {
                var poller = std.io.poll(stdout_array.allocator, enum { stdout, stderr }, .{
                    .stdout = std.fs.File{ .handle = child.stdout_pipe[0] },
                    .stderr = std.fs.File{ .handle = child.stderr_pipe[0] },
                });
                defer poller.deinit();
                while (try poller.poll()) {
                    // std.debug.print("\npoller pull {d}:{d}..\n", .{ poller.fifo(.stdout).count, poller.fifo(.stderr).count });
                    if (poller.fifo(.stdout).count > max_output_bytes)
                        return error.StdoutStreamTooLong;
                    if (poller.fifo(.stderr).count > max_output_bytes)
                        return error.StderrStreamTooLong;
                }

                stdout_array.* = fifoToOwnedArrayList(poller.fifo(.stdout));
                stderr_array.* = fifoToOwnedArrayList(poller.fifo(.stderr));
            }
        } else if (need_stderr and !need_stdout) {
            std.debug.print("\nneed_stderr, fd={d}\n", .{child.stderr_pipe[0]});
            var poller = std.io.poll(stderr_array.allocator, enum { stderr }, .{
                .stderr = std.fs.File{ .handle = child.stderr_pipe[0] },
            });
            defer poller.deinit();
            while (try poller.poll()) {
                std.debug.print("\npoller pull 2 {d}..\n", .{poller.fifo(.stderr).count});
                if (poller.fifo(.stderr).count > max_output_bytes)
                    return error.StderrStreamTooLong;
            }
            stderr_array.* = fifoToOwnedArrayList(poller.fifo(.stderr));
        } else {
            @panic("no support for need_stdout only or nothing, should not call");
        }
    }

    pub const RunError = std.os.GetCwdError || std.os.ReadError || SpawnError || std.os.PollError || error{
        StdoutStreamTooLong,
        StderrStreamTooLong,
    };

    fn waitPosix(self: *CommandChildProcess) !Term {
        if (self.term) |term| {
            try self.cleanupStreams();
            return term;
        }

        try self.waitUnwrapped();
        return self.term.?;
    }

    fn waitUnwrapped(self: *CommandChildProcess) !void {
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

            std.debug.print("\nbefore std.os.waitpid: {d}\n", .{self.id});
            break :res std.os.waitpid(self.id, 0);
        };
        const status = res.status;
        try self.cleanupStreams();
        self.handleWaitResult(status);
    }

    inline fn handleWaitResult(self: *CommandChildProcess, status: u32) void {
        self.term = self.cleanupAfterWait(status);
    }

    fn cleanupStreams(self: *CommandChildProcess) !void {
        try self.zcmd_.closeFd(self.stderr_pipe[0]);
    }

    fn cleanupAfterWait(self: *CommandChildProcess, status: u32) !Term {
        const err_pipe = self.err_pipe;
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

        return statusToTerm(status);
    }

    fn statusToTerm(status: u32) Term {
        return if (std.os.W.IFEXITED(status))
            Term{ .Exited = std.os.W.EXITSTATUS(status) }
        else if (std.os.W.IFSIGNALED(status))
            Term{ .Signal = std.os.W.TERMSIG(status) }
        else if (std.os.W.IFSTOPPED(status))
            unreachable
            // Term{ .Stopped = std.os.W.STOPSIG(status) }
        else
            unreachable;
        // Term{ .Unknown = status };
    }

    fn spawnPosix(self: *CommandChildProcess) SpawnError!void {
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

        std.debug.print("\nbefore fork {s}: stdin={any}, stdout={any}, stderr={any}, err={any}\n", .{
            self.argv,
            self.stdin_pipe,
            self.stdout_pipe,
            self.stderr_pipe,
            self.err_pipe,
        });

        const pid_result = try std.os.fork();
        if (pid_result == 0) {
            // we are the child
            // child will prepare next pipes for upstream command is there is

            std.os.close(self.err_pipe[0]);

            if (self.stdin_behavior == .Pipeline) {
                std.os.dup2(self.stdin_pipe[0], std.os.STDIN_FILENO) catch |err| forkChildErrReport(self.err_pipe[1], err);
            }
            destroyPipe(self.stdin_pipe);

            std.os.dup2(self.stdout_pipe[1], std.os.STDOUT_FILENO) catch |err| forkChildErrReport(self.err_pipe[1], err);
            destroyPipe(self.stdout_pipe);

            std.os.dup2(self.stderr_pipe[1], std.os.STDERR_FILENO) catch |err| forkChildErrReport(self.err_pipe[1], err);
            destroyPipe(self.stderr_pipe);

            // std.debug.print("\nto keep={d},{d}\n", .{ to_keep_fd_errin, to_keep_fd_errout });
            // std.debug.print("\nto dup={?d} {d} {d}\n", .{
            //     if (self.stdin_behavior == .Pipe) self.stdin_pipe[0] else null,
            //     self.stdout_pipe[1],
            //     self.stderr_pipe[1],
            // });
            // std.debug.print("\nto close=", .{});
            // {
            //     var it = self.zcmd_.known_fds.iterator();
            //     while (it.next()) |entry| {
            //         const fd = entry.key_ptr.*;
            //         const status = entry.value_ptr.*;
            //         switch (status) {
            //             .live => if (to_keep_fd_errin != fd and to_keep_fd_errout != fd) {
            //                 std.debug.print("{d} ", .{fd});
            //             },
            //             .closed => {},
            //         }
            //     }
            //     std.debug.print("\n", .{});
            // }

            if (self.stdin_behavior == .Pipe) {
                std.os.dup2(self.stdin_pipe[0], std.os.STDIN_FILENO) catch |err| forkChildErrReport(self.err_pipe[1], err);
            }

            std.os.dup2(self.stdout_pipe[1], std.os.STDOUT_FILENO) catch |err| forkChildErrReport(self.err_pipe[1], err);

            std.os.dup2(self.stderr_pipe[1], std.os.STDERR_FILENO) catch |err| forkChildErrReport(self.err_pipe[1], err);

            // now close all those fds inherited from parent
            var it = self.zcmd_.known_fds.iterator();
            while (it.next()) |entry| {
                const fd = entry.key_ptr.*;
                const status = entry.value_ptr.*;
                switch (status) {
                    .live => if (to_keep_fd_errout != fd) {
                        std.os.close(fd);
                    },
                    .closed => {},
                }
            }

            if (self.cwd_dir) |cwd| {
                std.os.fchdir(cwd.fd) catch |err| forkChildErrReport(self.err_pipe[1], err);
            } else if (self.cwd) |cwd| {
                std.os.chdir(cwd) catch |err| forkChildErrReport(self.err_pipe[1], err);
            }

            if (self.gid) |gid| {
                std.os.setregid(gid, gid) catch |err| forkChildErrReport(self.err_pipe[1], err);
            }

            if (self.uid) |uid| {
                std.os.setreuid(uid, uid) catch |err| forkChildErrReport(self.err_pipe[1], err);
            }

            const err = switch (self.expand_arg0) {
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
            forkChildErrReport(self.err_pipe[1], err);
        }

        // we are the parent
        // parent will actually execute the command

        // this pid is actually the next upstream
        // const pid = @as(i32, @intCast(pid_result));

        std.os.close(self.err_pipe[0]);

        if (self.stdin_behavior == .Pipeline) {
            std.os.dup2(self.stdin_pipe[0], std.os.STDIN_FILENO) catch |err| forkChildErrReport(self.err_pipe[1], err);
        }
        destroyPipe(self.stdin_pipe);

        std.os.dup2(self.stdout_pipe[1], std.os.STDOUT_FILENO) catch |err| forkChildErrReport(self.err_pipe[1], err);
        destroyPipe(self.stdout_pipe);

        std.os.dup2(self.stderr_pipe[1], std.os.STDERR_FILENO) catch |err| forkChildErrReport(self.err_pipe[1], err);
        destroyPipe(self.stderr_pipe);

        if (self.cwd_dir) |cwd| {
            std.os.fchdir(cwd.fd) catch |err| forkChildErrReport(self.err_pipe[1], err);
        } else if (self.cwd) |cwd| {
            std.os.chdir(cwd) catch |err| forkChildErrReport(self.err_pipe[1], err);
        }

        if (self.gid) |gid| {
            std.os.setregid(gid, gid) catch |err| forkChildErrReport(self.err_pipe[1], err);
        }

        if (self.uid) |uid| {
            std.os.setreuid(uid, uid) catch |err| forkChildErrReport(self.err_pipe[1], err);
        }

        // now there is no way back :)
        const err = switch (self.expand_arg0) {
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
        forkChildErrReport(self.err_pipe[1], err);
    }
};

fn destroyPipe(pipe: [2]std.os.fd_t) void {
    if (pipe[0] > 2) {
        std.os.close(pipe[0]);
    }
    if (pipe[0] != pipe[1] and pipe[1] > 2) {
        std.os.close(pipe[1]);
    }
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

fn writeByteFd(fd: i32, value: u8) !void {
    const file = std.fs.File{
        .handle = fd,
        .capable_io_mode = .blocking,
        .intended_io_mode = .blocking,
    };
    file.writer().writeInt(u8, value, .little) catch return error.SystemResources;
}

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
    // {
    //     const result = try runCommandsErr(.{
    //         .allocator = allocator,
    //         .commands = &[_][]const []const u8{
    //             &.{ "cat", "./tests/big_input.txt" },
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
    //     const result = try runCommandsErr(.{
    //         .allocator = allocator,
    //         .commands = &[_][]const []const u8{
    //             &.{ "cat", "./tests/big_input.txt" },
    //             &.{ "wc", "-lw" },
    //             &.{ "wc", "-lw" },
    //             // &.{ "xargs", "-0", "print", "'result: %s'" },
    //         },
    //     });
    //     defer result.deinit();
    //     // std.debug.print("\n{?s}\n", .{result.stdout});
    //     // try testing.expectEqualSlices(u8, result.stdout, "    1302    2604\n");
    //     // try testing.expect(result.stderr.len == 0);
    // }
    {
        const f = try std.fs.cwd().openFile("./tests/big_input.txt", .{});
        defer f.close();
        const big_input = try f.readToEndAlloc(allocator, MAX_OUTPUT);
        defer allocator.free(big_input);
        const zcmd = try ZCmd.runErr(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "grep", "tests" },
                &.{ "wc", "-lw" },
                &.{ "wc", "-lw" },
            },
            .stdin_input = big_input,
        });
        defer zcmd.deinit();
        // std.debug.print("\n{?s}\n", .{result.stdout});
        try testing.expectEqualSlices(u8, zcmd.result.?.stdout, "      12      24\n");
        try testing.expect(zcmd.result.?.stderr.len == 0);
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

// test "forbidden city" {
//     {
//         const maybe_value: anyerror!usize = 5;
//         try testing.expect(!_testIsError(
//             usize,
//             maybe_value,
//             error.FileNotFound,
//         ));
//     }
// }
