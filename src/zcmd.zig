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
    if (args.commands.len == 0) {
        @panic("zero commands!");
    }

    var cmd_pipes: []PipeFd = try args.allocator.alloc(PipeFd, args.commands.len - 1);
    defer args.allocator.free(cmd_pipes);
    // do we need to consider async io in commands?
    // const pipe_flags = if (std.io.is_async) std.os.O.NONBLOCK else 0;
    const pipe_flags = 0; // std.os.system.O.CLOEXEC;
    for (0..cmd_pipes.len) |i| {
        cmd_pipes[i] = try std.os.pipe2(pipe_flags);
        std.debug.print("\ncreated {d} pipe= {any}\n", .{ i, cmd_pipes[i] });
    }

    var cmd_processes: []CommandProcess = try args.allocator.alloc(CommandProcess, args.commands.len);
    defer {
        args.allocator.free(cmd_processes);
    }
    for (0..cmd_processes.len) |i| {
        cmd_processes[i] = try CommandProcess.init(.{
            .allocator = args.allocator,
            .command = args.commands[i],
            .stdin_input = if (i == 0) args.stdin_input else null,
            .stdin_pipe = if (i > 0) cmd_pipes[i - 1] else null,
            .owned_stdin_pipe = if (i > 0) false else true,
            .stdout_pipe = if (i + 1 == cmd_processes.len) null else cmd_pipes[i],
            .owned_stdout_pipe = if (i + 1 == cmd_processes.len) true else false,
            .cwd = args.cwd,
            .cwd_dir = args.cwd_dir,
            .env_map = args.env_map,
            .max_output_bytes = args.max_output_bytes,
            .expand_arg0 = args.expand_arg0,
        });
    }

    for (0..cmd_processes.len) |i| {
        try cmd_processes[i].child_process.spawn();
        std.debug.print("\nspawned {d}\n", .{cmd_processes[i].child_process.id});
    }

    var all_results = std.ArrayList(SingleRunResult).init(args.allocator);
    var last_result = SingleRunResult{ .allocator = args.allocator };
    for (0..cmd_processes.len) |i| {
        var cmd_process = cmd_processes[i];
        std.debug.print("\ncollect {d} {s}\n", .{ cmd_process.child_process.id, args.commands[i] });
        if (i + 1 < cmd_processes.len) {
            if (i == 0) {
                if (args.stdin_input) |si| {
                    std.debug.print("\nfeedStdin {d}\n", .{cmd_processes[0].child_process.id});
                    try cmd_processes[0].feedStdinInput(si);
                }
            } else {
                if (cmd_process.child_process.stdin_pipe) |si| {
                    std.debug.print("\nwant to close: fd={any}\n", .{si});
                    std.os.close(si[0]);
                    std.os.close(si[1]);
                    cmd_process.child_process.stdin = null;
                }
            }
            // try cmd_process.child_process.collectOutput(
            //     @as(*allowzero std.ArrayList(u8), @ptrFromInt(0)),
            //     false,
            //     &cmd_process.stderr_array,
            //     true,
            //     cmd_process.max_output_bytes,
            // );
            try all_results.append(SingleRunResult{
                .allocator = args.allocator,
                .stderr = try args.allocator.alloc(u8, 0), //try cmd_process.stderr_array.toOwnedSlice(),
            });
            // if (cmd_process.stdout_pipe) |so| {
            //     // we should only need to close the write pipe while all others are closed
            //     // std.debug.print("\nnow close fd={d}\n", .{so[1]});
            //     // std.os.close(so[0]);
            //     // std.os.close(so[1]);
            // }
        } else {
            if (i == 0) {
                if (args.stdin_input) |si| {
                    std.debug.print("\nfeedStdin {d}\n", .{cmd_processes[0].child_process.id});
                    try cmd_processes[0].feedStdinInput(si);
                }
            } else {
                if (cmd_process.child_process.stdin_pipe) |si| {
                    std.debug.print("\nwant to close: fd={any}\n", .{si});
                    std.os.close(si[0]);
                    std.os.close(si[1]);
                    cmd_process.child_process.stdin = null;
                }
            }
            // try cmd_process.child_process.collectOutput(
            //     &cmd_process.stdout_array.?,
            //     true,
            //     &cmd_process.stderr_array,
            //     true,
            //     cmd_process.max_output_bytes,
            // );
            const so = try args.allocator.alloc(u8, 0); // try cmd_process.stdout_array.?.toOwnedSlice();
            const se = try args.allocator.alloc(u8, 0); // try cmd_process.stderr_array.toOwnedSlice();
            try all_results.append(SingleRunResult{
                .allocator = args.allocator,
                .stdout = so,
                .stderr = se,
            });
            last_result.stdout = so;
            last_result.stderr = se;
        }
    }

    for (0..cmd_processes.len) |i| {
        std.debug.print("\nwait for process: {d}\n", .{cmd_processes[i].child_process.id});
        const term = try cmd_processes[i].child_process.wait();
        if (i + 1 == cmd_processes.len) {
            last_result.term = term;
        }
        all_results.items[i].term = term;
    }

    return RunResult{
        .allocator = args.allocator,
        .term = last_result.term,
        .stdout = last_result.stdout.?,
        .stderr = last_result.stderr,
        .all_results = all_results,
    };
}

const CommandProcess = struct {
    allocator: std.mem.Allocator,
    child_process: ChildProcess,
    stdin_input: ?[]const u8,
    stdin_pipe: ?PipeFd,
    stdout_pipe: ?PipeFd,
    stdout_array: ?std.ArrayList(u8),
    stderr_array: std.ArrayList(u8),
    max_output_bytes: usize = MAX_OUTPUT,

    pub fn init(args: struct {
        allocator: std.mem.Allocator,
        command: []const []const u8,
        stdin_input: ?[]const u8 = null,
        stdin_pipe: ?PipeFd = null,
        owned_stdin_pipe: bool = true,
        stdout_pipe: ?PipeFd = null,
        owned_stdout_pipe: bool = true,
        cwd: ?[]const u8 = null,
        cwd_dir: ?std.fs.Dir = null,
        env_map: ?*const std.process.EnvMap = null,
        max_output_bytes: usize = MAX_OUTPUT,
        expand_arg0: ChildProcess.Arg0Expand = .no_expand,
    }) anyerror!CommandProcess {
        var child = ChildProcess.init(args.command, args.allocator);
        child.stdin_behavior = if (args.stdin_pipe != null or args.stdin_input != null) .Pipe else .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        child.stdin_pipe = args.stdin_pipe;
        child.owned_stdin_pipe = args.owned_stdin_pipe;
        child.stdout_pipe = args.stdout_pipe;
        child.owned_stdout_pipe = args.owned_stdout_pipe;
        child.cwd_dir = brk: {
            if (args.cwd) |cwd_str| break :brk try std.fs.openDirAbsolute(cwd_str, .{});
            if (args.cwd_dir) |cwd| break :brk cwd;
            break :brk std.fs.cwd();
        };
        child.env_map = args.env_map;
        child.expand_arg0 = args.expand_arg0;

        const stdout = if (args.stdout_pipe == null) std.ArrayList(u8).init(args.allocator) else null;
        const stderr = std.ArrayList(u8).init(args.allocator);

        return CommandProcess{
            .allocator = args.allocator,
            .child_process = child,
            .stdin_input = args.stdin_input,
            .stdin_pipe = args.stdin_pipe,
            .stdout_pipe = args.stdout_pipe,
            .stdout_array = stdout,
            .stderr_array = stderr,
            .max_output_bytes = args.max_output_bytes,
        };
    }

    pub fn feedStdinInput(this: *CommandProcess, stdin_input: ?[]const u8) !void {
        // credit goes to: https://www.reddit.com/r/Zig/comments/13674ed/help_request_using_stdin_with_childprocess/
        if (stdin_input) |si| {
            // std.debug.print("\ninput of {d} bytes\n", .{si.len});
            if (this.child_process.stdin) |stdin| {
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
                stdin.close();
                std.debug.print("\nfd={d} closed, {?any}\n", .{ stdin.handle, this.child_process.stdin_pipe });
                this.child_process.stdin = null;
            }
        }
    }
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

    stdin_behavior: StdIo,
    stdin: ?std.fs.File,
    stdin_pipe: ?PipeFd,
    owned_stdin_pipe: bool,

    stdout_behavior: StdIo,
    stdout: ?std.fs.File,
    stdout_pipe: ?PipeFd,
    owned_stdout_pipe: bool,

    stderr: ?std.fs.File,
    stderr_behavior: StdIo,

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
            .stdin_behavior = StdIo.Inherit,
            .stdin = null,
            .stdin_pipe = null,
            .owned_stdin_pipe = true,
            .stdout_behavior = StdIo.Inherit,
            .stdout = null,
            .stdout_pipe = null,
            .owned_stdout_pipe = true,
            .stderr = null,
            .stderr_behavior = StdIo.Inherit,
            .env_map = null,
            .cwd = null,
            .uid = null,
            .gid = null,
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
    pub inline fn spawn(self: *ChildProcess) SpawnError!void {
        if (!std.process.can_spawn) {
            @compileError("the target operating system cannot spawn processes");
        }
        return self.spawnPosix();
    }

    pub inline fn spawnAndWait(self: *ChildProcess) SpawnError!Term {
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
        stdout_array: *allowzero std.ArrayList(u8),
        need_stdout: bool,
        stderr_array: *std.ArrayList(u8),
        need_stderr: bool,
        max_output_bytes: usize,
    ) !void {
        if (need_stdout) std.debug.assert(child.stdout_behavior == .Pipe);
        if (need_stderr) std.debug.assert(child.stderr_behavior == .Pipe);

        // we could make this work with multiple allocators but YAGNI
        if (need_stdout and need_stderr) {
            if (stdout_array.allocator.ptr != stderr_array.allocator.ptr or
                stdout_array.allocator.vtable != stderr_array.allocator.vtable)
                @panic("ChildProcess.collectOutput only supports 1 allocator");
        }

        if (need_stdout and need_stderr) {
            std.debug.print("\nneed_stdout and need_stderr, fd={?any},{?any}\n", .{ child.stdout, child.stderr });
            var poller = std.io.poll(stdout_array.allocator, enum { stdout, stderr }, .{
                .stdout = child.stdout.?,
                .stderr = child.stderr.?,
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
        } else if (need_stderr and !need_stdout) {
            std.debug.print("\nneed_stderr, fd={?any}\n", .{child.stderr});
            // var poller = std.io.poll(stderr.allocator, enum { stderr }, .{
            //     .stderr = child.stderr.?,
            // });
            // defer poller.deinit();
            // while (try poller.poll()) {
            //     std.debug.print("\npoller pull 2 {d}..\n", .{poller.fifo(.stderr).count});
            //     if (poller.fifo(.stderr).count > max_output_bytes)
            //         return error.StderrStreamTooLong;
            // }
            // std.debug.print("\nneed_stderr, polled\n", .{});
            // stderr.* = fifoToOwnedArrayList(poller.fifo(.stderr));
            if (child.stderr) |child_stderr| {
                var buf: [4096]u8 = undefined;
                while (true) {
                    // const pos = try child_stderr.getPos();
                    // std.debug.print("\nneed_stderr, fd cur pos={d}\n", .{pos});
                    const read_count = try child_stderr.read(&buf);
                    if (read_count > 0) {
                        try stderr_array.appendSlice(buf[0..read_count]);
                        continue;
                    } else {
                        break;
                    }
                }
            }
        } else {
            @panic("no support for need_stdout only or nothing, should not call");
        }
    }

    pub const RunError = std.os.GetCwdError || std.os.ReadError || SpawnError || std.os.PollError || error{
        StdoutStreamTooLong,
        StderrStreamTooLong,
    };

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

    inline fn handleWaitResult(self: *ChildProcess, status: u32) void {
        self.term = self.cleanupAfterWait(status);
    }

    fn cleanupStreams(self: *ChildProcess) void {
        if (self.stdin) |*stdin| {
            if (self.owned_stdin_pipe) stdin.close();
            self.stdin = null;
        }
        if (self.stdout) |*stdout| {
            if (self.owned_stdout_pipe) stdout.close();
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
        // do we need to consider async io in commands?
        // const pipe_flags = if (std.io.is_async) std.os.O.NONBLOCK else 0;
        const pipe_flags = 0;

        self.stdin_pipe = stdin_brk: {
            if (self.stdin_pipe != null) {
                self.owned_stdin_pipe = false;
                break :stdin_brk self.stdin_pipe;
            } else {
                if (self.stdin_behavior == StdIo.Pipe) {
                    const p = try std.os.pipe2(pipe_flags);
                    std.debug.print("\npipe got={any}\n", .{p});
                    break :stdin_brk p;
                } else break :stdin_brk null;
            }
        };
        errdefer if (self.stdin_pipe != null and self.owned_stdin_pipe) {
            destroyPipe(self.stdin_pipe.?);
        };

        self.stdout_pipe = stdout_brk: {
            if (self.stdout_pipe != null) {
                self.owned_stdout_pipe = false;
                break :stdout_brk self.stdout_pipe;
            } else {
                if (self.stdout_behavior == StdIo.Pipe) {
                    const p = try std.os.pipe2(pipe_flags);
                    std.debug.print("\npipe got={any}\n", .{p});
                    break :stdout_brk p;
                } else break :stdout_brk null;
            }
        };
        errdefer if (self.stdout_pipe != null and self.owned_stdout_pipe) {
            destroyPipe(self.stdout_pipe.?);
        };

        const stderr_pipe = if (self.stderr_behavior == StdIo.Pipe) try std.os.pipe2(pipe_flags) else undefined;
        errdefer if (self.stderr_behavior == StdIo.Pipe) {
            destroyPipe(stderr_pipe);
        };
        std.debug.print("\nstderr pipe, fd={any}\n", .{stderr_pipe});

        const any_ignore = (self.stdin_behavior == StdIo.Ignore or
            self.stdout_behavior == StdIo.Ignore or
            self.stderr_behavior == StdIo.Ignore);
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

        std.debug.print("\nbefore fork {s}: stdin={?any},own_stdin={any}, stdout={?any}, own_stdout={any}\n", .{
            self.argv,
            self.stdin_pipe,
            self.owned_stdin_pipe,
            self.stdout_pipe,
            self.owned_stdout_pipe,
        });

        const pid_result = try std.os.fork();
        if (pid_result == 0) {
            // we are the child
            setUpChildIo(
                self.stdin_behavior,
                if (self.stdin_behavior == .Pipe) self.stdin_pipe.?[0] else undefined,
                std.os.STDIN_FILENO,
                dev_null_fd,
            ) catch |err| forkChildErrReport(err_pipe[1], err);
            if (self.stdin_behavior == .Pipe) {
                std.os.close(self.stdin_pipe.?[0]);
                std.os.close(self.stdin_pipe.?[1]);
            }

            setUpChildIo(
                self.stdout_behavior,
                if (self.stdout_behavior == .Pipe) self.stdout_pipe.?[1] else undefined,
                std.os.STDOUT_FILENO,
                dev_null_fd,
            ) catch |err| forkChildErrReport(err_pipe[1], err);
            if (self.stdout_behavior == .Pipe) {
                std.os.close(self.stdout_pipe.?[0]);
                std.os.close(self.stdout_pipe.?[1]);
            }

            setUpChildIo(
                self.stderr_behavior,
                stderr_pipe[1],
                std.os.STDERR_FILENO,
                dev_null_fd,
            ) catch |err| forkChildErrReport(err_pipe[1], err);
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
            forkChildErrReport(err_pipe[1], err);
        }

        // we are the parent
        const pid = @as(i32, @intCast(pid_result));

        if (self.owned_stdin_pipe) {
            if (self.stdin_behavior == StdIo.Pipe) {
                std.debug.print("\nstdin fd={d} close, fd={d} left\n", .{
                    self.stdin_pipe.?[0],
                    self.stdin_pipe.?[1],
                });
                self.stdin = std.fs.File{ .handle = self.stdin_pipe.?[1] };
                std.os.close(self.stdin_pipe.?[0]);
            } else {
                self.stdin = null;
            }
            std.debug.print("\npid{d} stdin fd={?any}\n", .{ pid, self.stdin });
        } else {
            if (self.stdin_behavior == StdIo.Pipe) {
                self.stdin = std.fs.File{ .handle = self.stdin_pipe.?[0] };
            }
            // std.debug.print("\nstdin close fd={?any}\n", .{self.stdin_pipe});
            // if (self.stdin_pipe) |stdin_pipe| destroyPipe(stdin_pipe);
        }

        if (self.owned_stdout_pipe) {
            if (self.stdout_behavior == StdIo.Pipe) {
                std.debug.print("\nstdout fd={d} close, fd={d} left\n", .{
                    self.stdout_pipe.?[1],
                    self.stdout_pipe.?[0],
                });
                self.stdout = std.fs.File{ .handle = self.stdout_pipe.?[0] };
                std.os.close(self.stdout_pipe.?[1]);
            } else {
                self.stdout = null;
            }
            std.debug.print("\npid{d} stdout fd={?any}\n", .{ pid, self.stdout });
        } else {
            if (self.stdout_behavior == StdIo.Pipe) {
                self.stdout = std.fs.File{ .handle = self.stdout_pipe.?[1] };
            }
            // std.debug.print("\nstdout close fd={?any}\n", .{self.stdout_pipe});
            // if (self.stdout_pipe) |stdout_pipe| destroyPipe(stdout_pipe);
        }

        if (self.stderr_behavior == StdIo.Pipe) {
            std.debug.print("\nstderr fd={d} close, fd={d} left\n", .{
                stderr_pipe[1],
                stderr_pipe[0],
            });
            self.stderr = std.fs.File{ .handle = stderr_pipe[0] };
            std.os.close(stderr_pipe[1]);
        } else {
            self.stderr = null;
        }

        self.id = pid;
        self.err_pipe = err_pipe;
        self.term = null;
    }

    fn setUpChildIo(stdio: StdIo, pipe_fd: i32, std_fileno: i32, dev_null_fd: i32) !void {
        // std.debug.print("\nwill dup2:{d} {d} {any}\n", .{ pipe_fd, std_fileno, stdio });
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
    {
        const result = try runCommandsErr(.{
            .allocator = allocator,
            .commands = &[_][]const []const u8{
                &.{ "cat", "./tests/big_input.txt" },
                &.{ "wc", "-lw" },
                &.{ "wc", "-lw" },
                // &.{ "xargs", "-0", "print", "'result: %s'" },
            },
        });
        defer result.deinit();
        // std.debug.print("\n{?s}\n", .{result.stdout});
        try testing.expectEqualSlices(u8, result.stdout, "    1302    2604\n");
        try testing.expect(result.stderr.len == 0);
    }
    // {
    //     const f = try std.fs.cwd().openFile("./tests/big_input.txt", .{});
    //     defer f.close();
    //     const big_input = try f.readToEndAlloc(allocator, MAX_OUTPUT);
    //     defer allocator.free(big_input);
    //     const result = try runCommandsErr(.{
    //         .allocator = allocator,
    //         .commands = &[_][]const []const u8{
    //             &.{ "grep", "tests" },
    //             &.{ "wc", "-lw" },
    //         },
    //         .stdin_input = big_input,
    //     });
    //     defer result.deinit();
    //     // std.debug.print("\n{?s}\n", .{result.stdout});
    //     try testing.expectEqualSlices(u8, result.stdout, "      12      24\n");
    //     try testing.expect(result.stderr.len == 0);
    // }
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
