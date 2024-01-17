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

pub const Term = union(enum) {
    Exited: u8,
    Signal: u32,
    Stopped: u32,
    Unknown: u32,

    fn fromStatus(status: u32) Term {
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
    OutOfMemory,

    InputOutput,
    BrokenPipe,
    OperationAborted,
    WouldBlock,
    ConnectionResetByPeer,
    NetworkSubsystemFailed,
    ConnectionTimedOut,
    NotOpenForReading,
    SocketNotConnected,
    NetNameDeleted,

    Unexpected,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    AccessDenied,
    IsDir,
};

pub const RunResult = struct {
    allocator: std.mem.Allocator,

    term: Term = undefined,
    stdout: ?[]const u8 = null,
    stderr: ?[]const u8 = undefined,

    pub fn deinit(this: *const RunResult) void {
        if (this.stdout) |stdout_slice| this.allocator.free(stdout_slice);
        if (this.stderr) |stderr_slice| this.allocator.free(stderr_slice);
    }
};

const Zcmd = @This();

const ZcmdArgs = struct {
    allocator: std.mem.Allocator,
    commands: []const []const []const u8,
    stdin_input: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    cwd_dir: ?std.fs.Dir = null,
    env_map: ?*const std.process.EnvMap = null,
    max_output_bytes: usize = MAX_OUTPUT,
    expand_arg0: std.ChildProcess.Arg0Expand = .no_expand,
};

pub fn run(args: ZcmdArgs) ZcmdError!RunResult {
    const stdout_pipe = try std.os.pipe2(0);
    const stderr_pipe = try std.os.pipe2(0);
    const err_pipe = try std.os.pipe2(0);
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
        Zcmd._run(args) catch |err| forkChildErrReport(err_pipe[1], err);
        std.os.exit(0);
    } else {
        // we are parent
        std.os.close(stdout_pipe[1]);
        std.os.close(stderr_pipe[1]);

        var poller = std.io.poll(args.allocator, enum { stdout, stderr }, .{
            .stdout = std.fs.File{ .handle = stdout_pipe[0] },
            .stderr = std.fs.File{ .handle = stderr_pipe[0] },
        });
        defer poller.deinit();
        while (try poller.poll()) {}
        var stdout_array = fifoToOwnedArrayList(poller.fifo(.stdout));
        var stderr_array = fifoToOwnedArrayList(poller.fifo(.stderr));

        try writeIntFd(err_pipe[1], std.math.maxInt(ErrInt));
        const err_int = try readIntFd(err_pipe[0]);
        defer {
            std.os.close(err_pipe[0]);
            std.os.close(err_pipe[1]);
        }
        if (err_int != std.math.maxInt(ErrInt)) {
            return @as(ZcmdError, @errorCast(@errorFromInt(err_int)));
        }

        // var stdout_f = std.fs.File{ .handle = stdout_pipe[0] };
        // // defer std.os.close(stdout_pipe[0]);
        // const out = try stdout_f.readToEndAlloc(allocator, MAX_OUTPUT);
        const result = std.os.waitpid(pid_result, 0);
        return RunResult{
            .allocator = args.allocator,
            .term = Term.fromStatus(result.status),
            .stdout = try stdout_array.toOwnedSlice(),
            .stderr = try stderr_array.toOwnedSlice(),
        };
    }
}

pub fn _run(args: ZcmdArgs) !void {
    // here we create a pipe then fork a copy of ourself, but instead of executing command, we do it in parent, and
    // let child to prepare for next environment. Using an example command pipelien
    // `cat ./tests/big_input.txt | wc -lw | wc-lw`, we will
    // 1. fork and let ourself do next command (which is `cat ...`)
    // 2. let forked children to bridge STDIN <-> pipe[0] then go to step (next command then become `wc` then `wc`
    //    then nothing so we get out of for loop)
    // the whole pipeline still use STDIN as input and STDOUT as output, so if we wrap this again, we can capture
    // the io streams
    for (args.commands, 0..) |next_command, i| {
        const pipe_flags = 0;
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
            Zcmd.executeCommand(args.allocator, next_command) catch |err| {
                std.io.getStdErr().writer().print("zig: {any}: {s}\n", .{ err, next_command }) catch {};
                std.os.exit(1);
            };
        }
    }
}

fn executeCommand(allocator: std.mem.Allocator, command: []const []const u8) !void {
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

    const envp = @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.environ.ptr));
    const exec_error = std.os.execvpeZ_expandArg0(
        .no_expand,
        argv_buf.ptr[0].?,
        argv_buf.ptr,
        envp,
    );
    return exec_error;
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

// Child of fork calls this to report an error to the fork parent.
// Then the child exits.
fn forkChildErrReport(fd: i32, err: ZcmdError) noreturn {
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

fn _testIsError(comptime T: type, maybe_value: anyerror!T, expected_error: anyerror) bool {
    if (maybe_value) |_| {
        return false;
    } else |err| {
        return err == expected_error;
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
        try testing.expectEqualSlices(
            u8,
            result.stdout.?,
            "    1302    2604\n",
        );
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
        try testing.expectEqualSlices(u8, result.stdout.?, "       0       0\n");
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
        try testing.expectEqualSlices(u8, result.stdout.?, "       0       0\n");
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
        try testing.expectEqualSlices(u8, result.stdout.?, "       0       0\n");
        try testing.expectEqualSlices(
            u8,
            result.stderr.?,
            "find: nonexist: No such file or directory\n",
        );
    }
}
