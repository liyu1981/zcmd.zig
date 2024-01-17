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
            unreachable
            // Term{ .Stopped = std.os.W.STOPSIG(status) }
        else
            unreachable;
        // Term{ .Unknown = status };
    }
};

pub const StdIo = enum {
    Inherit,
    Ignore,
    Pipeline,
    Pipe,
    Close,
};

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

pub const Zcmd = struct {
    pub fn run(allocator: std.mem.Allocator, commands: []const []const []const u8) !SingleRunResult {
        const pipe = try std.os.pipe2(0);
        const pid_result = try std.os.fork();
        if (pid_result == 0) {
            // we are child
            try std.os.dup2(pipe[1], std.os.STDOUT_FILENO);
            std.os.close(pipe[0]);
            std.os.close(pipe[1]);
            try Zcmd._run(allocator, commands);
            std.os.exit(0);
        } else {
            // we are parent
            std.os.close(pipe[1]);
            var stdout_f = std.fs.File{ .handle = pipe[0] };
            const out = try stdout_f.readToEndAlloc(allocator, MAX_OUTPUT);
            const result = std.os.waitpid(pid_result, 0);
            return SingleRunResult{
                .allocator = allocator,
                .term = Term.fromStatus(result.status),
                .stdout = out,
            };
        }
    }

    fn _run(allocator: std.mem.Allocator, commands: []const []const []const u8) !void {
        // here we create a pipe then fork a copy of ourself, but instead of executing command, we do it in parent, and
        // let child to prepare for next environment. Using an example command pipelien
        // `cat ./tests/big_input.txt | wc -lw | wc-lw`, we will
        // 1. fork and let ourself do next command (which is `cat ...`)
        // 2. let forked children to bridge STDIN <-> pipe[0] then go to step (next command then become `wc` then `wc`
        //    then nothing so we get out of for loop)
        // the whole pipeline still use STDIN as input and STDOUT as output, so if we wrap this again, we can capture
        // the io streams
        for (commands, 0..) |next_command, i| {
            const pipe_flags = 0;
            var pipe = try std.os.pipe2(pipe_flags);
            const pid_result = try std.os.fork();
            if (pid_result == 0) {
                // we are child
                try std.os.dup2(pipe[0], std.os.STDIN_FILENO);
                std.os.close(pipe[0]);
                std.os.close(pipe[1]);
                pipe = try std.os.pipe2(pipe_flags);
            } else {
                // we are parent
                // std.debug.print("\nwill run command: {s}:{d}\n", .{ next_command, i });
                if (i + 1 != commands.len) {
                    try std.os.dup2(pipe[1], std.os.STDOUT_FILENO);
                }
                std.os.close(pipe[0]);
                std.os.close(pipe[1]);
                Zcmd.executeCommand(allocator, next_command);
            }
        }
    }

    fn executeCommand(allocator: std.mem.Allocator, command: []const []const u8) noreturn {
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
        const argv_buf = arena.allocSentinel(?[*:0]const u8, command.len, null) catch unreachable;
        for (command, 0..) |arg, i| {
            const duped = arena.dupeZ(u8, arg) catch unreachable;
            argv_buf[i] = duped.ptr;
        }

        const envp = @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.environ.ptr));
        std.os.execvpeZ_expandArg0(
            .no_expand,
            argv_buf.ptr[0].?,
            argv_buf.ptr,
            envp,
        ) catch {};
        unreachable;
    }
};

test "default" {
    const allocator = std.testing.allocator;
    {
        try Zcmd.run(allocator, &[_][]const []const u8{
            &.{ "cat", "./tests/big_input.txt" },
            &.{ "wc", "-lw" },
            &.{ "wc", "-lw" },
        });
    }
}

pub fn main() !u8 {
    const allocator = std.heap.page_allocator;
    const result = try Zcmd.run(allocator, &[_][]const []const u8{
        &.{ "cat", "./tests/big_input.txt" },
        &.{ "wc", "-lw" },
        &.{ "wc", "-lw" },
    });
    defer result.deinit();
    std.debug.print("\n{any}: {?s}\n", .{ result.term, result.stdout });
    return 0;
}
