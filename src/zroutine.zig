const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

fn staticCalcMaxWorkerStrategy(comptime limit: usize) anyerror!usize {
    return limit;
}

fn defaultCalcMaxWorkerStrategy() anyerror!usize {
    return try std.Thread.getCpuCount() / 2;
}

pub const CalcMaxWorkerStrategy = *const fn () anyerror!usize;

fn defineRoutineMgr(comptime RoutineFnType: type) type {
    const VoidType = @TypeOf(void);
    const RoutineFnArgsType = brk: {
        switch (@typeInfo(RoutineFnType)) {
            .Pointer => |ti| switch (@typeInfo(ti.child)) {
                .Fn => |fti| {
                    if (fti.params.len <= 0) {
                        break :brk VoidType;
                    } else if (fti.params.len == 1) {
                        break :brk fti.params[0].type.?;
                    } else @compileError("RoutineFn can only have one union param args. Define your routine like fn routine(args: union { a: usize, b: []const u8 })");
                },
                else => {
                    @compileError("RoutineFnType must be function pointer.");
                },
            },
            else => {
                @compileError("RoutineFnType must be function pointer.");
            },
        }
    };

    return struct {
        const Self = @This();

        const RoutineQ = std.DoublyLinkedList(RoutineEntry);
        pub const RoutineEntry = struct {
            rfn: RoutineFnType,
            rfn_args: RoutineFnArgsType = undefined,
        };

        const RoutineMgrThread = struct {
            allocator: std.mem.Allocator,
            id: usize,
            localq: RoutineQ,
            busy: bool = false,
            should_exit: bool = false,
            thread: std.Thread = undefined,
            mutex: std.Thread.Mutex,
            cond: std.Thread.Condition,
        };

        allocator: std.mem.Allocator,
        WORKER_MAX: usize = 0,
        calc_max_worker_strategy: CalcMaxWorkerStrategy,
        worker_threads: []RoutineMgrThread = undefined,
        worker_threads_initialized: bool = false,

        pub fn init(allocator: std.mem.Allocator, calc_worker_max_strategy: ?CalcMaxWorkerStrategy) Self {
            return Self{
                .allocator = allocator,
                .calc_max_worker_strategy = if (calc_worker_max_strategy) |cwms| cwms else defaultCalcMaxWorkerStrategy,
            };
        }

        pub fn deinit(this: *Self) void {
            _ = this;
        }

        fn initWorkerThreads(this: *Self) !void {
            this.WORKER_MAX = if (builtin.is_test) 2 else try this.calc_max_worker_strategy();
            this.worker_threads = try this.allocator.alloc(RoutineMgrThread, this.WORKER_MAX);
            for (0..this.WORKER_MAX) |i| {
                this.worker_threads[i] = RoutineMgrThread{
                    .allocator = this.allocator,
                    .id = i,
                    .localq = RoutineQ{},
                    .mutex = std.Thread.Mutex{},
                    .cond = std.Thread.Condition{},
                };
                this.worker_threads[i].thread = try std.Thread.spawn(.{}, workerMgrFn, .{&this.worker_threads[i]});
            }
            this.worker_threads_initialized = true;
        }

        fn workerMgrFn(ctx: *RoutineMgrThread) !void {
            std.debug.print("\nworker start!\n", .{});
            while (true) {
                ctx.mutex.lock();
                defer ctx.mutex.unlock();

                if (ctx.localq.len == 0 and !ctx.should_exit)
                    continue;

                const maybe_e = ctx.localq.popFirst();
                if (maybe_e) |entry| {
                    defer ctx.allocator.destroy(entry);
                    ctx.busy = true;
                    ctx.mutex.unlock();
                    if (RoutineFnArgsType == VoidType) {
                        try entry.data.rfn();
                    } else {
                        try entry.data.rfn(entry.data.rfn_args);
                    }
                    ctx.mutex.lock();
                    ctx.busy = false;
                }

                if (ctx.localq.len == 0 and ctx.should_exit)
                    break;
            }
        }

        fn schedule(this: *Self) usize {
            var ret: usize = 0;
            var min_qlen = this.worker_threads[0].localq.len + 1;
            for (1..this.WORKER_MAX) |i| {
                if (this.worker_threads[i].localq.len + 1 < min_qlen) {
                    ret = i;
                    min_qlen = this.worker_threads[i].localq.len + 1;
                }
            }
            return ret;
        }

        pub fn spawn(this: *Self, rfn: RoutineFnType, args: anytype) !usize {
            if (!this.worker_threads_initialized) {
                try this.initWorkerThreads();
            }

            const i = this.schedule();

            var fw_ = &this.worker_threads[i];
            fw_.mutex.lock();
            defer fw_.mutex.unlock();
            var n = try fw_.allocator.create(RoutineQ.Node);
            if (RoutineFnArgsType == VoidType) {
                n.data = .{ .rfn = rfn };
            } else {
                n.data = .{ .rfn = rfn, .rfn_args = args };
            }
            fw_.localq.append(n);
            std.debug.print("\nenqueue to localq of worker {d}\n", .{fw_.id});

            return 0;
        }

        pub fn join(this: *Self) void {
            if (this.worker_threads_initialized) {
                for (0..this.WORKER_MAX) |i| {
                    this.worker_threads[i].mutex.lock();
                    defer this.worker_threads[i].mutex.unlock();
                    this.worker_threads[i].should_exit = true;
                }
                for (0..this.WORKER_MAX) |i| {
                    this.worker_threads[i].thread.join();
                }
            }
            this.allocator.free(this.worker_threads);
            this.worker_threads_initialized = false;
        }
    };
}

// all tests

const TestArgs = union {
    msg: []const u8,
    count: usize,
};

fn testRfn1(args: TestArgs) anyerror!void {
    std.debug.print("\ntestRfn1: {s} from thread: {d}\n", .{ args.msg, std.Thread.getCurrentId() });
}

fn testRfn2(args: TestArgs) anyerror!void {
    std.debug.print("\ntestRfn2: {d} from thread: {d}\n", .{ args.count, std.Thread.getCurrentId() });
}

test "simple" {
    const RoutineMgr = defineRoutineMgr(*const fn (args: TestArgs) anyerror!void);
    var rmgr = RoutineMgr.init(testing.allocator, null);
    defer rmgr.deinit();
    _ = try rmgr.spawn(testRfn1, .{ .msg = "hello" });
    _ = try rmgr.spawn(testRfn2, .{ .count = 8 });
    _ = try rmgr.spawn(testRfn2, .{ .count = 18 });
    rmgr.join();
}
