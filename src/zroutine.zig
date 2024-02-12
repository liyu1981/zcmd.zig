const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

const Self = @This();

const RoutineFn = *const fn () anyerror!void;

const RoutineEntry = struct {
    rfn: RoutineFn,
};

const RoutineQ = std.DoublyLinkedList(RoutineEntry);

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

var ga: std.mem.Allocator = undefined;
var WORKER_MAX: usize = 0;
var worker_threads: []RoutineMgrThread = undefined;
var worker_threads_initialized: bool = false;

fn initWorkerThreads(allocator: std.mem.Allocator) !void {
    ga = allocator;
    WORKER_MAX = if (builtin.is_test) 2 else try std.Thread.getCpuCount() / 2;
    worker_threads = try ga.alloc(RoutineMgrThread, WORKER_MAX);
    for (0..WORKER_MAX) |i| {
        worker_threads[i] = RoutineMgrThread{
            .allocator = allocator,
            .id = i,
            .localq = RoutineQ{},
            .mutex = std.Thread.Mutex{},
            .cond = std.Thread.Condition{},
        };
        worker_threads[i].thread = try std.Thread.spawn(.{}, workerMgrFn, .{&worker_threads[i]});
    }
    worker_threads_initialized = true;
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
            try entry.data.rfn();
            ctx.busy = false;
        }

        if (ctx.localq.len == 0 and ctx.should_exit)
            break;
    }
}

fn schedule() usize {
    var ret: usize = 0;
    var min_qlen = worker_threads[0].localq.len + 1;
    for (1..WORKER_MAX) |i| {
        if (worker_threads[i].localq.len + 1 < min_qlen) {
            ret = i;
            min_qlen = worker_threads[i].localq.len + 1;
        }
    }
    return ret;
}

pub fn go(rfn: RoutineFn) !usize {
    if (!worker_threads_initialized) {
        try initWorkerThreads(ga);
    }

    const i = schedule();

    var fw_ = &worker_threads[i];
    fw_.mutex.lock();
    defer fw_.mutex.unlock();
    var n = try fw_.allocator.create(RoutineQ.Node);
    n.data = .{ .rfn = rfn };
    fw_.localq.append(n);
    std.debug.print("\nenqueue to localq of worker {d}\n", .{fw_.id});

    return 0;
}

pub fn join() void {
    if (worker_threads_initialized) {
        for (0..WORKER_MAX) |i| {
            worker_threads[i].mutex.lock();
            defer worker_threads[i].mutex.unlock();
            worker_threads[i].should_exit = true;
        }
        for (0..WORKER_MAX) |i| {
            worker_threads[i].thread.join();
        }
    }
    ga.free(worker_threads);
    worker_threads_initialized = false;
}

// all tests

fn testFn1() anyerror!void {
    std.debug.print("\ntestFn1 from thread: {d}\n", .{std.Thread.getCurrentId()});
}

fn testFn2() anyerror!void {
    std.debug.print("\ntestFn2 from thread: {d}\n", .{std.Thread.getCurrentId()});
}

test "start" {
    ga = testing.allocator;
    _ = try go(testFn1);
    _ = try go(testFn2);
    _ = try go(testFn2);
    join();
}
