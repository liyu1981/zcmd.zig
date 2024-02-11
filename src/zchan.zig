const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const s2s = @import("s2s.zig");

fn defineChan(comptime TaskType: type) type {
    return struct {
        const Self = @This();
        const MIN_BUF_SIZE = if (builtin.is_test) 64 else 16 * std.mem.page_size;

        const PopTaskValue = struct {
            allocator: std.mem.Allocator,
            task: TaskType,

            pub fn deinit(this: *PopTaskValue) void {
                s2s.free(this.allocator, TaskType, &this.task);
            }
        };

        allocator: std.mem.Allocator,
        task_buf: std.ArrayList(u8),
        task_head: usize,
        task_buf_head: usize,
        task_count: usize,
        mutex: std.Thread.Mutex,

        pub fn init(allocator: std.mem.Allocator) !Self {
            var c = Self{
                .allocator = allocator,
                .task_buf = std.ArrayList(u8).init(allocator),
                .task_head = 0,
                .task_buf_head = 0,
                .task_count = 0,
                .mutex = std.Thread.Mutex{},
            };
            try c.task_buf.ensureTotalCapacityPrecise(MIN_BUF_SIZE);
            return c;
        }

        pub fn deinit(this: *const Self) void {
            defer this.task_buf.deinit();
            // TODO: should we release the lock here?
        }

        pub fn appendTask(this: *Self, taskValue: *const TaskType) !void {
            var tmpbuf = std.ArrayList(u8).init(this.allocator);
            defer tmpbuf.deinit();

            const size_start = tmpbuf.items.len;
            try tmpbuf.append(0);
            try tmpbuf.append(0);
            try tmpbuf.append(0);
            try tmpbuf.append(0);

            const serialized_start = tmpbuf.items.len;
            try s2s.serialize(tmpbuf.writer(), TaskType, taskValue.*);
            const serialized_len: u64 = @intCast(tmpbuf.items.len - serialized_start);

            tmpbuf.items[size_start] = @intCast(serialized_len >> 24);
            tmpbuf.items[size_start + 1] = @intCast(serialized_len >> 16);
            tmpbuf.items[size_start + 2] = @intCast(serialized_len >> 8);
            tmpbuf.items[size_start + 3] = @intCast(serialized_len);

            try this.ensureTaskBufIncrementalCapacity(tmpbuf.items.len);
            try this.task_buf.appendSlice(tmpbuf.items);

            this.task_buf_head += tmpbuf.items.len;
            this.task_count += 1;
        }

        pub fn popTask(this: *Self) !?PopTaskValue {
            if (this.task_head == this.task_buf_head)
                return null;

            var head = this.task_head;
            var json_len: u64 = (@as(u64, @intCast(this.task_buf.items[head])) << 24);
            head += 1;
            json_len |= (@as(u64, @intCast(this.task_buf.items[head])) << 16);
            head += 1;
            json_len |= (@as(u64, @intCast(this.task_buf.items[head])) << 8);
            head += 1;
            json_len |= (@as(u64, @intCast(this.task_buf.items[head])));
            head += 1;

            var seralized_data = std.io.fixedBufferStream(this.task_buf.items[head .. head + @as(usize, @intCast(json_len))]);
            const task = try s2s.deserializeAlloc(seralized_data.reader(), TaskType, this.allocator);

            this.task_head += 4 + @as(usize, @intCast(json_len));
            this.task_count -= 1;

            if (this.task_buf_head - this.task_head < (this.task_buf.capacity / 2) and this.task_buf.capacity > MIN_BUF_SIZE) {
                try this.shrinkTaskBufCapacityByHalf();
            }

            return .{
                .allocator = this.allocator,
                .task = task,
            };
        }

        fn ensureTaskBufIncrementalCapacity(this: *Self, incremental_len: usize) !void {
            if (this.task_buf_head + incremental_len < this.task_buf.capacity) {
                return;
            }

            const new_len = this.task_buf.capacity * 2;
            try this.task_buf.ensureTotalCapacityPrecise(new_len);
        }

        fn shrinkTaskBufCapacityByHalf(this: *Self) !void {
            const new_cap = this.task_buf.capacity / 2;
            var new_array = std.ArrayList(u8).init(this.allocator);
            try new_array.ensureTotalCapacityPrecise(new_cap);
            try new_array.appendSlice(this.task_buf.items[this.task_head..this.task_buf_head]);
            const old_buf_len = this.task_buf_head - this.task_head;
            const old_buf = this.task_buf;
            defer old_buf.deinit();
            this.task_buf = new_array;
            this.task_head = 0;
            this.task_buf_head = old_buf_len;
        }
    };
}

pub inline fn makeChan(comptime TaskType: type, allocator: std.mem.Allocator) !defineChan(TaskType) {
    return try defineChan(TaskType).init(allocator);
}

fn defineChanRoutineFn(comptime TaskType: type) type {
    return fn (chan: *defineChan(TaskType)) anyerror!void;
}

pub fn spawn(comptime TaskType: type, chan: *defineChan(TaskType), comptime rfunc: defineChanRoutineFn(TaskType)) !std.Thread {
    return try std.Thread.spawn(.{}, rfunc, .{chan});
}

const TestT1 = struct { a: i32, b: []const u8 };

const TestT2 = struct { a: i32, b: i32, c: i32 };

fn testChanFunc(chan: *defineChan(TestT2)) anyerror!void {
    std.debug.print("\nstarted thread!\n", .{});
    var maybe_t = try chan.popTask();
    // var result: TestT2 = .{
    //     .a = 0,
    //     .b = 0,
    //     .c = 0,
    // };
    if (maybe_t) |t| {
        defer maybe_t.?.deinit();
        std.debug.print("\npoped: {any}\n", .{t.task});
        // result.a = t.task.a;
        // result.b = t.task.b;
        // result.c = t.task.a + t.task.b;
        try chan.appendTask(&.{
            .a = t.task.a,
            .b = t.task.b,
            .c = t.task.a + t.task.b,
        });
    }
    // try chan.appendTask(&result);
}

test "makeChan" {
    {
        var ch = try makeChan(TestT1, testing.allocator);
        defer ch.deinit();
        const t1 = .{ .a = 1, .b = "hello" };
        const t2 = .{ .a = 2, .b = "world" };
        try ch.appendTask(&t1);
        try ch.appendTask(&t2);
        var maybe_t = try ch.popTask();
        try testing.expect(maybe_t != null);
        if (maybe_t) |t| {
            defer maybe_t.?.deinit();
            try testing.expectEqual(t.task.a, 1);
            try testing.expectEqualSlices(u8, t.task.b, "hello");
        }
        maybe_t = try ch.popTask();
        try testing.expect(maybe_t != null);
        if (maybe_t) |t| {
            defer maybe_t.?.deinit();
            try testing.expectEqual(t.task.a, 2);
            try testing.expectEqualSlices(u8, t.task.b, "world");
        }
        maybe_t = try ch.popTask();
        try testing.expect(maybe_t == null);
    }

    {
        var ch = try makeChan(TestT2, testing.allocator);
        defer ch.deinit();
        const t1 = .{ .a = 1, .b = 2, .c = 0 };
        try ch.appendTask(&t1);
        var thread = try spawn(TestT2, &ch, testChanFunc);
        thread.join();
        var maybe_t = try ch.popTask();
        try testing.expect(maybe_t != null);
        if (maybe_t) |t| {
            defer maybe_t.?.deinit();
            try testing.expectEqual(t.task.c, 3);
        }
    }
}
