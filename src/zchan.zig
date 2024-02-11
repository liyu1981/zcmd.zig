const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const s2s = @import("s2s.zig");

pub fn Chan(comptime DataType: type) type {
    return struct {
        const Self = @This();
        const MIN_BUF_SIZE = if (builtin.is_test) 64 else 16 * std.mem.page_size;

        allocator: std.mem.Allocator,
        task_buf: std.ArrayList(u8),
        task_head: usize,
        task_buf_head: usize,
        task_count: usize,
        mutex: std.Thread.Mutex,
        cond: std.Thread.Condition,

        pub fn init(allocator: std.mem.Allocator) !Self {
            var c = Self{
                .allocator = allocator,
                .task_buf = std.ArrayList(u8).init(allocator),
                .task_head = 0,
                .task_buf_head = 0,
                .task_count = 0,
                .mutex = std.Thread.Mutex{},
                .cond = std.Thread.Condition{},
            };
            try c.task_buf.ensureTotalCapacityPrecise(MIN_BUF_SIZE);
            return c;
        }

        pub fn deinit(this: *const Self) void {
            defer this.task_buf.deinit();
            // TODO: should we release the lock here?
        }

        pub fn free(this: *const Self, data_: *DataType) void {
            s2s.free(this.allocator, DataType, data_);
        }

        fn _appendTask(this: *Self, task_value_: *const DataType) !void {
            var tmpbuf = std.ArrayList(u8).init(this.allocator);
            defer tmpbuf.deinit();

            const size_start = tmpbuf.items.len;
            try tmpbuf.append(0);
            try tmpbuf.append(0);
            try tmpbuf.append(0);
            try tmpbuf.append(0);

            const serialized_start = tmpbuf.items.len;
            try s2s.serialize(tmpbuf.writer(), DataType, task_value_.*);
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

        pub fn appendTask(this: *Self, task_value_: *const DataType) !void {
            this.mutex.lock();
            defer this.mutex.unlock();

            try this._appendTask(task_value_);

            const old_task_count = this.task_count;
            while (this.task_count >= old_task_count) {
                this.cond.wait(&this.mutex);
            }
        }

        fn _popTask(this: *Self) !DataType {
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
            const ch_data = try s2s.deserializeAlloc(seralized_data.reader(), DataType, this.allocator);

            this.task_head += 4 + @as(usize, @intCast(json_len));
            this.task_count -= 1;

            if (this.task_buf_head - this.task_head < (this.task_buf.capacity / 2) and this.task_buf.capacity > MIN_BUF_SIZE) {
                try this.shrinkTaskBufCapacityByHalf();
            }

            return ch_data;
        }

        pub fn popTask(this: *Self) !DataType {
            while (true) {
                if (this.task_head == this.task_buf_head)
                    continue;

                this.mutex.lock();
                defer this.mutex.unlock();

                this.cond.signal();
                return try this._popTask();
            }
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

        pub fn spawn(this: *Self, comptime rfunc: ChanRoutineFn(DataType)) !std.Thread {
            return try std.Thread.spawn(.{}, rfunc, .{this});
        }
    };
}

pub inline fn makeChan(comptime DataType: type, allocator: std.mem.Allocator) !Chan(DataType) {
    return try Chan(DataType).init(allocator);
}

pub fn ChanRoutineFn(comptime DataType: type) type {
    return fn (chan: *Chan(DataType)) anyerror!void;
}

// all tests

const TestT1 = struct { a: i32, b: []const u8 };

const TestT2 = struct { a: i32, b: i32, c: i32 };

fn testChanFunc(chan: *Chan(TestT2)) anyerror!void {
    std.debug.print("\nstarted thread!\n", .{});
    var t = try chan.popTask();
    defer chan.free(&t);
    std.debug.print("\npoped: {any}\n", .{t});
    try chan.appendTask(&.{
        .a = t.a,
        .b = t.b,
        .c = t.a + t.b,
    });
}

test "_appendTask/_popTask" {
    var ch = try makeChan(TestT1, testing.allocator);
    defer ch.deinit();
    const t1 = .{ .a = 1, .b = "hello" };
    const t2 = .{ .a = 2, .b = "world" };
    try ch._appendTask(&t1);
    try ch._appendTask(&t2);
    {
        var t = try ch._popTask();
        defer ch.free(&t);
        try testing.expectEqual(t.a, 1);
        try testing.expectEqualSlices(u8, t.b, "hello");
    }
    {
        var t = try ch._popTask();
        defer ch.free(&t);
        try testing.expectEqual(t.a, 2);
        try testing.expectEqualSlices(u8, t.b, "world");
    }
}

test "appendTask/popTask" {
    var ch = try makeChan(TestT2, testing.allocator);
    defer ch.deinit();
    const t1 = .{ .a = 1, .b = 2, .c = 0 };
    _ = try ch.spawn(testChanFunc);
    try ch.appendTask(&t1);
    var t = try ch.popTask();
    defer ch.free(&t);
    try testing.expectEqual(t.c, 3);
}
