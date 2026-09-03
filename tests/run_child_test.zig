const std = @import("std");

test "stop test" {
    var io = std.Io.Threaded.init(.{}) catch return;
    defer io.deinit();
    const io_handle = io.io();

    const rr = try std.process.run(
        @import("std").testing.allocator,
        io_handle,
        .{
            .argv = &[_][]const u8{"./exit_stop"},
        },
    );
    defer {
        @import("std").testing.allocator.free(rr.stdout);
        @import("std").testing.allocator.free(rr.stderr);
    }
    _ = rr;
}
