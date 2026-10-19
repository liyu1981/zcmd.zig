const std = @import("std");

test "stop test" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io_handle = threaded.io();

    const rr = try std.process.run(
        std.testing.allocator,
        io_handle,
        .{
            .argv = &[_][]const u8{"./exit_stop"},
        },
    );
    defer {
        std.testing.allocator.free(rr.stdout);
        std.testing.allocator.free(rr.stderr);
    }
}
