const std = @import("std");
const linux = std.os.linux;
const buildInfo = @import("build_generated");

fn print(comptime msg: []const u8) void {
    _ = linux.write(std.posix.STDOUT_FILENO, msg.ptr, msg.len);
}

pub fn main() !void {
    print("Hello!\nversion: ");
    print(buildInfo.version);
    print("\nbuilt os: ");
    print(buildInfo.built_os);
    print("\n");
}
