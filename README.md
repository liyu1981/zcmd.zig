# zcmd.zig

`zcmd` is a single file lib (`zcmd.zig`) to replace zig's `std.childProcess.run`. It has almost identical API like `std.childProcess.run`, but with the ability of running pipeline like `bash`.

Example like execution of single command (replacement of zig's `std.childProcess.run`)

```zig
const result = try Zcmd.run(.{
    .allocator = allocator,
    .commands = &[_][]const []const u8{
        &.{ "uname", "-a" },
    },
});
```

the differences to `std.childProcess.run` is it will take `commands` instead of single `command`.

It can run a `bash` like pipeline like follows (_to recursively find and list the latest modified files in a directory with subdirectories and times_)

```zig
const result = try Zcmd.run(.{
    .allocator = allocator,
    .commands = &[_][]const []const u8{
        &.{ "find", ".", "-type", "f", "-exec", "stat", "-f", "'%m %N'", "{}", ";" },
        &.{ "sort", "-nr" },
        &.{ "head", "-1" },
    },
});
```

It can also accept an input from outside as stdin to command or command pipeline, like follows

```zig
const f = try std.fs.cwd().openFile("tests/big_input.txt", .{});
defer f.close();
const content = try f.readToEndAlloc(allocator, MAX_OUTPUT);
defer allocator.free(content);
const result = try Zcmd.run(.{
    .allocator = allocator,
    .commands = &[_][]const []const u8{
        &.{"cat"},
        &.{ "wc", "-lw" },
    },
    .stdin_input = content,
});
```

When there is something failed inside pipeline, we will report back `stdout` and `stderr` just like `bash`, like below example

```zig
const result = try Zcmd.run(.{
    .allocator = allocator,
    .commands = &[_][]const []const u8{
        &.{ "find", "nonexist" },
        &.{ "wc", "-lw" },
    },
});
defer result.deinit();
try testing.expectEqualSlices(
    u8,
    result.stdout.?,
    "       0       0\n",
);
try testing.expectEqualSlices(
    u8,
    result.stderr.?,
    "find: nonexist: No such file or directory\n",
);
```

## Usage

### through Zig Package Manager

use following bash in your project folder (with `build.zig.zon`)

```
zig fetch --save https://github.com/liyu1981/zcmd.zig/archive/refs/tags/v0.1.0.tar.gz
```

you can change the version `v0.1.0` to other version if there are in [release](https://github.com/liyu1981/zcmd.zig/releases) page.

### or simply just copy `zcmd.zig` file to your project

It is a single file lib with no dependencies!

## Zig Docs

Zig docs is hosted in github pages at: https://liyu1981.github.io/zcmd.zig/docs/index.html#A;zcmd, please go there to
find what apis `zcmd.zig` provides.

## Coverage

`zcmd.zig` is rigorously tested and my goal is to reach 100%. Visit the coverage report here: https://liyu1981.github.io/zcmd.zig/kcov/index.html
