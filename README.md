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

Please check [example/zcmd_app](https://github.com/liyu1981/zcmd.zig/tree/main/example/zcmd_app) for an example on how to use `zcmd.zig`.

### use `zcmd.zig` in `build.zig`

Originally `zcmd.zig` is functions I wrote in `build.zig` to auto generating files with commands, so it is important that can use this in `build.zig`. So `zcmd.zig` exposed itself for `build.zig` too.

To use that we will need to normally introduce `zcmd.zig` to `build.zig.zon` (see Usage below). Then in your `build.zig`, do following to use it

```zig
// when import in build.zig, the zcmd is exposed in nested const zcmd
const zcmd = @import("zcmd").zcmd;
// then next can use zcmd.run as above
```

Please check [example/zcmd_build_app](https://github.com/liyu1981/zcmd.zig/tree/main/example/zcmd_build_app) for detail version how to use in this way.

## Usage

### through Zig Package Manager

use following bash in your project folder (with `build.zig.zon`)

```
zig fetch --save https://github.com/liyu1981/zcmd.zig/archive/refs/tags/v0.2.2.tar.gz
```

you can change the version `v0.1.0` to other version if there are in [release](https://github.com/liyu1981/zcmd.zig/releases) page.

### or simply just copy `zcmd.zig` file to your project

It is a single file lib with no dependencies!

## Zig Docs

Zig docs is hosted in github pages at: https://liyu1981.github.io/zcmd.zig/docs/index.html#A;zcmd, please go there to
find what apis `zcmd.zig` provides.

## Coverage

`zcmd.zig` is rigorously tested. Run unit tests at repo checkout root folder with `zig test src/zcmd.zig`.

For coverage test, as `kcov` is working in a way of 'debug every line and record', it can not work with `zcmd` tests. `zcmd` tests will fork many sub processes and if one of them be stopped the whole pipeline hangs. I am still in searching of what's the best method to cover.
