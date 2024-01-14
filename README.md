# zcmd.zig

`zcmd` is a single file lib (`zcmd.zig`) to wrap `std.childProcess` for easier execution of external programs, or pipe
of external programs.

Example like execution of simple commands

```zig
const result = runCommandAndGetResult(.{
    .allocator = allocator,
    .command = &[_][]const u8{ "uname", "-a" },
}, "test uname -a");
```

or using several simple commands piped to each other for complex jobs (just like in bash)

```zig
var result = runPipedCommandAndGetResult(.{
    .allocator = allocator,
    .commands = &[_][]const []const u8{
        &.{ "find", ".", "-type", "f", "-exec", "stat", "-f", "'%m %N'", "{}", ";" },
        &.{ "sort", "-nr" },
        &.{"head"},
    },
}, "recursively find and list the latest modified files in a directory with subdirectories and times");
```

`zcmd` provides 2 flavors of functions, with suffix `Err` apis will generally return error when found it, and without
suffix `Err` apis will not return error and try best to just return result, or `@panic` if something bad happens.
The former ones is suitable for dynamic commands execution (as can nov valid before execution), and the latter ones is
suitable for fixed commands execution (like in scripts).

`zcmd`'s api also introduced `stop_on_any_error` and `stop_on_any_stderr` options for control of piped commands flow a
bit. Like in following example

```zig
const result = try runPipedCommandsAndGetResultErr(.{
    .allocator = allocator,
    .commands = &[_][]const []const u8{
        &.{"./tests/exit_sigabrt"},
        &.{ "uname", "-a" },
    },
    .stop_on_any_error = false,
});
```

We will be able to get the second "uname -a" result even that the first command will fail.

## Usage

### through Zig Package Manager

add following lines to your `build.zig.zon` dependencies

```zig

```

### or simply just copy `zcmd.zig` file to your project

It is a single file lib with no dependencies!

## Zig Docs

Zig docs is hosted in github pages at: https://liyu1981.github.io/zcmd.zig/docs/index.html#A;zcmd, please go there to
find what apis `zcmd.zig` provides.

## Coverage

`zcmd.zig` is rigorously tested and my goal is to reach 100%. Visit the coverage report here: https://liyu1981.github.io/zcmd.zig/kcov/index.html
