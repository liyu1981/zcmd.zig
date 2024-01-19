## example: using `zcmd` in `build.zig` zig app

`zcmd` also exposed itself for using inside `build.zig`

### fetch `zcmd` and update `build.zig.zon`

(in folder `zcmd_app`)

```zig
zig fetch --save zig fetch --save https://github.com/liyu1981/zcmd.zig/archive/refs/tags/v0.2.1.tar.gz
```

### build run

```zig
zig build run
```

You will notice that `src/build_generated.zig` is auto generated during build, and it will provide `version` from git history and `built_os` from command `uname -a`.

Read `build.zig` and `src/main.zig` for detail usage.
