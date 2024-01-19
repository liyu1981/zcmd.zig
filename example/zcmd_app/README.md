## example: using `zcmd` in zig app

### fetch `zcmd` and update `build.zig.zon`

(in folder `zcmd_app`)

```zig
zig fetch --save zig fetch --save https://github.com/liyu1981/zcmd.zig/archive/refs/tags/v0.2.1.tar.gz
```

### build run

```zig
zig build run
```
