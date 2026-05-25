# Adding as a dependency

## `build.zig.zon`

Point at a path or git revision:

```zig
.{
    .name = .my_app,
    .version = "0.1.0",
    .dependencies = .{
        .neofs_sdk_zig = .{
            .path = "../neofs-sdk-zig", // or .url + .hash for git
        },
    },
}
```

Run `zig build --fetch` after editing the dependency.

## `build.zig`

```zig
const sdk_dep = b.dependency("neofs_sdk_zig", .{
    .target = target,
    .optimize = optimize,
});
const sdk_mod = sdk_dep.module("neofs_sdk");

const exe_mod = b.createModule(.{
    .root_source_file = b.path("src/main.zig"),
    .target = target,
    .optimize = optimize,
    .imports = &.{
        .{ .name = "neofs_sdk", .module = sdk_mod },
    },
});

const exe = b.addExecutable(.{ .name = "my_app", .root_module = exe_mod });
exe.root_module.link_libc = true;
exe.linkSystemLibrary("ssl");
exe.linkSystemLibrary("crypto");
```

The SDK module re-exports the public surface from `src/root.zig` (`client`, `container_init`, `netmap`, `pool`, …).

## Import style

```zig
const sdk = @import("neofs_sdk");

var client = sdk.client.Client.init(allocator);
const owner = sdk.user.ID.fromKeyPair(kp);
```

Do not import `src/root.zig` by relative path in applications — use the `neofs_sdk` module name from your build file.

## Transitive dependency

The SDK depends on [zig-protobuf](https://github.com/Arwalk/zig-protobuf) (`protobuf` module). Zig resolves it via the SDK’s `build.zig.zon`; you normally do not add it yourself.

## OpenSSL

TLS (`grpcs://`) requires linking `ssl` and `crypto` on the **executable** (or test binary), as in the snippet above. Missing links typically fail at link time with unresolved OpenSSL symbols.
