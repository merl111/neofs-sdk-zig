# Getting started

## Requirements

- **Zig** `0.15.x` (see `minimum_zig_version` in `build.zig.zon`)
- **OpenSSL** (`libssl`, `libcrypto`) — gRPC over TLS uses the system libraries
- **bash** — proto generation and integration scripts
- **protoc** — only if you regenerate stubs (`zig build gen-proto`)

## Clone and build

```bash
git clone --recurse-submodules <repo-url> neofs-sdk-zig
cd neofs-sdk-zig
zig build test
```

Submodules include `neofs-api/` (pinned to `v2.23.0`). Generated stubs live in
`src/proto/gen/` and are committed so a normal build does not need `protoc`.
See the [documentation index](README.md) for guides beyond this page.

## Minimal program

```zig
const std = @import("std");
const sdk = @import("neofs_sdk");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var client = sdk.client.Client.init(gpa.allocator());
    defer client.deinit();

    try client.dial("grpc://localhost:8080", false, 10_000);
    const epoch = try client.networkInfo();
    std.debug.print("epoch {d}\n", .{epoch});
});
```

For a public testnet endpoint with TLS:

```bash
export NEOFS_ENDPOINT=grpcs://st1.t5.fs.neo.org:8082
export NEOFS_WIF='L...'   # Neo WIF private key
zig build run -Dexample=list_containers
```

See [Authentication](authentication.md) for key handling and [Examples](examples.md) for full flows.

## Next steps

1. [Add the SDK to your project](adding-as-dependency.md)
2. [Create a container and upload an object](objects.md)
3. [Configure placement](placement-policy.md) when you need more than `REP` / `CBF`
