# Examples

Runnable programs live in `examples/`. The build exposes them via `-Dexample=<name>`:

```bash
zig build run -Dexample=<name>
```

Pass extra args after `--` (forwarded to the executable when using `zig build run`).

## Catalog

| Name | File | Network | Description |
|------|------|---------|-------------|
| `client_dial` | `client_dial.zig` | Local | Connect to `grpc://localhost:8080`, print success |
| `list_containers` | `list_containers.zig` | Testnet | List containers for `NEOFS_WIF` owner |
| `container_object_lifecycle` | `container_object_lifecycle.zig` | Testnet | Create container → put → get → delete object → delete container |
| `object_put_get` | `object_put_get.zig` | Local | Minimal put/get (requires local node) |
| `pool_usage` | `pool_usage.zig` | Local | Add two nodes and dial pool |
| `placement_policy` | `placement_policy.zig` | None | Parse, verify, and analyze QL policy text |
| `aio_lifecycle` | `test/integration/lifecycle.zig` | Docker AIO | Same lifecycle against `zig build integration` |

### Environment (testnet examples)

```bash
export NEOFS_WIF='L...'
export NEOFS_ENDPOINT='grpcs://st1.t5.fs.neo.org:8082'   # optional
zig build run -Dexample=list_containers
zig build run -Dexample=container_object_lifecycle
```

### Local examples

Start a NeoFS node (or AIO stack) listening on port 8080, then:

```bash
zig build run -Dexample=client_dial
zig build run -Dexample=object_put_get
zig build run -Dexample=pool_usage
```

## Adding an example

1. Add `examples/my_example.zig` importing `@import("neofs_sdk")`.
2. Register the name in `build.zig` under the `examples` table (same pattern as existing entries).
3. Document env vars and expected output in this file.
