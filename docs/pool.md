# Pool

`sdk.pool.Pool` manages multiple NeoFS node endpoints: dial, health sampling, and **session cache** (reuse object sessions across requests).

## Basic usage

```zig
var pool = sdk.pool.Pool.init(allocator);
defer pool.deinit();

try pool.addNode(.{ .endpoint = "grpcs://node-a:8082" });
try pool.addNode(.{ .endpoint = "grpcs://node-b:8082" });

try pool.dial();
```

See `examples/pool_usage.zig`:

```bash
zig build run -Dexample=pool_usage
```

## When to use a pool

- Applications that must survive single-node outages
- Load spread across storage nodes in the same network
- Amortizing `sessionCreate` cost via `session_cache`

The pool wraps transport and client primitives from `src/pool/pool.zig`; configure timeouts and TLS the same way as a single `Client` dial (`grpcs://` → TLS).

## Session cache

`pool/session_cache.zig` stores session keys keyed by container/operation context so repeated object uploads do not recreate sessions every time. Tests: `session_cache_test.zig`.

## Relationship to Client

A pool typically owns or borrows `Client` instances per node. Simple apps may use a single `Client` directly; services that fan out to many nodes should prefer the pool API.
