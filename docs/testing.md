# Testing

The SDK uses three test tiers. CI should run **unit** and **vectors** without network access; **integration** is optional and Docker-based.

## Unit tests

```bash
zig build test
```

Covers modules, signing, mock gRPC transport (`client/mock_transport.zig`), status mapping, WalletConnect crypto helpers, proto encoding tests, netmap policy round-trips, and more. Entry: `src/root.zig` test block.

## Vector tests

```bash
zig build vectors
```

Cross-language parity:

| Fixture | Location | Checks |
|---------|----------|--------|
| HRW | `test/vectors/hrw/` | Hash/sort vs Go |
| TZ hash | `test/vectors/tzhash/` | Checksum bytes |
| Netmap JSON | `test/vectors/netmap/*.json` | Placement engine vs Go |
| Proto golden | `test/vectors/proto/*/roundtrip.bin` | Marshal/unmarshal |

Regenerate proto golden blobs (requires Go toolchain):

```bash
go run ./scripts/export_proto_golden.go
```

Netmap JSON cases come from `neofs-sdk-go/netmap/json_tests`.

## Integration (AIO)

```bash
export NEOFS_AIO=1
zig build integration
```

Runs `test/integration/run_aio.sh` (Dockerized NeoFS) and `lifecycle.zig` — full container/object flow against a real node.

## Test utilities

`src/testutil/` — helpers for vectors (`json_vectors`, `marshal_stable`, `expect`, `random`). Imported only from tests inside the module tree.

## Writing tests

- Prefer real behavior over smoke imports.
- For RPC paths, extend `mock_transport` or golden frames in `grpc_rpc_test.zig`.
- For placement, add JSON under `test/vectors/netmap/` and run `zig build vectors`.
