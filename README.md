# neofs-sdk-zig

Zig implementation of the [NeoFS](https://neofs.com/) SDK, aligned with
[neofs-sdk-go](https://github.com/nspcc-dev/neofs-sdk-go) and built on the
pinned [`neofs-api`](https://github.com/nspcc-dev/neofs-api) protocol submodule.

**Documentation lives in [`docs/`](docs/README.md)** — start with
[Getting started](docs/getting-started.md), then follow the topic guides below.

## Documentation

| Guide | Topic |
|-------|--------|
| [Overview](docs/README.md) | Index of all guides |
| [Getting started](docs/getting-started.md) | Requirements, clone, first `zig build test` |
| [Adding as a dependency](docs/adding-as-dependency.md) | `build.zig.zon`, OpenSSL, module import |
| [Client](docs/client.md) | Dial, RPCs, sessions, status handling |
| [Authentication](docs/authentication.md) | WIF keys, signers, request signing |
| [Containers](docs/containers.md) | Create, list, ACL, attributes |
| [Objects](docs/objects.md) | Put/get, streaming, search, delete |
| [Placement policy](docs/placement-policy.md) | QL syntax, presets, wire encoding |
| [Netmap](docs/netmap.md) | Policy parser, placement engine, HRW |
| [Pool](docs/pool.md) | Multi-node dial and session cache |
| [Examples](docs/examples.md) | Runnable programs (`zig build run -Dexample=…`) |
| [Testing](docs/testing.md) | Unit tests, vectors, NeoFS AIO integration |

## Project layout

- `docs/` — user guides (see [docs/README.md](docs/README.md))
- `neofs-api/` — protocol definitions submodule (pinned to `v2.23.0`)
- `src/proto/gen/` — generated Zig protocol stubs (committed)
- `src/internal/proto/` + `src/proto/*/encoding.zig` — stable wire helpers
- `src/hrw/` — port of `nspcc-dev/hrw/v2`
- `src/tzhash/` — port-compatible TZ checksum API with reference vectors

## Core modules

- `client` — high-level request API for NeoFS services
- `pool` — multi-node selection and session cache
- `object`, `container`, `session`, `session/v2`, `eacl`, `bearer`
- `netmap` — placement policy parser and HRW-backed node selection
- `crypto`, `user`, `checksum`, `accounting`, `version`

## Development

Requirements:

- Zig `0.15.x` (see `minimum_zig_version` in `build.zig.zon`)
- `bash`
- `protoc` (only needed if regenerating stubs)

Commands:

```bash
zig build test
zig build gen-proto
zig build vectors
zig build integration
```

## Test tiers

| Step | Command | Scope |
|------|---------|--------|
| Unit | `zig build test` | SDK modules, request signing, gRPC encode paths (mock transport), status mapping, WalletConnect crypto/pairing helpers |
| Vectors | `zig build vectors` | Cross-language HRW, tzhash, netmap JSON, and protobuf round-trip binaries |
| Integration | `zig build integration` | Dockerized NeoFS AIO: dial smoke test plus full container/object lifecycle (`test/integration/lifecycle.zig`, requires `NEOFS_AIO=1`) |

`zig build test` is the default CI gate and must pass without network access.

## Examples

Run with `zig build run -Dexample=<name>`. See [docs/examples.md](docs/examples.md) for the full catalog and environment variables.

```bash
zig build run -Dexample=client_dial
zig build run -Dexample=placement_policy              # no network
zig build run -Dexample=container_object_lifecycle   # needs NEOFS_WIF
```
