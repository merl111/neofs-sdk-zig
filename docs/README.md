# neofs-sdk-zig documentation

Guides and examples for the Zig NeoFS SDK. The API mirrors [neofs-sdk-go](https://github.com/nspcc-dev/neofs-sdk-go) where practical; wire types come from the pinned `neofs-api` submodule.

## Guides

| Topic | Description |
|-------|-------------|
| [Getting started](getting-started.md) | Requirements, build, first connection |
| [Adding as a dependency](adding-as-dependency.md) | `build.zig.zon`, linking OpenSSL |
| [Client](client.md) | Dial, RPCs, sessions, status handling |
| [Authentication](authentication.md) | WIF keys, signers, request signing |
| [Containers](containers.md) | Create, list, ACL, attributes |
| [Objects](objects.md) | Put/get, streaming, search, delete |
| [Placement policy](placement-policy.md) | Policy language (QL), presets, wire encoding |
| [Netmap](netmap.md) | Policy parser, placement engine, HRW |
| [Pool](pool.md) | Multi-node dial and session cache |
| [Examples](examples.md) | Runnable programs and how to run them |
| [Testing](testing.md) | Unit tests, vectors, integration (AIO) |

## Quick links

- Module entry: `src/root.zig` — import as `neofs_sdk`
- Runnable examples: `examples/`
- Cross-language fixtures: `test/vectors/`
- Integration against NeoFS AIO: `test/integration/`
