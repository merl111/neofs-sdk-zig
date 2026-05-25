# Client

`sdk.client.Client` is the main entry point for NeoFS gRPC services (object, container, session, netmap, accounting, …).

## Lifecycle

```zig
var client = sdk.client.Client.init(allocator);
defer client.deinit();

try client.dial("grpcs://st1.t5.fs.neo.org:8082", true, 30_000);
// tls = true for grpcs://, false for grpc://

client.setSignerKey(&secret);
```

| Method | Purpose |
|--------|---------|
| `dial(endpoint, tls, timeout_ms)` | Connect transport |
| `setSignerKey` / `signerKey` | Default request signer |
| `close` / `deinit` | Release connection and state |
| `networkInfo` | Current epoch (unsigned OK) |
| `endpointInfo` | Node metadata |

## Containers

| Method | Notes |
|--------|-------|
| `putContainer` | Signed PUT from `stable.Container` |
| `containerGet` / `containerList` / `containerDelete` | Owner-scoped |
| `containerEaclGet` / `containerEaclSet` | Extended ACL table bytes |
| `setContainerAttribute` / `removeContainerAttribute` | Metadata patches |

## Objects

| Method | Notes |
|--------|-------|
| `prepareObjectPut` | Builds signed init + streaming writer |
| `objectGetInit` | Streaming download with header |
| `objectDeleteInContainer` | Requires session + epoch window |
| `searchObjects` / `searchObjectsDetailed` | Container listing |
| `objectHead` / `objectHash` | Metadata and payload hash |

Lower-level streaming: `objectPutInit`, `objectGetInitV2`, `objectGetRangeInit`.

## Accounting

```zig
const balance = try client.balanceGetForOwner(owner);
```

## Status and errors

NeoFS returns rich **status** objects per RPC (success, partial success, access denied, etc.). The client maps common codes in `sdk.client_status` and `sdk.client_status_errors`. Inspect failures when retries or user messaging matter — a single Zig `error` is not always enough (same design as Go SDK).

## Pool vs single client

For production apps that talk to several nodes, use [`pool.Pool`](pool.md) for dial rotation and session cache; embed or wrap `Client` as needed.
