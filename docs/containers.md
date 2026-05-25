# Containers

Containers are namespaces for objects. Creation is a signed **Container.Put** RPC; the SDK builds wire messages from `stable.Container` helpers in `container/init.zig`.

## Create with defaults

```zig
const nonce = try sdk.container_init.randomNonce(allocator);
defer allocator.free(nonce);

const container = try sdk.container_init.newContainer(allocator, owner, nonce, "my-bucket");
defer sdk.container_init.deinitContainer(allocator, container);

const cid = try client.putContainer(container);
const cid_str = try sdk.container_init.encodeID(allocator, cid);
defer allocator.free(cid_str);
```

`newContainer` sets a default placement of `REP 1` / `CBF 1` and public-read-write ACL unless you override options.

## ACL and placement options

```zig
const container = try sdk.container_init.newContainerWithOptions(allocator, owner, nonce, "my-bucket", .{
    .basic_acl = sdk.container_acl.defaultPreset().bits,
    .placement_policy = policy, // sdk.container_init.PlacementPolicy (stable)
});
```

ACL presets live in `sdk.container_acl` (`private`, `public-read`, `eacl-public-read-write`, …).

Placement presets and policy parsing: [Placement policy](placement-policy.md).

## Container ID

IDs are 32-byte values derived from the signed container structure:

```zig
const id_str = try sdk.container_init.encodeID(allocator, cid);
defer allocator.free(id_str);
// CID type: sdk.container_id.ID ([32]u8), hash of signed container body
```

## List and delete

```zig
const ids = try client.containerList(owner);
defer allocator.free(ids);

try client.containerDelete(cid);
```

## Extended ACL

Fetch/set raw eACL table bytes:

```zig
const table = try client.containerEaclGet(cid);
defer allocator.free(table);
try client.containerEaclSet(cid, new_table_bytes);
```

Validation helpers: `sdk.eacl` (`validator` for rule checking).

## Memory ownership

- `deinitContainer` frees attributes, placement policy slices, and owner bytes you allocated through helpers.
- After `putContainer`, the returned `[32]u8` CID is yours; encoded strings from `encodeID` must be freed.
