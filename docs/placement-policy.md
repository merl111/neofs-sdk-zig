# Placement policy

Placement policies describe **how many copies** of each object NeoFS stores and **which storage nodes** may be chosen. The human-readable **policy language (QL)** is parsed in Zig (no ANTLR runtime).

## Policy language basics

One statement per line:

```
REP 3
CBF 2
SELECT 2 IN SAME Location FROM * AS X
FILTER Country EQ UA AS FromUA
EC 3/1
REP 1 IN X
```

| Term | Meaning |
|------|---------|
| `REP n` | Replica count in a placement rule |
| `CBF n` | Container backup factor (candidate nodes per slot) |
| `SELECT` | Attribute-based node grouping |
| `FILTER` | Restrict nodes by key/value (supports nesting) |
| `EC d/p` | Erasure coding data/parity parts |

## Parse and analyze

```zig
var parsed = try sdk.netmap.policy.decodeString(allocator, policy_text);
defer sdk.netmap.policy.deinitPolicy(&parsed, allocator);

const analysis = sdk.container_placement.analyzeParsed(parsed);
try sdk.container_placement.printPolicyAnalysis(stdout, analysis);
```

Validate semantics after parse (ported from Go `verifyPolicy`):

```zig
var parsed = try sdk.netmap.policy.decodeString(allocator, policy_text);
defer sdk.netmap.policy.deinitPolicy(&parsed, allocator);
try sdk.netmap.policy.verifyPolicy(allocator, parsed);

// or: verifyPolicyErrmsg(allocator, parsed) for an error string
```

## Wire encoding for container create

Convert parsed policy to the stable shape used on container PUT:

```zig
const stable_policy = try sdk.container_placement.parsePolicyString(allocator, policy_text);
defer sdk.container_placement.deinitPlacementPolicy(allocator, stable_policy);
// attach via newContainerWithOptions, then putContainer
```

Offline parse/verify only: `zig build run -Dexample=placement_policy`

`stableFromParsed` maps selectors, filters, and EC rules into `internal/proto/stable.PlacementPolicy`; `container_init.toPutRequestBody` marshals them into protobuf.

## Presets

For simple REP/CBF without QL:

```zig
const preset = sdk.container_placement.defaultPreset(); // standard: REP 3, CBF 1
const policy = try sdk.container_placement.buildFromPreset(allocator, preset);
// or
const policy = try sdk.container_placement.buildPolicy(allocator, 3, 1);
```

Preset IDs: `single`, `geo-2`, `standard`, `ha` — see `container/placement.zig`.

## Encode policy text

Round-trip for tooling:

```zig
const encoded = try sdk.netmap.policy.encodeString(allocator, parsed);
defer allocator.free(encoded);
```

## Relation to netmap engine

Parsing + container wire encoding are separate from **runtime node selection** (`netmap.engine.NetMap.containerNodes`), which applies a policy to a node list and optional pivot. See [Netmap](netmap.md).
