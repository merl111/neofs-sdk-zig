# Netmap

The `netmap` module covers placement **policy parsing**, **HRW-based ordering**, and the **placement engine** that selects storage nodes for a policy (port of Go `netmap`).

## Policy parser

`sdk.netmap.policy` — lexer/parser for the QL syntax:

- `decodeString` / `encodeString`
- `verifyPolicy` / `verifyPolicyErrmsg`
- AST types: replicas, selectors, filters, EC rules

Tests and fixtures: `src/netmap/policy_test.zig`, JSON vectors under `test/vectors/netmap/`.

## HRW helpers

`sdk.netmap` exposes lightweight HRW sorting for ad hoc selection:

```zig
var nodes = [_]sdk.netmap.NodeInfo{
    .{ .public_key = "key-a" },
    .{ .public_key = "key-b" },
};
sdk.netmap.sortNodesByPivot(nodes[0..], pivot_bytes);
const picked = sdk.netmap.selectReplicas(nodes[0..], 2, pivot_bytes);
```

Underlying hash: `sdk.hrw` (compatible with Go `nspcc-dev/hrw/v2` — see vector tests).

## Placement engine

`sdk.netmap.engine.NetMap` implements `ContainerNodes`-style selection:

1. Apply filters to the node set
2. Run selectors (SAME/DISTINCT clauses, CBF)
3. Flatten node groups per replica or EC rule

```zig
var nm = sdk.netmap.engine.NetMap.init(allocator, node_infos);
defer nm.deinit();

const groups = try nm.containerNodes(placement_policy_pb, pivot);
defer nm.freeContainerNodes(groups);
```

`node_info.NodeInfo` carries public key, attributes, and weight; build from netmap snapshots or test vectors.

## Cross-language tests

```bash
zig build vectors
```

Runs HRW/tzhash binaries and all `test/vectors/netmap/*.json` cases against the engine (parity with Go `json_test.go`).

## TZ hash

`sdk.tzhash` — Tillich–Zemor checksum API with reference vectors for object payload checks.
