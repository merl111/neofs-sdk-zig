# Objects

Objects live inside a container. Large payloads use **streaming** PUT/GET; the client prepares signed init messages and session tokens.

## Full lifecycle (recommended path)

See `examples/container_object_lifecycle.zig`:

1. Dial and set signer
2. `putContainer`
3. `sessionCreate` for PUT
4. `prepareObjectPut` → `write` → `close`
5. `objectGetInit` → read chunks
6. `sessionCreate` for DELETE
7. `objectDeleteInContainer`
8. `containerDelete`

Run:

```bash
export NEOFS_WIF='L...'
zig build run -Dexample=container_object_lifecycle
```

## Streaming upload

```zig
const epoch = try client.networkInfo();
const session = try client.sessionCreate(owner, epoch + 10);
defer allocator.free(session.session_key);

var writer = try client.prepareObjectPut(
    container_id,
    owner,
    "",                    // optional inline hint; payload goes to write()
    "document.pdf",
    session,
    epoch,                 // nbf
    epoch + 10,            // exp
    epoch,                 // creation epoch
);
defer writer.deinit();

try writer.write(file_bytes);
try writer.close();

const oid = writer.storedObjectID() orelse return error.MissingObjectID;
```

`prepareObjectPutV2` / `prepareObjectPutV2WithHeaderSession` expose v2 session wire details when you need them.

## Streaming download

```zig
var result = try client.objectGetInit(container_id, object_id);
defer result.header.deinit(allocator);
defer result.reader.deinit();

var buf: [4096]u8 = undefined;
while (true) {
    const n = try result.reader.read(&buf);
    if (n == 0) break;
    // process buf[0..n]
}
```

## Search

```zig
const ids = try client.searchObjects(container_id);
defer {
    for (ids) |id| { /* ids are [32]u8 */ }
    allocator.free(ids);
}
```

`searchObjectsDetailed` returns richer entries; call `freeSearchObjects` when done.

## Object IDs

```zig
const s = try sdk.object_put.encodeObjectID(allocator, object_id);
```

## Slicing and relations

- `sdk.object_slicer` — split large objects for advanced upload paths
- `sdk.object_relations` — parent/child linking on the object graph

## Checksums

Payload integrity uses SHA-256 and Tillich–Zemor (`sdk.checksum`, `sdk.tzhash`) per NeoFS object header rules; vector tests cover tzhash parity with Go.
