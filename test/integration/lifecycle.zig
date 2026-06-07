const std = @import("std");
const sdk = @import("neofs_sdk");

/// Full container/object lifecycle against a live NeoFS node.
/// Guarded by `NEOFS_AIO=1` so it only runs from integration scripts.
pub fn main(init: std.process.Init) !void {
    if (!aioEnabled()) {
        std.debug.print("Set NEOFS_AIO=1 to run the integration lifecycle test.\n", .{});
        return;
    }
    const allocator = init.gpa;

    const endpoint = std.process.getEnvVarOwned(allocator, "NEOFS_ENDPOINT") catch
        try allocator.dupe(u8, "grpc://localhost:8080");
    defer allocator.free(endpoint);

    const default_wif = "KxyjQ8eUa4FHt3Gvioyt1Wz29cTUrE4eTqX3yFSk1YFCsPL8uNsY";
    const wif = std.process.getEnvVarOwned(allocator, "NEOFS_WIF") catch try allocator.dupe(u8, default_wif);
    defer allocator.free(wif);

    const secret = try sdk.crypto_wif.decodePrivateKey(wif);
    const kp = try sdk.crypto_ecdsa.KeyPair.fromSecretBytes(&secret);
    const owner = sdk.user.ID.fromKeyPair(kp);
    const owner_str = try owner.encodeToString(allocator);
    defer allocator.free(owner_str);

    var client = sdk.client.Client.init(allocator);
    defer client.deinit();
    client.setSignerKey(&secret);

    const tls = std.mem.startsWith(u8, endpoint, "grpcs://");
    try client.dial(init.io, endpoint, tls, 30_000);
    std.debug.print("AIO lifecycle: connected to {s} as {s}\n", .{ endpoint, owner_str });

    const epoch = try client.networkInfo();
    const session_exp = epoch + 10;

    const nonce = try sdk.container_init.randomNonce(allocator);
    defer allocator.free(nonce);
    const container = try sdk.container_init.newContainer(allocator, owner, nonce, "zig-aio-lifecycle");
    defer sdk.container_init.deinitContainer(allocator, container);
    const cid = try client.putContainer(container);
    const cid_str = try sdk.container_init.encodeID(allocator, cid);
    defer allocator.free(cid_str);
    std.debug.print("AIO lifecycle: created container {s}\n", .{cid_str});

    const payload_text = "NeoFS Zig SDK AIO lifecycle payload";
    const session_put = try client.sessionCreate(owner, session_exp);
    defer allocator.free(session_put.session_key);

    const prepared_and_writer = try client.prepareObjectPut(
        cid,
        owner,
        payload_text,
        "aio-lifecycle.txt",
        session_put,
        epoch,
        session_exp,
        epoch,
    );
    var writer = prepared_and_writer;
    defer writer.deinit();
    try writer.write(payload_text);
    try writer.close();
    const oid = writer.storedObjectID() orelse return error.MissingObjectID;
    const oid_str = try sdk.object_put.encodeObjectID(allocator, oid);
    defer allocator.free(oid_str);
    std.debug.print("AIO lifecycle: uploaded object {s}\n", .{oid_str});

    var get_result = try client.objectGetInit(cid, oid);
    defer get_result.header.deinit(allocator);
    defer get_result.reader.deinit();
    var payload_buf: std.ArrayList(u8) = .empty;
    defer payload_buf.deinit(allocator);
    var read_buf: [4096]u8 = undefined;
    while (true) {
        const n = try get_result.reader.read(&read_buf);
        if (n == 0) break;
        try payload_buf.appendSlice(allocator, read_buf[0..n]);
    }
    if (!std.mem.eql(u8, payload_text, payload_buf.items)) return error.PayloadMismatch;
    std.debug.print("AIO lifecycle: verified object payload ({d} bytes)\n", .{payload_buf.items.len});

    const session_delete = try client.sessionCreate(owner, session_exp);
    defer allocator.free(session_delete.session_key);
    try client.objectDeleteInContainer(cid, oid, owner, session_delete, epoch, session_exp);
    std.debug.print("AIO lifecycle: deleted object {s}\n", .{oid_str});

    try client.containerDelete(cid);
    std.debug.print("AIO lifecycle: deleted container {s}\n", .{cid_str});
}

fn aioEnabled() bool {
    const value = std.process.getEnvVarOwned(std.heap.page_allocator, "NEOFS_AIO") catch return false;
    defer std.heap.page_allocator.free(value);
    return value.len == 1 and value[0] == '1';
}
