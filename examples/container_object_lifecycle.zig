const std = @import("std");
const sdk = @import("neofs_sdk");

const default_endpoint = "grpcs://st1.t5.fs.neo.org:8082";

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const endpoint = std.process.getEnvVarOwned(allocator, "NEOFS_ENDPOINT") catch try allocator.dupe(u8, default_endpoint);
    defer allocator.free(endpoint);

    const wif = std.process.getEnvVarOwned(allocator, "NEOFS_WIF") catch {
        std.debug.print(
            \\Set NEOFS_WIF to your Neo WIF private key and optionally NEOFS_ENDPOINT.
            \\Example:
            \\  export NEOFS_WIF='L...'
            \\  export NEOFS_ENDPOINT='grpcs://st1.t5.fs.neo.org:8082'
            \\  zig build run -Dexample=container_object_lifecycle
            \\
        , .{});
        return error.MissingWif;
    };
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
    std.debug.print("Connected to {s} as owner {s}\n", .{ endpoint, owner_str });

    const epoch = try client.networkInfo();
    const session_exp = epoch + 10;

    const nonce = try sdk.container_init.randomNonce(allocator);
    defer allocator.free(nonce);
    const container = try sdk.container_init.newContainer(allocator, owner, nonce, "zig-lifecycle-example");
    defer sdk.container_init.deinitContainer(allocator, container);
    const cid = try client.putContainer(container);
    const cid_str = try sdk.container_init.encodeID(allocator, cid);
    defer allocator.free(cid_str);
    std.debug.print("Created container {s}\n", .{cid_str});

    const tmp_path = "/tmp/neofs-zig-example.txt";
    const payload_text =
        \\NeoFS Zig SDK lifecycle example.
        \\Generated at runtime and uploaded via gRPC.
        \\
    ;
    {
        const file = try std.Io.Dir.cwd().createFile(io, tmp_path, .{});
        defer file.close(io);
        try std.Io.File.writeStreamingAll(file, io, payload_text);
    }
    std.debug.print("Wrote local file {s}\n", .{tmp_path});

    const session_put = try client.sessionCreate(owner, session_exp);
    defer allocator.free(session_put.session_key);

    const prepared_and_writer = try client.prepareObjectPut(
        cid,
        owner,
        payload_text,
        "neofs-zig-example.txt",
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
    std.debug.print("Uploaded object {s}\n", .{oid_str});

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
    std.debug.print("Downloaded payload ({d} bytes):\n{s}\n", .{ payload_buf.items.len, payload_buf.items });

    const session_delete = try client.sessionCreate(owner, session_exp);
    defer allocator.free(session_delete.session_key);
    try client.objectDeleteInContainer(cid, oid, owner, session_delete, epoch, session_exp);
    std.debug.print("Deleted object {s}\n", .{oid_str});

    try client.containerDelete(cid);
    std.debug.print("Deleted container {s}\n", .{cid_str});
}
