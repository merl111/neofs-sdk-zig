const std = @import("std");
const sdk = @import("neofs_sdk");

const default_endpoint = "grpcs://st1.t5.fs.neo.org:8082";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const endpoint = std.process.getEnvVarOwned(allocator, "NEOFS_ENDPOINT") catch try allocator.dupe(u8, default_endpoint);
    defer allocator.free(endpoint);

    const wif = std.process.getEnvVarOwned(allocator, "NEOFS_WIF") catch {
        std.debug.print(
            \\Set NEOFS_WIF to your Neo WIF private key and optionally NEOFS_ENDPOINT.
            \\Example:
            \\  export NEOFS_WIF='L...'
            \\  export NEOFS_ENDPOINT='grpcs://st1.t5.fs.neo.org:8082'
            \\  zig build run -Dexample=list_containers
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
    try client.dial(endpoint, tls, 30_000);
    std.debug.print("Connected to {s} as owner {s}\n", .{ endpoint, owner_str });

    const epoch = try client.networkInfo();
    std.debug.print("Current epoch: {d}\n", .{epoch});

    const container_ids = try client.containerList(owner);
    defer allocator.free(container_ids);

    std.debug.print("Found {d} container(s) for {s}:\n", .{ container_ids.len, owner_str });
    for (container_ids) |id| {
        const cid_str = try sdk.container_init.encodeID(allocator, id);
        defer allocator.free(cid_str);
        std.debug.print("  {s}\n", .{cid_str});
    }
}
