const std = @import("std");
const id = @import("id.zig");

test "container id from marshaled data is deterministic" {
    const data = "container-nonce-payload";
    const cid1 = id.fromMarshaledContainer(data);
    const cid2 = id.fromMarshaledContainer(data);
    try std.testing.expectEqualSlices(u8, &cid1, &cid2);

    const other = id.fromMarshaledContainer("other");
    try std.testing.expect(!std.mem.eql(u8, &cid1, &other));
}

test "container id is 32 bytes sha256" {
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("x", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &id.fromMarshaledContainer("x"));
}
