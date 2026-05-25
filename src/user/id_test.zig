const std = @import("std");
const id = @import("id.zig");

test "user id base58 round-trip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pubkey: [33]u8 = undefined;
    @memset(&pubkey, 0x02);
    const original = id.ID.fromCompressedPublicKey(pubkey);

    const encoded = try original.encodeToString(allocator);
    defer allocator.free(encoded);
    const decoded = try id.ID.decodeString(allocator, encoded);
    try std.testing.expectEqualSlices(u8, &original.bytes, &decoded.bytes);
}

test "user id fromRaw rejects invalid checksum" {
    var pubkey: [33]u8 = undefined;
    @memset(&pubkey, 0x02);
    const uid = id.ID.fromCompressedPublicKey(pubkey);
    var bad = uid.bytes;
    bad[24] +%= 1;
    try std.testing.expectError(error.InvalidChecksum, id.ID.fromRaw(bad));
}
