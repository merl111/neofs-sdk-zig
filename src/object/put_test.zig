const std = @import("std");
const put = @import("put.zig");
const user = @import("../user/id.zig");

test "prepare put object golden object id" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pubkey: [33]u8 = undefined;
    @memset(&pubkey, 0x02);
    const owner = user.ID.fromCompressedPublicKey(pubkey);

    const container_id = [_]u8{0xAB} ** 32;
    const payload = "golden-payload";
    const prepared = try put.preparePutObject(
        allocator,
        "secret-key-material",
        container_id,
        owner,
        payload,
        "file.txt",
        42,
    );
    defer {
        var hdr = prepared.header;
        hdr.deinit(allocator);
        allocator.free(prepared.object_signature.key);
        allocator.free(prepared.object_signature.sign);
    }

    const prepared2 = try put.preparePutObject(
        allocator,
        "secret-key-material",
        container_id,
        owner,
        payload,
        "file.txt",
        42,
    );
    defer {
        var hdr = prepared2.header;
        hdr.deinit(allocator);
        allocator.free(prepared2.object_signature.key);
        allocator.free(prepared2.object_signature.sign);
    }

    try std.testing.expectEqualSlices(u8, &prepared.object_id, &prepared2.object_id);
    try std.testing.expectEqual(@as(u64, 42), prepared.header.creation_epoch);
    try std.testing.expectEqual(@as(usize, payload.len), prepared.header.payload_length);
}
