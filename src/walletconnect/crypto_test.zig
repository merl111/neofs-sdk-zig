const std = @import("std");
const wc_crypto = @import("crypto.zig");

test "hex encode/decode round trip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const input = "deadbeef";
    const raw = try wc_crypto.decodeHex(allocator, input);
    defer allocator.free(raw);
    try std.testing.expectEqual(@as(usize, 4), raw.len);
    try std.testing.expectEqual(@as(u8, 0xDE), raw[0]);
    try std.testing.expectEqual(@as(u8, 0xAD), raw[1]);

    const encoded = try wc_crypto.encodeHex(allocator, raw);
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings(input, encoded);
}

test "sha256Hex is deterministic" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const digest1 = try wc_crypto.sha256Hex(allocator, "walletconnect");
    defer allocator.free(digest1);
    const digest2 = try wc_crypto.sha256Hex(allocator, "walletconnect");
    defer allocator.free(digest2);
    try std.testing.expectEqualStrings(digest1, digest2);
    try std.testing.expectEqual(@as(usize, 64), digest1.len);
}

test "base64UrlNoPad round trip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const payload = "hello walletconnect";
    const encoded = try wc_crypto.base64UrlNoPad(allocator, payload);
    defer allocator.free(encoded);

    const decoded_len = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    try std.base64.url_safe_no_pad.Decoder.decode(decoded, encoded);
    try std.testing.expectEqualStrings(payload, decoded);
}

test "pairing topic derives from symmetric key" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const pairing = @import("pairing.zig");

    const sym_key_hex = try allocator.dupe(u8, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    defer allocator.free(sym_key_hex);
    const topic = try pairing.topicFromSymKey(allocator, sym_key_hex);
    defer allocator.free(topic);
    try std.testing.expectEqual(@as(usize, 64), topic.len);

    const uri = try pairing.buildUri(allocator, .{
        .topic = topic,
        .sym_key_hex = sym_key_hex,
        .expiry_timestamp = 1_700_000_000,
    }, &.{ "wc_sessionPropose" });
    defer allocator.free(uri);
    try std.testing.expect(std.mem.startsWith(u8, uri, "wc:"));
    try std.testing.expect(std.mem.indexOf(u8, uri, "symKey=") != null);
}
