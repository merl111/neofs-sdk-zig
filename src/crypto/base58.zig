const std = @import("std");

pub const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn decodeChecked(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const decoded = try decode(allocator, s);
    defer allocator.free(decoded);
    if (decoded.len < 5) return error.InvalidBase58Check;
    const payload = decoded[0 .. decoded.len - 4];
    const checksum = decoded[decoded.len - 4 ..];
    var h1: [32]u8 = undefined;
    var h2: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &h1, .{});
    std.crypto.hash.sha2.Sha256.hash(&h1, &h2, .{});
    if (!std.mem.eql(u8, checksum, h2[0..4])) return error.InvalidChecksum;
    return try allocator.dupe(u8, payload);
}

pub fn encodeChecked(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    var h1: [32]u8 = undefined;
    var h2: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &h1, .{});
    std.crypto.hash.sha2.Sha256.hash(&h1, &h2, .{});
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, payload);
    try buf.appendSlice(allocator, h2[0..4]);
    return encode(allocator, buf.items);
}

pub fn encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var zeros: usize = 0;
    while (zeros < data.len and data[zeros] == 0) : (zeros += 1) {}

    const size = data.len * 138 / 100 + 1;
    var b58 = try allocator.alloc(u8, size);
    defer allocator.free(b58);
    @memset(b58, 0);

    for (data[zeros..]) |byte| {
        var carry: u32 = byte;
        var j: isize = @intCast(size - 1);
        while (j >= 0) : (j -= 1) {
            carry += @as(u32, b58[@intCast(j)]) * 256;
            b58[@intCast(j)] = @intCast(carry % 58);
            carry /= 58;
        }
    }

    var start: usize = 0;
    while (start < size and b58[start] == 0) : (start += 1) {}

    const out = try allocator.alloc(u8, zeros + (size - start));
    var i: usize = 0;
    while (i < zeros) : (i += 1) out[i] = '1';
    while (i < out.len) : (i += 1) {
        out[i] = alphabet[b58[start + i - zeros]];
    }
    return out;
}

pub fn decode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var zeros: usize = 0;
    while (zeros < s.len and s[zeros] == '1') : (zeros += 1) {}

    const size = s.len * 733 / 1000 + 1;
    var b256 = try allocator.alloc(u8, size);
    defer allocator.free(b256);
    @memset(b256, 0);

    for (s[zeros..]) |ch| {
        const val = std.mem.indexOfScalar(u8, alphabet, ch) orelse return error.InvalidBase58Char;
        var carry: u32 = @intCast(val);
        var j: isize = @intCast(size - 1);
        while (j >= 0) : (j -= 1) {
            carry += @as(u32, b256[@intCast(j)]) * 58;
            b256[@intCast(j)] = @intCast(carry % 256);
            carry /= 256;
        }
    }

    var start: usize = 0;
    while (start < size and b256[start] == 0) : (start += 1) {}

    const out = try allocator.alloc(u8, zeros + (size - start));
    @memset(out, 0);
    @memcpy(out[zeros..], b256[start..]);
    return out;
}

test "base58 neo user id vector" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const expected = "NQZkR7mG74rJsGAHnpkiFeU9c4f5VLN54f";
    const payload = [_]u8{
        53, 51, 5, 166, 111, 29, 20, 101, 192, 165, 28, 167, 57,
        160, 82, 80, 41, 203, 20, 254, 30, 138, 195, 17, 92,
    };
    const enc = try encode(allocator, &payload);
    defer allocator.free(enc);
    try std.testing.expectEqualStrings(expected, enc);
    const dec = try decode(allocator, expected);
    defer allocator.free(dec);
    try std.testing.expectEqualSlices(u8, &payload, dec);
}

test "base58 roundtrip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const payload = "hello";
    const enc = try encode(allocator, payload);
    defer allocator.free(enc);
    const dec = try decode(allocator, enc);
    defer allocator.free(dec);
    try std.testing.expectEqualStrings(payload, dec);
}
