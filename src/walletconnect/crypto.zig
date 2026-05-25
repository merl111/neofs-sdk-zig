const std = @import("std");

pub fn randomHex(allocator: std.mem.Allocator, bytes_len: usize) ![]u8 {
    const raw = try allocator.alloc(u8, bytes_len);
    defer allocator.free(raw);
    std.crypto.random.bytes(raw);
    const hex = try allocator.alloc(u8, bytes_len * 2);
    const alphabet = "0123456789abcdef";
    for (raw, 0..) |b, i| {
        hex[i * 2] = alphabet[(b >> 4) & 0x0F];
        hex[i * 2 + 1] = alphabet[b & 0x0F];
    }
    return hex;
}

pub fn encodeHex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const hex = try allocator.alloc(u8, data.len * 2);
    const alphabet = "0123456789abcdef";
    for (data, 0..) |b, i| {
        hex[i * 2] = alphabet[(b >> 4) & 0x0F];
        hex[i * 2 + 1] = alphabet[b & 0x0F];
    }
    return hex;
}

pub fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

pub fn base64UrlNoPad(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const size = std.base64.url_safe_no_pad.Encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, size);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, data);
    return out;
}

pub fn sha256Hex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const hex = try allocator.alloc(u8, digest.len * 2);
    const alphabet = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        hex[i * 2] = alphabet[(b >> 4) & 0x0F];
        hex[i * 2 + 1] = alphabet[b & 0x0F];
    }
    return hex;
}

