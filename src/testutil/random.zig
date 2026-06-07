const std = @import("std");
const csprng = @import("../crypto/csprng.zig");

pub fn randomBytes(allocator: std.mem.Allocator, len: usize) ![]u8 {
    const out = try allocator.alloc(u8, len);
    csprng.randomBytes(out);
    return out;
}

pub fn randomString(allocator: std.mem.Allocator, len: usize) ![]u8 {
    const raw = try randomBytes(allocator, len);
    defer allocator.free(raw);
    return try allocator.dupe(u8, raw);
}

pub fn randomHex(allocator: std.mem.Allocator, byte_len: usize) ![]u8 {
    const raw = try randomBytes(allocator, byte_len);
    defer allocator.free(raw);
    var hex = try allocator.alloc(u8, raw.len * 2);
    for (raw, 0..) |b, i| {
        _ = try std.fmt.bufPrint(hex[i * 2 ..][0..2], "{x:0>2}", .{b});
    }
    return hex;
}

pub fn randContainerId() [32]u8 {
    var id: [32]u8 = undefined;
    csprng.randomBytes(&id);
    return id;
}

pub fn randOwnerId(allocator: std.mem.Allocator) ![33]u8 {
    var key: [33]u8 = undefined;
    key[0] = 0x02;
    csprng.randomBytes(key[1..]);
    _ = allocator;
    return key;
}

test "random helpers produce data" {
    const allocator = std.testing.allocator;

    const raw = try randomBytes(allocator, 16);
    defer allocator.free(raw);
    try std.testing.expectEqual(@as(usize, 16), raw.len);

    const hex = try randomHex(allocator, 8);
    defer allocator.free(hex);
    try std.testing.expectEqual(@as(usize, 16), hex.len);

    _ = randContainerId();
    _ = try randOwnerId(allocator);
}
