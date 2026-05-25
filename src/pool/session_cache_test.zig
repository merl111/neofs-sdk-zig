const std = @import("std");
const cache_mod = @import("session_cache.zig");
const session = @import("../session/token.zig");
const session_v2 = @import("../session/v2/token.zig");

test "session cache v1 get put and expiry" {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = false }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cache = cache_mod.SessionCache.init(allocator, 4);
    defer cache.deinit();

    const tok = session.new(.put, 0, 100);
    const key = try allocator.dupe(u8, "node-1");
    try cache.putV1(key, tok);

    cache.updateEpoch(50);
    const got = cache.getV1("node-1").?;
    try std.testing.expectEqual(tok.verb, got.verb);

    cache.updateEpoch(99);
    try std.testing.expect(cache.getV1("node-1") == null);
    cache.purge();
}

test "session cache v2 expires by unix time" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cache = cache_mod.SessionCache.init(allocator, 4);
    defer cache.deinit();

    const now: u64 = @intCast(std.time.timestamp());
    const tok = session_v2.Token{
        .verb = .object_put,
        .issuer = "issuer",
        .target = "target",
        .iat = now,
        .nbf = now,
        .exp = now + 3600,
    };
    const key = try allocator.dupe(u8, "node-v2");
    try cache.putV2(key, tok);

    const got = cache.getV2("node-v2").?;
    try std.testing.expectEqual(tok.exp, got.exp);
}

test "session cache delete by prefix" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cache = cache_mod.SessionCache.init(allocator, 8);
    defer cache.deinit();

    try cache.putV1(try allocator.dupe(u8, "pool/a"), session.new(.get, 0, 10));
    try cache.putV1(try allocator.dupe(u8, "pool/b"), session.new(.put, 0, 10));
    try cache.putV1(try allocator.dupe(u8, "other/c"), session.new(.delete, 0, 10));

    cache.deleteByPrefix("pool/");
    try std.testing.expect(cache.getV1("pool/a") == null);
    try std.testing.expect(cache.getV1("pool/b") == null);
    try std.testing.expect(cache.getV1("other/c") != null);
}
