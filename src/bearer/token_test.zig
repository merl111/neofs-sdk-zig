const std = @import("std");
const token_mod = @import("token.zig");
const user = @import("../user/id.zig");
const user_signer = @import("../user/signer.zig");

test "lifetime claims and validAt" {
    var tok: token_mod.Token = .{};
    try std.testing.expect(tok.validAt(0));
    try std.testing.expect(!tok.validAt(1));

    tok.iat = 1;
    tok.nbf = 2;
    tok.exp = 4;

    try std.testing.expect(!tok.validAt(0));
    try std.testing.expect(!tok.validAt(1));
    try std.testing.expect(tok.validAt(2));
    try std.testing.expect(tok.validAt(3));
    try std.testing.expect(tok.validAt(4));
    try std.testing.expect(!tok.validAt(5));
}

test "assertUser restricts target owner" {
    var pubkey: [33]u8 = undefined;
    @memset(&pubkey, 0x42);
    pubkey[0] = 0x02;
    const usr1 = user.ID.fromCompressedPublicKey(pubkey);
    var pubkey2 = pubkey;
    pubkey2[32] = 0x43;
    const usr2 = user.ID.fromCompressedPublicKey(pubkey2);

    var tok: token_mod.Token = .{};
    try std.testing.expect(tok.assertUser(usr1));
    try std.testing.expect(tok.assertUser(usr2));

    tok.forUser(usr1);
    try std.testing.expect(tok.assertUser(usr1));
    try std.testing.expect(!tok.assertUser(usr2));
}

test "marshal unmarshal round-trip" {
    const allocator = std.testing.allocator;

    var pubkey: [33]u8 = undefined;
    @memset(&pubkey, 0x02);
    const owner = user.ID.fromCompressedPublicKey(pubkey);
    var pubkey2 = pubkey;
    pubkey2[1] = 0x03;
    const issuer = user.ID.fromCompressedPublicKey(pubkey2);

    var src: token_mod.Token = .{
        .owner = owner,
        .issuer = issuer,
        .nbf = 2,
        .iat = 3,
        .exp = 10,
    };

    const data = try src.marshal(allocator);
    defer allocator.free(data);

    var dst: token_mod.Token = .{};
    try dst.unmarshal(allocator, data);

    try std.testing.expect(dst.owner != null);
    try std.testing.expectEqualSlices(u8, &owner.bytes, &dst.owner.?.bytes);
    try std.testing.expectEqualSlices(u8, &issuer.bytes, &dst.issuer.?.bytes);
    try std.testing.expectEqual(@as(u64, 2), dst.nbf);
    try std.testing.expectEqual(@as(u64, 3), dst.iat);
    try std.testing.expectEqual(@as(u64, 10), dst.exp);
}

test "sign and verify signature" {
    const secret = "secret-key-material";
    const signer = user_signer.Signer{ .key = secret };

    var tok: token_mod.Token = .{ .nbf = 1, .iat = 1, .exp = 100 };
    try tok.sign(std.testing.allocator, signer);
    defer if (tok.signature) |s| {
        std.testing.allocator.free(s.key);
        std.testing.allocator.free(s.value);
    };
    try std.testing.expect(tok.verifySignature(std.testing.allocator));
    try std.testing.expect(tok.issuerID() != null);
}
