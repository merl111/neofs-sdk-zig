const std = @import("std");
const keys = @import("ecdsa/keys.zig");

pub const Scheme = enum(u32) {
    ecdsa_sha512 = 0,
    ecdsa_deterministic_sha256 = 1,
    ecdsa_walletconnect = 2,
    n3 = 3,
};

pub const Signature = struct {
    scheme: Scheme,
    key: []const u8,
    value: []const u8,
};

/// N3 witness verification callback: verify(data, invoc_script, verif_script).
pub const N3Verifier = *const fn ([]const u8, []const u8, []const u8) bool;

var n3_verifier: ?N3Verifier = null;

pub fn setN3Verifier(verifier: N3Verifier) void {
    n3_verifier = verifier;
}

pub fn newN3Signature(allocator: std.mem.Allocator, invoc_script: []const u8, verif_script: []const u8) !Signature {
    return .{
        .scheme = .n3,
        .key = try allocator.dupe(u8, verif_script),
        .value = try allocator.dupe(u8, invoc_script),
    };
}

pub fn sign(allocator: std.mem.Allocator, scheme: Scheme, secret: []const u8, data: []const u8) !Signature {
    const kp = try keys.KeyPair.fromSecretBytes(secret);
    return kp.sign(allocator, scheme, data);
}

pub fn verify(_: []const u8, data: []const u8, signature: Signature) bool {
    if (signature.scheme == .n3) {
        if (n3_verifier) |cb| {
            return cb(data, signature.value, signature.key);
        }
        return false;
    }
    return keys.verify(signature.scheme, signature.key, data, signature.value);
}

test "sign and verify rfc6979" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const s = try sign(gpa.allocator(), .ecdsa_deterministic_sha256, "secret-key-material", "msg");
    defer gpa.allocator().free(s.key);
    defer gpa.allocator().free(s.value);
    try std.testing.expect(verify(s.key, "msg", s));
}

test "n3 uses verifier callback" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const Verifier = struct {
        fn verify(_: []const u8, invoc: []const u8, verif: []const u8) bool {
            return std.mem.eql(u8, invoc, "invoc") and std.mem.eql(u8, verif, "verif");
        }
    };
    setN3Verifier(Verifier.verify);
    const s = try newN3Signature(gpa.allocator(), "invoc", "verif");
    defer gpa.allocator().free(s.key);
    defer gpa.allocator().free(s.value);
    try std.testing.expect(verify("verif", "data", s));
}

test "walletconnect signature carries salt suffix" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const s = try sign(gpa.allocator(), .ecdsa_walletconnect, "secret", "msg");
    defer gpa.allocator().free(s.key);
    defer gpa.allocator().free(s.value);
    try std.testing.expectEqual(@as(usize, 80), s.value.len);
    try std.testing.expect(verify(s.key, "msg", s));
}
