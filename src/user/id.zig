const std = @import("std");
const ripemd160 = @import("../crypto/ripemd160.zig");
const keys = @import("../crypto/ecdsa/keys.zig");

pub const IDSize = 25;
pub const neo3_prefix: u8 = 0x35;

pub const ID = struct {
    bytes: [IDSize]u8,

    pub fn fromKeyPair(kp: keys.KeyPair) ID {
        return fromCompressedPublicKey(kp.publicKeyBytes());
    }

    pub fn fromCompressedPublicKey(pubkey: [33]u8) ID {
        const script = verificationScript(&pubkey);
        var sha: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&script, &sha, .{});
        const script_hash = ripemd160.hash(&sha);

        var out: [IDSize]u8 = undefined;
        out[0] = neo3_prefix;
        @memcpy(out[1..21], &script_hash);
        var checksum_src: [21]u8 = undefined;
        @memcpy(checksum_src[0..21], out[0..21]);
        var c1: [32]u8 = undefined;
        var c2: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&checksum_src, &c1, .{});
        std.crypto.hash.sha2.Sha256.hash(&c1, &c2, .{});
        @memcpy(out[21..25], c2[0..4]);
        return .{ .bytes = out };
    }

    pub fn fromPublicKey(pubkey: []const u8) ID {
        if (pubkey.len == 33) {
            var compressed: [33]u8 = undefined;
            @memcpy(&compressed, pubkey[0..33]);
            return fromCompressedPublicKey(compressed);
        }
        const kp = keys.KeyPair.fromSecretBytes(pubkey) catch {
            var out: [IDSize]u8 = [_]u8{0} ** IDSize;
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(pubkey, &hash, .{});
            out[0] = neo3_prefix;
            @memcpy(out[1..21], hash[0..20]);
            return .{ .bytes = out };
        };
        return fromKeyPair(kp);
    }

    pub fn fromRaw(raw: [IDSize]u8) !ID {
        if (isZero(raw)) return error.ZeroUserID;
        if (raw[0] != neo3_prefix) return error.InvalidPrefix;
        var payload: [21]u8 = undefined;
        @memcpy(&payload, raw[0..21]);
        var c1: [32]u8 = undefined;
        var c2: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&payload, &c1, .{});
        std.crypto.hash.sha2.Sha256.hash(&c1, &c2, .{});
        if (!std.mem.eql(u8, c2[0..4], raw[21..25])) return error.InvalidChecksum;
        return .{ .bytes = raw };
    }

    pub fn encodeToString(self: ID, allocator: std.mem.Allocator) ![]u8 {
        return @import("../crypto/base58.zig").encode(allocator, &self.bytes);
    }

    pub fn decodeString(allocator: std.mem.Allocator, s: []const u8) !ID {
        const decoded = try @import("../crypto/base58.zig").decode(allocator, s);
        defer allocator.free(decoded);
        if (decoded.len != IDSize) return error.InvalidLength;
        var raw: [IDSize]u8 = undefined;
        @memcpy(&raw, decoded[0..IDSize]);
        return ID.fromRaw(raw);
    }

    pub fn isZeroID(self: ID) bool {
        return isZero(self.bytes);
    }
};

fn verificationScript(compressed_pubkey: *const [33]u8) [40]u8 {
    var script: [40]u8 = undefined;
    script[0] = 0x0C; // PUSHDATA1
    script[1] = 0x21; // 33 bytes
    @memcpy(script[2..35], compressed_pubkey);
    script[35] = 0x41; // SYSCALL
    const syscall_name = "System.Crypto.CheckSig";
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(syscall_name, &hash, .{});
    std.mem.writeInt(u32, script[36..40], std.mem.readInt(u32, hash[0..4], .little), .little);
    return script;
}

fn isZero(b: [IDSize]u8) bool {
    for (b) |v| {
        if (v != 0) return false;
    }
    return true;
}

test {
    _ = @import("id_test.zig");
}

test "user id from neo wif" {
    const wif = "KxyjQ8eUa4FHt3Gvioyt1Wz29cTUrE4eTqX3yFSk1YFCsPL8uNsY";
    const secret = try @import("../crypto/wif.zig").decodePrivateKey(std.testing.allocator, wif);
    const kp = try keys.KeyPair.fromSecretBytes(&secret);
    try std.testing.expectEqualStrings(
        "02b3622bf4017bdfe317c58aed5f4c753f206b7db896046fa7d774bbc4bf7f8dc2",
        &std.fmt.bytesToHex(kp.publicKeyBytes(), .lower),
    );
    const id = ID.fromKeyPair(kp);
    const expected_bytes = [_]u8{
        0x35, 0xee, 0x9e, 0xa2, 0x2c, 0x27, 0xe3, 0x4b, 0xd0, 0x14,
        0x8f, 0xc4, 0x10, 0x8e, 0x08, 0xf7, 0x4e, 0x8f, 0x50, 0x48,
        0xb2, 0xf1, 0x95, 0xca, 0x73,
    };
    try std.testing.expectEqualSlices(u8, &expected_bytes, &id.bytes);
    const s = try id.encodeToString(std.testing.allocator);
    defer std.testing.allocator.free(s);
    try std.testing.expectEqualStrings("Nhfg3TbpwogLvDGVvAvqyThbsHgoSUKwtn", s);
}

test "user id from known wif public key" {
    const expected = [_]u8{
        0x35, 0xee, 0x9e, 0xa2, 0x2c, 0x27, 0xe3, 0x4b, 0xd0, 0x14,
        0x8f, 0xc4, 0x10, 0x8e, 0x08, 0xf7, 0x4e, 0x8f, 0x50, 0x48,
        0xb2, 0xf1, 0x95, 0xca, 0x73,
    };
    var pubkey: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, "02b3622bf4017bdfe317c58aed5f4c753f206b7db896046fa7d774bbc4bf7f8dc2");
    const id = ID.fromCompressedPublicKey(pubkey);
    try std.testing.expectEqualSlices(u8, &expected, &id.bytes);
}

test "user id validates checksum and prefix" {
    var pubkey: [33]u8 = undefined;
    @memset(&pubkey, 0x42);
    pubkey[0] = 0x02;
    const id = ID.fromCompressedPublicKey(pubkey);
    const parsed = try ID.fromRaw(id.bytes);
    try std.testing.expect(!parsed.isZeroID());

    var bad = id.bytes;
    bad[0] = 0x00;
    try std.testing.expectError(error.InvalidPrefix, ID.fromRaw(bad));
}
