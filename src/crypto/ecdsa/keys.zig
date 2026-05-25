const std = @import("std");
const sig = @import("../signature.zig");

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP256Sha512 = std.crypto.sign.ecdsa.Ecdsa(
    std.crypto.ecc.P256,
    std.crypto.hash.sha2.Sha512,
);

pub const KeyPair = struct {
    inner: EcdsaP256Sha256.KeyPair,

    pub fn fromSeed(seed: [32]u8) !KeyPair {
        return .{ .inner = try EcdsaP256Sha256.KeyPair.fromSecretKey(.{ .bytes = seed }) };
    }

    pub fn fromSecretBytes(bytes: []const u8) !KeyPair {
        var seed: [32]u8 = undefined;
        if (bytes.len == 32) {
            @memcpy(&seed, bytes);
        } else {
            std.crypto.hash.sha2.Sha256.hash(bytes, &seed, .{});
        }
        return fromSeed(seed);
    }

    pub fn publicKeyBytes(self: KeyPair) [33]u8 {
        return self.inner.public_key.toCompressedSec1();
    }

    pub fn sign(self: KeyPair, allocator: std.mem.Allocator, scheme: sig.Scheme, data: []const u8) !sig.Signature {
        const value = switch (scheme) {
            .ecdsa_sha512 => try signSha512(allocator, self, data),
            .ecdsa_deterministic_sha256 => try signRfc6979(allocator, self, data),
            .ecdsa_walletconnect => try signWalletConnect(allocator, self, data),
            .n3 => return error.UnsupportedScheme,
        };
        const key = try allocator.dupe(u8, &self.publicKeyBytes());
        return .{ .scheme = scheme, .key = key, .value = value };
    }
};

fn signSha512(allocator: std.mem.Allocator, kp: KeyPair, data: []const u8) ![]u8 {
    var digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(data, &digest, .{});
    const sha512_kp = try EcdsaP256Sha512.KeyPair.fromSecretKey(.{ .bytes = kp.inner.secret_key.bytes });
    const signature = try sha512_kp.signPrehashed(digest, null);
    const raw = signature.toBytes();
    var out = try allocator.alloc(u8, 65);
    out[0] = 0x04;
    @memcpy(out[1..33], raw[0..32]);
    @memcpy(out[33..65], raw[32..64]);
    return out;
}

fn signRfc6979(allocator: std.mem.Allocator, kp: KeyPair, data: []const u8) ![]u8 {
    const signature = try kp.inner.sign(data, null);
    return allocator.dupe(u8, &signature.toBytes());
}

fn signWalletConnect(allocator: std.mem.Allocator, kp: KeyPair, data: []const u8) ![]u8 {
    const b64 = try encodeBase64(allocator, data);
    defer allocator.free(b64);
    var salt: [16]u8 = undefined;
    std.crypto.random.bytes(&salt);
    const salted = try saltMessageWalletConnect(allocator, salt, b64);
    defer allocator.free(salted);
    const signature = try kp.inner.sign(salted, null);
    var out = try allocator.alloc(u8, 80);
    @memcpy(out[0..64], &signature.toBytes());
    @memcpy(out[64..80], &salt);
    return out;
}

pub fn verify(scheme: sig.Scheme, public_key: []const u8, data: []const u8, signature: []const u8) bool {
    return switch (scheme) {
        .ecdsa_sha512 => verifySha512(public_key, data, signature),
        .ecdsa_deterministic_sha256 => verifyRfc6979(public_key, data, signature),
        .ecdsa_walletconnect => verifyWalletConnect(public_key, data, signature),
        .n3 => false,
    };
}

fn verifySha512(public_key: []const u8, data: []const u8, signature: []const u8) bool {
    if (signature.len != 65 or signature[0] != 0x04) return false;
    const pk = EcdsaP256Sha512.PublicKey.fromSec1(public_key) catch return false;
    var digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(data, &digest, .{});
    var raw: [64]u8 = undefined;
    @memcpy(raw[0..32], signature[1..33]);
    @memcpy(raw[32..64], signature[33..65]);
    const sig_obj = EcdsaP256Sha512.Signature.fromBytes(raw);
    sig_obj.verifyPrehashed(digest, pk) catch return false;
    return true;
}

fn verifyRfc6979(public_key: []const u8, data: []const u8, signature: []const u8) bool {
    if (signature.len != 64) return false;
    const pk = EcdsaP256Sha256.PublicKey.fromSec1(public_key) catch return false;
    var raw: [64]u8 = undefined;
    @memcpy(&raw, signature[0..64]);
    const sig_obj = EcdsaP256Sha256.Signature.fromBytes(raw);
    sig_obj.verify(data, pk) catch return false;
    return true;
}

fn verifyWalletConnect(public_key: []const u8, data: []const u8, signature: []const u8) bool {
    if (signature.len != 80) return false;
    const pk = EcdsaP256Sha256.PublicKey.fromSec1(public_key) catch return false;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const b64 = encodeBase64(allocator, data) catch return false;
    defer allocator.free(b64);
    var salt: [16]u8 = undefined;
    @memcpy(&salt, signature[64..80]);
    const salted = saltMessageWalletConnect(allocator, salt, b64) catch return false;
    defer allocator.free(salted);
    var raw: [64]u8 = undefined;
    @memcpy(&raw, signature[0..64]);
    const sig_obj = EcdsaP256Sha256.Signature.fromBytes(raw);
    sig_obj.verify(salted, pk) catch return false;
    return true;
}

fn saltMessageWalletConnect(allocator: std.mem.Allocator, salt: [16]u8, b64: []const u8) ![]u8 {
    const salt_hex_buf = std.fmt.bytesToHex(salt, .lower);
    const salt_hex = try allocator.dupe(u8, &salt_hex_buf);
    defer allocator.free(salt_hex);
    var out: std.ArrayList(u8) = .{};
    defer out.deinit(allocator);
    try out.appendSlice(allocator, &[_]u8{ 0x01, 0x00, 0x01, 0xf0 });
    var tmp: [9]u8 = undefined;
    const n = putNeoVarUint(&tmp, salt_hex.len + b64.len);
    try out.appendSlice(allocator, tmp[0..n]);
    try out.appendSlice(allocator, salt_hex);
    try out.appendSlice(allocator, b64);
    try out.appendSlice(allocator, &[_]u8{ 0x00, 0x00 });
    return out.toOwnedSlice(allocator);
}

/// Neo `io.PutVarUint` encoding: 1 byte when value < 0xFD, otherwise marker
/// (0xFD / 0xFE / 0xFF) followed by 2/4/8 little-endian bytes.
fn putNeoVarUint(out: []u8, value: u64) usize {
    if (value < 0xFD) {
        out[0] = @intCast(value);
        return 1;
    }
    if (value <= 0xFFFF) {
        out[0] = 0xFD;
        std.mem.writeInt(u16, out[1..3], @intCast(value), .little);
        return 3;
    }
    if (value <= 0xFFFFFFFF) {
        out[0] = 0xFE;
        std.mem.writeInt(u32, out[1..5], @intCast(value), .little);
        return 5;
    }
    out[0] = 0xFF;
    std.mem.writeInt(u64, out[1..9], value, .little);
    return 9;
}

fn encodeBase64(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const size = std.base64.standard.Encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, size);
    _ = std.base64.standard.Encoder.encode(out, data);
    return out;
}

test "neo varuint encoding" {
    var buf: [9]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), putNeoVarUint(&buf, 0));
    try std.testing.expectEqual(@as(u8, 0), buf[0]);
    try std.testing.expectEqual(@as(usize, 1), putNeoVarUint(&buf, 0xFC));
    try std.testing.expectEqual(@as(u8, 0xFC), buf[0]);
    try std.testing.expectEqual(@as(usize, 3), putNeoVarUint(&buf, 0xFD));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xFD, 0xFD, 0x00 }, buf[0..3]);
    try std.testing.expectEqual(@as(usize, 3), putNeoVarUint(&buf, 0x1234));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xFD, 0x34, 0x12 }, buf[0..3]);
    try std.testing.expectEqual(@as(usize, 5), putNeoVarUint(&buf, 0x10000));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xFE, 0x00, 0x00, 0x01, 0x00 }, buf[0..5]);
}

test "walletconnect salted message roundtrip large payload" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x33);
    const kp = try KeyPair.fromSeed(seed);
    // Use a payload large enough that salt_hex.len + b64.len >= 128, exercising
    // the Neo VarUint two-byte length encoding path.
    var payload: [200]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i & 0xff);
    const s = try kp.sign(allocator, .ecdsa_walletconnect, &payload);
    defer allocator.free(s.key);
    defer allocator.free(s.value);
    try std.testing.expect(verify(.ecdsa_walletconnect, s.key, &payload, s.value));
}

test "ecdsa rfc6979 roundtrip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try KeyPair.fromSeed(seed);
    const s = try kp.sign(gpa.allocator(), .ecdsa_deterministic_sha256, "message");
    defer gpa.allocator().free(s.key);
    defer gpa.allocator().free(s.value);
    try std.testing.expect(verify(.ecdsa_deterministic_sha256, s.key, "message", s.value));
}
