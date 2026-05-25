const std = @import("std");
const sig = @import("../crypto/signature.zig");
const user = @import("../user/id.zig");
const refs_pb = @import("../proto/gen/refs/types.pb.zig");

pub const Account = struct {
    blockchain: []const u8,
    network: []const u8,
    address: []const u8,
};

pub const SignedMessage = struct {
    data: []const u8,
    salt: []const u8,
    public_key: []const u8,
    message_hex: []const u8,
};

pub fn parseAccount(account: []const u8) !Account {
    var it = std.mem.splitScalar(u8, account, ':');
    const blockchain = it.next() orelse return error.InvalidAccount;
    const network = it.next() orelse return error.InvalidAccount;
    const address = it.next() orelse return error.InvalidAccount;
    if (it.next() != null) return error.InvalidAccount;
    return .{
        .blockchain = blockchain,
        .network = network,
        .address = address,
    };
}

pub fn userIDFromPublicKeyHex(public_key_hex: []const u8) !user.ID {
    if (public_key_hex.len != 66) return error.InvalidPublicKey;
    var key: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, public_key_hex);
    return user.ID.fromCompressedPublicKey(key);
}

/// Script hash in the byte order Neon expects for Hash160 / signer account fields.
pub fn scriptHashHex(allocator: std.mem.Allocator, address: []const u8) ![]u8 {
    const id = try user.ID.decodeString(allocator, address);
    var reversed: [20]u8 = undefined;
    for (0..20) |i| {
        reversed[i] = id.bytes[20 - i];
    }
    return std.fmt.allocPrint(allocator, "{x}", .{&reversed});
}

pub fn toWalletConnectSignature(allocator: std.mem.Allocator, data_hex: []const u8, salt_hex: []const u8) ![]u8 {
    if (salt_hex.len != 32) return error.InvalidSalt;
    if (data_hex.len != 128 and data_hex.len != 130) return error.InvalidSignature;

    var raw_sig = try allocator.alloc(u8, if (data_hex.len == 130) 65 else 64);
    defer allocator.free(raw_sig);
    _ = try std.fmt.hexToBytes(raw_sig, data_hex);
    const sig_64 = if (raw_sig.len == 65 and raw_sig[0] == 0x04) raw_sig[1..65] else raw_sig[0..64];

    var salt: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&salt, salt_hex);

    const out = try allocator.alloc(u8, 80);
    @memcpy(out[0..64], sig_64);
    @memcpy(out[64..80], &salt);
    return out;
}

pub fn toNeoFSSignature(allocator: std.mem.Allocator, msg: SignedMessage) !sig.Signature {
    const key = try allocator.alloc(u8, 33);
    if (msg.public_key.len != 66) return error.InvalidPublicKey;
    _ = try std.fmt.hexToBytes(key, msg.public_key);
    errdefer allocator.free(key);
    const value = if (msg.salt.len == 0)
        try rfc6979SignatureBytes(allocator, msg.data)
    else
        try toWalletConnectSignature(allocator, msg.data, msg.salt);
    errdefer allocator.free(value);
    const signature: sig.Signature = .{
        .scheme = if (msg.salt.len == 0) .ecdsa_deterministic_sha256 else .ecdsa_walletconnect,
        .key = key,
        .value = value,
    };
    return signature;
}

/// Verify a WalletConnect NeoFS signature against the payload bytes that were signed.
pub fn verifyNeoFSSignature(data: []const u8, signature: sig.Signature) bool {
    return sig.verify(signature.key, data, signature);
}

pub fn verifySignedMessagePayload(data: []const u8, signature: sig.Signature) !void {
    if (verifyNeoFSSignature(data, signature)) return;
    return error.SignatureMismatch;
}

pub fn toRFC6979ContainerSignature(allocator: std.mem.Allocator, msg: SignedMessage) !refs_pb.SignatureRFC6979 {
    const key = try allocator.alloc(u8, 33);
    if (msg.public_key.len != 66) return error.InvalidPublicKey;
    _ = try std.fmt.hexToBytes(key, msg.public_key);
    errdefer allocator.free(key);
    const sign = try rfc6979SignatureBytes(allocator, msg.data);
    errdefer allocator.free(sign);
    return .{ .key = key, .sign = sign };
}

pub fn verifyRFC6979ContainerSignature(data: []const u8, container_sig: refs_pb.SignatureRFC6979) bool {
    if (container_sig.key.len != 33 or container_sig.sign.len != 64) return false;
    return sig.verify(container_sig.key, data, .{
        .scheme = .ecdsa_deterministic_sha256,
        .key = container_sig.key,
        .value = container_sig.sign,
    });
}

pub fn verifyRFC6979SignedMessage(data: []const u8, container_sig: refs_pb.SignatureRFC6979) !void {
    if (verifyRFC6979ContainerSignature(data, container_sig)) return;
    return error.SignatureMismatch;
}

fn rfc6979SignatureBytes(allocator: std.mem.Allocator, data_hex: []const u8) ![]u8 {
    if (data_hex.len != 128 and data_hex.len != 130) return error.InvalidSignature;
    const raw_sig = try allocator.alloc(u8, if (data_hex.len == 130) 65 else 64);
    errdefer allocator.free(raw_sig);
    _ = try std.fmt.hexToBytes(raw_sig, data_hex);
    if (raw_sig.len == 65 and raw_sig[0] == 0x04) {
        return allocator.dupe(u8, raw_sig[1..65]);
    }
    return raw_sig;
}
