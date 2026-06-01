const std = @import("std");
const keys = @import("../crypto/ecdsa/keys.zig");

pub const Hash160 = [20]u8;
pub const Hash256 = [32]u8;

pub fn hash160(data: []const u8) Hash160 {
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &sha, .{});
    return @import("../crypto/ripemd160.zig").hash(&sha);
}

pub fn hash256(data: []const u8) Hash256 {
    var out: Hash256 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

pub fn netSignDigest(network_magic: u32, tx_hash: Hash256) Hash256 {
    var buf: [36]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], network_magic, .little);
    @memcpy(buf[4..36], &tx_hash);
    return hash256(&buf);
}

pub fn signHashable(
    allocator: std.mem.Allocator,
    kp: keys.KeyPair,
    network_magic: u32,
    tx_hash: Hash256,
) ![]u8 {
    const digest = netSignDigest(network_magic, tx_hash);
    const signature = try kp.inner.signPrehashed(digest, null);
    return allocator.dupe(u8, &signature.toBytes());
}

pub fn verificationScript(compressed_pubkey: *const [33]u8) [40]u8 {
    var script: [40]u8 = undefined;
    script[0] = 0x0C;
    script[1] = 0x21;
    @memcpy(script[2..35], compressed_pubkey);
    script[35] = 0x41;
    const syscall_name = "System.Crypto.CheckSig";
    const syscall_id = @import("interop.zig").syscallId(syscall_name);
    std.mem.writeInt(u32, script[36..40], syscall_id, .little);
    return script;
}

pub fn scriptHashFromAddress(id_bytes: [25]u8) Hash160 {
    var out: Hash160 = undefined;
    @memcpy(&out, id_bytes[1..21]);
    return out;
}

pub fn scriptHashLeHex(allocator: std.mem.Allocator, hash_be: Hash160) ![]u8 {
    var reversed: [20]u8 = undefined;
    for (0..20) |i| reversed[i] = hash_be[20 - i - 1];
    return std.fmt.allocPrint(allocator, "0x{x}", .{&reversed});
}

pub fn parseLeHexHash160(hex_with_prefix: []const u8) !Hash160 {
    const trimmed = if (std.mem.startsWith(u8, hex_with_prefix, "0x") or std.mem.startsWith(u8, hex_with_prefix, "0X"))
        hex_with_prefix[2..]
    else
        hex_with_prefix;
    if (trimmed.len != 40) return error.InvalidHash160;
    var le: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&le, trimmed);
    var be: Hash160 = undefined;
    for (0..20) |i| be[i] = le[20 - i - 1];
    return be;
}
