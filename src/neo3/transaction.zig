const std = @import("std");
const csprng = @import("../crypto/csprng.zig");
const keys = @import("../crypto/ecdsa/keys.zig");
const io_mod = @import("io.zig");
const hash_mod = @import("hash.zig");

pub const WitnessScope = enum(u8) {
    called_by_entry = 0x01,
};

pub const Signer = struct {
    account: hash_mod.Hash160,
    scopes: WitnessScope,
};

pub const Witness = struct {
    invocation: []const u8,
    verification: []const u8,
};

pub const Transaction = struct {
    version: u8 = 0,
    nonce: u32 = 0,
    system_fee: i64 = 0,
    network_fee: i64 = 0,
    valid_until_block: u32 = 0,
    signers: []const Signer = &.{},
    attributes: []const u8 = &.{},
    script: []const u8 = &.{},
    witnesses: []Witness = &.{},

    pub fn hash(self: Transaction, allocator: std.mem.Allocator) !hash_mod.Hash256 {
        var w = io_mod.Writer.init(allocator);
        defer w.deinit(allocator);
        try self.encodeHashable(allocator, &w);
        return hash_mod.hash256(w.bytes());
    }

    pub fn encode(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
        var w = io_mod.Writer.init(allocator);
        defer w.deinit(allocator);
        try self.encodeHashable(allocator, &w);
        try w.writeVarUint(allocator, self.witnesses.len);
        for (self.witnesses) |witness| {
            try w.writeVarBytes(allocator, witness.invocation);
            try w.writeVarBytes(allocator, witness.verification);
        }
        return try allocator.dupe(u8, w.bytes());
    }

    pub fn encodeHashable(self: Transaction, allocator: std.mem.Allocator, w: *io_mod.Writer) !void {
        try w.writeByte(allocator, self.version);
        try w.writeU32LE(allocator, self.nonce);
        try w.writeU64LE(allocator, @intCast(self.system_fee));
        try w.writeU64LE(allocator, @intCast(self.network_fee));
        try w.writeU32LE(allocator, self.valid_until_block);
        try w.writeVarUint(allocator, self.signers.len);
        for (self.signers) |signer| {
            try w.writeBytes(allocator, &signer.account);
            try w.writeByte(allocator, @intFromEnum(signer.scopes));
        }
        try w.writeVarUint(allocator, 0);
        try w.writeVarBytes(allocator, self.script);
    }

    pub fn sign(
        self: *Transaction,
        allocator: std.mem.Allocator,
        kp: keys.KeyPair,
        network_magic: u32,
    ) !void {
        const tx_hash = try self.hash(allocator);
        const sig = try hash_mod.signHashable(allocator, kp, network_magic, tx_hash);
        defer allocator.free(sig);

        var invocation: [66]u8 = undefined;
        invocation[0] = 0x0C;
        invocation[1] = 64;
        @memcpy(invocation[2..66], sig[0..64]);

        if (self.witnesses.len != 1) return error.InvalidWitnessCount;
        if (self.witnesses[0].invocation.len != 0) allocator.free(self.witnesses[0].invocation);
        self.witnesses[0].invocation = try allocator.dupe(u8, invocation[0..66]);
    }
};

pub fn randomNonce() u32 {
    var raw: [4]u8 = undefined;
    csprng.randomBytes(&raw);
    return std.mem.readInt(u32, &raw, .little);
}

pub const NetworkMagic = enum(u32) {
    mainnet = 0x334f454e,
    testnet = 0x3554334e,
};
