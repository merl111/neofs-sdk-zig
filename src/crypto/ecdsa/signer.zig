const std = @import("std");
const sig = @import("../signature.zig");
const keys = @import("keys.zig");

pub const Signer = struct {
    secret: []const u8,

    pub fn sign(self: Signer, allocator: std.mem.Allocator, data: []const u8) !sig.Signature {
        return sig.sign(allocator, .ecdsa_deterministic_sha256, self.secret, data);
    }

    pub fn publicKeyBytes(self: Signer) ![33]u8 {
        const kp = try keys.KeyPair.fromSecretBytes(self.secret);
        return kp.publicKeyBytes();
    }
};
