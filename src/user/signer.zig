const std = @import("std");
const id = @import("id.zig");
const sig = @import("../crypto/signature.zig");

pub const Signer = struct {
    key: []const u8,

    pub fn userID(self: Signer) id.ID {
        return id.ID.fromPublicKey(self.key);
    }

    pub fn sign(self: Signer, allocator: std.mem.Allocator, data: []const u8) !sig.Signature {
        return sig.sign(allocator, .ecdsa_deterministic_sha256, self.key, data);
    }
};
