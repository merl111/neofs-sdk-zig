const std = @import("std");
const signature = @import("signature.zig");

pub const SignFn = *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, data: []const u8) anyerror!signature.Signature;

pub const Signer = struct {
    ctx: *anyopaque,
    sign_fn: SignFn,

    pub fn sign(self: Signer, allocator: std.mem.Allocator, data: []const u8) !signature.Signature {
        return self.sign_fn(self.ctx, allocator, data);
    }
};

pub const LocalSigner = struct {
    secret: []const u8,
    scheme: signature.Scheme = .ecdsa_deterministic_sha256,

    pub fn asSigner(self: *const LocalSigner) Signer {
        return .{
            .ctx = @constCast(@ptrCast(self)),
            .sign_fn = signLocal,
        };
    }
};

fn signLocal(ctx: *anyopaque, allocator: std.mem.Allocator, data: []const u8) !signature.Signature {
    const local: *const LocalSigner = @ptrCast(@alignCast(ctx));
    return signature.sign(allocator, local.scheme, local.secret, data);
}

