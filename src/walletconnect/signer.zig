const std = @import("std");
const sign_client = @import("sign_client.zig");
const neon = @import("neon.zig");
const signer_mod = @import("../crypto/signer.zig");
const sig = @import("../crypto/signature.zig");
const stable = @import("../internal/proto/stable.zig");
const refs_pb = @import("../proto/gen/refs/types.pb.zig");

pub const sign_message_version_classic: u8 = 1;
pub const sign_message_version_default: u8 = 2;
pub const sign_message_version_without_salt: u8 = 3;

pub const WalletConnectSigner = struct {
    client: *sign_client.SignClient,
    /// NeoFS request meta/body signatures must use the salt-wrapped (CLASSIC)
    /// format. Neon's DEFAULT (v=2) ignores the salt and signs only the bare
    /// message hex, which the NeoFS Go SDK's verifier rejects.
    request_version: u8 = sign_message_version_classic,

    pub fn init(client: *sign_client.SignClient) WalletConnectSigner {
        return .{ .client = client };
    }

    pub fn asSigner(self: *WalletConnectSigner) signer_mod.Signer {
        return .{
            .ctx = @ptrCast(self),
            .sign_fn = signRequest,
        };
    }

    pub fn signContainer(
        self: *WalletConnectSigner,
        allocator: std.mem.Allocator,
        container: stable.Container,
    ) !refs_pb.SignatureRFC6979 {
        const data = try stable.marshalMessage(allocator, stable.sizeContainer, stable.marshalContainer, container);
        defer allocator.free(data);
        const message_hex = try hexEncodeAlloc(allocator, data);
        defer allocator.free(message_hex);
        const wc_signed = try self.client.signMessage(message_hex, sign_message_version_without_salt);
        defer freeSignedMessage(allocator, wc_signed);
        const container_sig = try neon.toRFC6979ContainerSignature(allocator, wc_signed);
        try neon.verifyRFC6979SignedMessage(data, container_sig);
        return container_sig;
    }

    pub fn signContainerID(
        self: *WalletConnectSigner,
        allocator: std.mem.Allocator,
        container_id: [32]u8,
    ) !refs_pb.SignatureRFC6979 {
        const message_hex = try hexEncodeAlloc(allocator, &container_id);
        defer allocator.free(message_hex);
        const wc_signed = try self.client.signMessage(message_hex, sign_message_version_without_salt);
        defer freeSignedMessage(allocator, wc_signed);
        const container_sig = try neon.toRFC6979ContainerSignature(allocator, wc_signed);
        try neon.verifyRFC6979SignedMessage(&container_id, container_sig);
        return container_sig;
    }
};

fn signRequest(ctx: *anyopaque, allocator: std.mem.Allocator, data: []const u8) !sig.Signature {
    const self: *WalletConnectSigner = @ptrCast(@alignCast(ctx));
    const message_b64 = try base64EncodeAlloc(allocator, data);
    defer allocator.free(message_b64);
    const wc_signed = try self.client.signMessage(message_b64, self.request_version);
    defer freeSignedMessage(allocator, wc_signed);
    const signature = try neon.toNeoFSSignature(allocator, wc_signed);
    try neon.verifySignedMessagePayload(data, signature);
    return signature;
}

fn freeSignedMessage(allocator: std.mem.Allocator, msg: neon.SignedMessage) void {
    allocator.free(msg.data);
    if (msg.salt.len > 0) allocator.free(msg.salt);
    allocator.free(msg.public_key);
    allocator.free(msg.message_hex);
}

fn hexEncodeAlloc(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const alphabet = "0123456789abcdef";
    const out = try allocator.alloc(u8, data.len * 2);
    for (data, 0..) |b, i| {
        out[i * 2] = alphabet[(b >> 4) & 0x0F];
        out[i * 2 + 1] = alphabet[b & 0x0F];
    }
    return out;
}

fn base64EncodeAlloc(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const size = std.base64.standard.Encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, size);
    _ = std.base64.standard.Encoder.encode(out, data);
    return out;
}
