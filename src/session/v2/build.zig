const std = @import("std");
const user = @import("../../user/id.zig");
const sig = @import("../../crypto/signature.zig");
const session_pb = @import("../../proto/gen/session/types.pb.zig");
const token_v2 = @import("token.zig");

pub const BuildParams = struct {
    issuer: user.ID,
    subject: user.ID,
    container_id: [32]u8,
    verbs: []const session_pb.Verb,
    iat: u64,
    nbf: u64,
    exp: u64,
    scheme: sig.Scheme = .ecdsa_deterministic_sha256,
};

pub fn buildOriginToken(
    allocator: std.mem.Allocator,
    signer_key: []const u8,
    params: BuildParams,
) !session_pb.SessionTokenV2 {
    const subject = try token_v2.newTargetUser(allocator, params.subject);
    const context = try token_v2.newContext(allocator, params.container_id, params.verbs);
    const body = try token_v2.buildBody(allocator, params.issuer, &.{subject}, &.{context}, .{
        .iat = params.iat,
        .nbf = params.nbf,
        .exp = params.exp,
    });
    defer {
        var b = body;
        b.deinit(allocator);
    }
    const signature = try token_v2.signBody(allocator, params.scheme, signer_key, body);
    defer {
        var s = signature;
        s.deinit(allocator);
    }
    return token_v2.buildToken(allocator, body, signature, null);
}

pub fn buildDelegatedToken(
    allocator: std.mem.Allocator,
    signer_key: []const u8,
    origin: session_pb.SessionTokenV2,
    params: BuildParams,
) !session_pb.SessionTokenV2 {
    const subject = try token_v2.newTargetUser(allocator, params.subject);
    const context = try token_v2.newContext(allocator, params.container_id, params.verbs);
    const body = try token_v2.buildBody(allocator, params.issuer, &.{subject}, &.{context}, .{
        .iat = params.iat,
        .nbf = params.nbf,
        .exp = params.exp,
    });
    defer {
        var b = body;
        b.deinit(allocator);
    }
    const signature = try token_v2.signBody(allocator, params.scheme, signer_key, body);
    defer {
        var s = signature;
        s.deinit(allocator);
    }
    return token_v2.buildToken(allocator, body, signature, origin);
}
