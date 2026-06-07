const std = @import("std");
const sig = @import("../../crypto/signature.zig");
const user = @import("../../user/id.zig");
const session_pb = @import("../../proto/gen/session/types.pb.zig");
const refs_pb = @import("../../proto/gen/refs/types.pb.zig");
const enc_v2 = @import("../../proto/session/encoding_v2.zig");

// Backward-compatible lightweight verb used by current pool placeholders.
pub const Verb = enum {
    container_put,
    container_delete,
    object_put,
    object_get,
    object_delete,
};

/// Minimal token state currently cached by pool. Additional helpers below expose
/// full SessionTokenV2 body/signature construction.
pub const Token = struct {
    verb: Verb,
    issuer: []const u8,
    target: []const u8,
    iat: u64,
    nbf: u64,
    exp: u64,
};

pub const Lifetime = struct {
    iat: u64,
    nbf: u64,
    exp: u64,
};

pub fn isWildcardContainerId(container_id: [32]u8) bool {
    return std.mem.eql(u8, &container_id, &std.mem.zeroes([32]u8));
}

pub fn isWildcardContainerValue(value: []const u8) bool {
    return value.len == 0 or (value.len == 32 and std.mem.eql(u8, value, &std.mem.zeroes([32]u8)));
}

/// Matches Go session.Context.protoMessage: wildcard contexts omit the container field.
pub fn normalizeSessionContextV2(ctx: *session_pb.SessionContextV2, allocator: std.mem.Allocator) void {
    if (ctx.container) |cid| {
        if (isWildcardContainerValue(cid.value)) {
            allocator.free(cid.value);
            ctx.container = null;
        }
    }
}

pub fn normalizeSessionTokenV2(allocator: std.mem.Allocator, tok: *session_pb.SessionTokenV2) void {
    if (tok.body) |*body| {
        for (body.contexts.items) |*ctx| {
            normalizeSessionContextV2(ctx, allocator);
        }
    }
    if (tok.origin) |origin| {
        normalizeSessionTokenV2(allocator, origin);
    }
}

pub fn newTargetUser(allocator: std.mem.Allocator, uid: user.ID) !session_pb.Target {
    return .{
        .identifier = .{
            .owner_id = .{ .value = try allocator.dupe(u8, &uid.bytes) },
        },
    };
}

pub fn newContext(
    allocator: std.mem.Allocator,
    container_id: [32]u8,
    verbs: []const session_pb.Verb,
) !session_pb.SessionContextV2 {
    var ctx: session_pb.SessionContextV2 = .{
        .container = null,
        .verbs = .empty,
    };
    errdefer ctx.deinit(allocator);
    if (!isWildcardContainerId(container_id)) {
        ctx.container = .{ .value = try allocator.dupe(u8, &container_id) };
    }
    try ctx.verbs.appendSlice(allocator, verbs);
    return ctx;
}

pub fn buildBody(
    allocator: std.mem.Allocator,
    issuer: user.ID,
    subjects: []const session_pb.Target,
    contexts: []const session_pb.SessionContextV2,
    lifetime: Lifetime,
) !session_pb.SessionTokenV2.Body {
    var body: session_pb.SessionTokenV2.Body = .{
        .version = 0,
        .issuer = .{ .value = try allocator.dupe(u8, &issuer.bytes) },
        .subjects = .empty,
        .lifetime = .{
            .iat = lifetime.iat,
            .nbf = lifetime.nbf,
            .exp = lifetime.exp,
        },
        .contexts = .empty,
    };
    errdefer body.deinit(allocator);
    try body.subjects.appendSlice(allocator, subjects);
    try body.contexts.appendSlice(allocator, contexts);
    return body;
}

pub fn signedData(allocator: std.mem.Allocator, body: session_pb.SessionTokenV2.Body) ![]u8 {
    return enc_v2.encodeSessionTokenV2Body(allocator, body);
}

pub fn signBody(
    allocator: std.mem.Allocator,
    scheme: sig.Scheme,
    signer_key: []const u8,
    body: session_pb.SessionTokenV2.Body,
) !refs_pb.Signature {
    const payload = try signedData(allocator, body);
    defer allocator.free(payload);
    const signature = try sig.sign(allocator, scheme, signer_key, payload);
    defer {
        allocator.free(signature.key);
        allocator.free(signature.value);
    }
    return .{
        .scheme = switch (signature.scheme) {
            .ecdsa_sha512 => .ECDSA_SHA512,
            .ecdsa_deterministic_sha256 => .ECDSA_RFC6979_SHA256,
            .ecdsa_walletconnect => .ECDSA_RFC6979_SHA256_WALLET_CONNECT,
            .n3 => .N3,
        },
        .key = try allocator.dupe(u8, signature.key),
        .sign = try allocator.dupe(u8, signature.value),
    };
}

test "normalizeSessionTokenV2 strips legacy zero container contexts" {
    const allocator = std.testing.allocator;
    const verbs = [_]session_pb.Verb{.CONTAINER_PUT};

    var ctx: session_pb.SessionContextV2 = .{
        .container = .{ .value = try allocator.dupe(u8, &std.mem.zeroes([32]u8)) },
        .verbs = .empty,
    };
    try ctx.verbs.appendSlice(allocator, &verbs);
    var body: session_pb.SessionTokenV2.Body = .{
        .contexts = .empty,
    };
    try body.contexts.append(allocator, ctx);
    var tok: session_pb.SessionTokenV2 = .{ .body = body };

    normalizeSessionTokenV2(allocator, &tok);
    defer tok.deinit(allocator);
    try std.testing.expect(tok.body.?.contexts.items[0].container == null);
}

test "wildcard context omits container field" {
    const allocator = std.testing.allocator;
    const verbs = [_]session_pb.Verb{.CONTAINER_PUT};

    var wildcard = try newContext(allocator, std.mem.zeroes([32]u8), &verbs);
    defer wildcard.deinit(allocator);
    try std.testing.expect(wildcard.container == null);

    var cid: [32]u8 = undefined;
    @memset(&cid, 0xAB);
    var explicit = try newContext(allocator, cid, &verbs);
    defer explicit.deinit(allocator);
    try std.testing.expect(explicit.container != null);

    const wildcard_size = enc_v2.sizeSessionContextV2(wildcard);
    const explicit_size = enc_v2.sizeSessionContextV2(explicit);
    try std.testing.expect(wildcard_size > 0);
    try std.testing.expect(wildcard_size < explicit_size);
}

pub fn buildToken(
    allocator: std.mem.Allocator,
    body: session_pb.SessionTokenV2.Body,
    signature: refs_pb.Signature,
    origin: ?session_pb.SessionTokenV2,
) !session_pb.SessionTokenV2 {
    var tok: session_pb.SessionTokenV2 = .{
        .body = try body.dupe(allocator),
        .signature = try signature.dupe(allocator),
    };
    if (origin) |o| {
        const p = try allocator.create(session_pb.SessionTokenV2);
        p.* = try o.dupe(allocator);
        tok.origin = p;
    }
    return tok;
}
