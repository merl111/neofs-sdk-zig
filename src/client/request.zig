const std = @import("std");
const version = @import("../version/version.zig");
const crypto_proto = @import("../crypto/proto.zig");
const signer_mod = @import("../crypto/signer.zig");
const sig = @import("../crypto/signature.zig");
const signing = @import("../internal/proto/signing.zig");
const session_pb = @import("../proto/gen/session/types.pb.zig");
const session_v2 = @import("../session/v2/token.zig");
const refs_pb = @import("../proto/gen/refs/types.pb.zig");

pub const default_request_ttl: u32 = 2;

pub fn defaultMetaHeader(_: std.mem.Allocator) !session_pb.RequestMetaHeader {
    const v = version.current();
    return .{
        .version = .{
            .major = v.major,
            .minor = v.minor,
        },
        .ttl = default_request_ttl,
        .epoch = 0,
    };
}

pub fn makeAddress(allocator: std.mem.Allocator, container_id: [32]u8, object_id: [32]u8) !refs_pb.Address {
    return .{
        .container_id = .{ .value = try allocator.dupe(u8, &container_id) },
        .object_id = .{ .value = try allocator.dupe(u8, &object_id) },
    };
}

pub fn makeContainerID(allocator: std.mem.Allocator, id: [32]u8) !refs_pb.ContainerID {
    return .{ .value = try allocator.dupe(u8, &id) };
}

pub fn makeObjectID(allocator: std.mem.Allocator, id: [32]u8) !refs_pb.ObjectID {
    return .{ .value = try allocator.dupe(u8, &id) };
}

pub fn encodeMessage(allocator: std.mem.Allocator, msg: anytype) ![]u8 {
    var w: std.Io.Writer.Allocating = .init(allocator);
    defer w.deinit();
    try msg.encode(&w.writer, allocator);
    return try allocator.dupe(u8, w.written());
}

pub fn toProtoSignature(allocator: std.mem.Allocator, signature: sig.Signature) !refs_pb.Signature {
    return .{
        .key = try allocator.dupe(u8, signature.key),
        .sign = try allocator.dupe(u8, signature.value),
        .scheme = switch (signature.scheme) {
            .ecdsa_sha512 => .ECDSA_SHA512,
            .ecdsa_deterministic_sha256 => .ECDSA_RFC6979_SHA256,
            .ecdsa_walletconnect => .ECDSA_RFC6979_SHA256_WALLET_CONNECT,
            .n3 => .N3,
        },
    };
}

fn fromProtoSignature(proto_sig: refs_pb.Signature) !sig.Signature {
    return .{
        .scheme = switch (proto_sig.scheme) {
            .ECDSA_SHA512 => .ecdsa_sha512,
            .ECDSA_RFC6979_SHA256 => .ecdsa_deterministic_sha256,
            .ECDSA_RFC6979_SHA256_WALLET_CONNECT => .ecdsa_walletconnect,
            .N3 => .n3,
            else => return error.UnsupportedSignatureScheme,
        },
        .key = proto_sig.key,
        .value = proto_sig.sign,
    };
}

pub fn verifySignedRequestMessage(request_msg: anytype) !void {
    const vh = request_msg.verify_header orelse return error.MissingVerifyHeader;
    const meta = request_msg.meta_header orelse return error.MissingMetaHeader;

    const meta_bytes = try signing.encode(std.heap.page_allocator, meta);
    defer std.heap.page_allocator.free(meta_bytes);

    const body_bytes = blk: {
        if (@hasField(@TypeOf(request_msg), "body")) {
            const BodyType = std.meta.Child(@TypeOf(request_msg.body));
            const body = request_msg.body orelse @as(BodyType, .{});
            break :blk try signing.encode(std.heap.page_allocator, body);
        }
        break :blk try signing.encode(std.heap.page_allocator, request_msg);
    };
    defer std.heap.page_allocator.free(body_bytes);

    const meta_sig = try fromProtoSignature(vh.meta_signature orelse return error.MissingMetaSignature);
    if (!sig.verify(meta_sig.key, meta_bytes, meta_sig)) return error.MetaSignatureMismatch;

    const origin_sig = try fromProtoSignature(vh.origin_signature orelse return error.MissingOriginSignature);
    if (!sig.verify(origin_sig.key, "", origin_sig)) return error.OriginSignatureMismatch;

    const body_sig_proto = vh.body_signature orelse return error.MissingBodySignature;
    const body_sig = try fromProtoSignature(body_sig_proto);
    if (!sig.verify(body_sig.key, body_bytes, body_sig)) return error.BodySignatureMismatch;
}

pub fn toProtoVerifyHeader(
    allocator: std.mem.Allocator,
    header: *const crypto_proto.RequestVerificationHeader,
) !session_pb.RequestVerificationHeader {
    var out = session_pb.RequestVerificationHeader{
        .meta_signature = try toProtoSignature(allocator, header.meta_signature),
        .origin_signature = try toProtoSignature(allocator, header.origin_signature),
    };
    if (header.body_signature) |body| {
        out.body_signature = try toProtoSignature(allocator, body);
    }
    if (header.origin) |origin| {
        const owned = try allocator.create(session_pb.RequestVerificationHeader);
        owned.* = try toProtoVerifyHeader(allocator, origin);
        out.origin = owned;
    }
    return out;
}

/// Returns a shallow copy of `request_msg` with verification header attached.
/// Only deinit the returned request; do not deinit the input separately.
pub fn signRequestMessage(
    allocator: std.mem.Allocator,
    signer_key: []const u8,
    request_msg: anytype,
    meta_msg: session_pb.RequestMetaHeader,
) !@TypeOf(request_msg) {
    var local = signer_mod.LocalSigner{ .secret = signer_key };
    return signRequestMessageWithSigner(allocator, local.asSigner(), request_msg, meta_msg);
}

pub fn signRequestMessageWithSigner(
    allocator: std.mem.Allocator,
    signer: signer_mod.Signer,
    request_msg: anytype,
    meta_msg: session_pb.RequestMetaHeader,
) !@TypeOf(request_msg) {
    var meta = meta_msg;
    if (meta.session_token_v2) |*tok| {
        session_v2.normalizeSessionTokenV2(allocator, tok);
    }

    const body_bytes = blk: {
        if (@hasField(@TypeOf(request_msg), "body")) {
            const BodyType = std.meta.Child(@TypeOf(request_msg.body));
            const body = request_msg.body orelse @as(BodyType, .{});
            break :blk try signing.encode(allocator, body);
        }
        break :blk try signing.encode(allocator, request_msg);
    };
    defer allocator.free(body_bytes);
    const meta_bytes = try signing.encode(allocator, meta);
    defer allocator.free(meta_bytes);

    var scratch: [4096]u8 = undefined;
    const signed = try crypto_proto.signRequestWithBuffer(allocator, signer, .{
        .body = body_bytes,
        .meta_chain = &.{meta_bytes},
        .verify_header = null,
    }, &scratch);
    defer crypto_proto.freeVerificationHeader(allocator, signed);

    var request = request_msg;
    request.meta_header = meta;
    request.verify_header = try toProtoVerifyHeader(allocator, signed);
    try verifySignedRequestMessage(request);
    return request;
}

test "signed container put request with session token v2 survives protobuf round trip" {
    const allocator = std.testing.allocator;
    const container_pb = @import("../proto/gen/container/types.pb.zig");
    const container_init = @import("../container/init.zig");
    const crypto_ecdsa = @import("../crypto/ecdsa/keys.zig");

    const user = @import("../user/id.zig");
    const owner_seed = [_]u8{0x11} ** 32;
    const delegate_seed = [_]u8{0x22} ** 32;
    const owner_kp = try crypto_ecdsa.KeyPair.fromSeed(owner_seed);
    const delegate_kp = try crypto_ecdsa.KeyPair.fromSeed(delegate_seed);
    const owner = user.ID.fromCompressedPublicKey(owner_kp.publicKeyBytes());
    const delegate_user = user.ID.fromCompressedPublicKey(delegate_kp.publicKeyBytes());

    const nonce = try container_init.randomNonce(allocator);
    defer allocator.free(nonce);
    const cont = try container_init.newContainer(allocator, owner, nonce, "test");
    defer container_init.deinitContainer(allocator, cont);

    const now: u64 = 1_700_000_000;
    const verbs = [_]session_pb.Verb{.CONTAINER_PUT};
    const subject = try session_v2.newTargetUser(allocator, delegate_user);
    const context = try session_v2.newContext(allocator, std.mem.zeroes([32]u8), &verbs);
    const body = try session_v2.buildBody(allocator, owner, &.{subject}, &.{context}, .{
        .iat = now,
        .nbf = now,
        .exp = now + 3600,
    });
    defer {
        var b = body;
        b.deinit(allocator);
    }
    const token_sig = try session_v2.signBody(allocator, .ecdsa_deterministic_sha256, &delegate_seed, body);
    defer {
        var s = token_sig;
        s.deinit(allocator);
    }
    var wc_token_sig = token_sig;
    wc_token_sig.scheme = .ECDSA_RFC6979_SHA256_WALLET_CONNECT;
    wc_token_sig.sign = try allocator.dupe(u8, &([_]u8{0xCD} ** 80));
    defer allocator.free(wc_token_sig.sign);
    var session_token = try session_v2.buildToken(allocator, body, wc_token_sig, null);
    defer session_token.deinit(allocator);

    const container_sig = try container_init.signContainer(allocator, &delegate_seed, cont);
    defer {
        allocator.free(container_sig.key);
        allocator.free(container_sig.sign);
    }
    const put_body = try container_init.toPutRequestBody(allocator, cont, container_sig);
    var meta = try defaultMetaHeader(allocator);
    meta.session_token_v2 = try session_token.dupe(allocator);
    const req = container_pb.PutRequest{
        .body = put_body,
        .meta_header = meta,
    };

    var delegate_signer = signer_mod.LocalSigner{ .secret = &delegate_seed };
    var signed = try signRequestMessageWithSigner(allocator, delegate_signer.asSigner(), req, req.meta_header.?);
    defer signed.deinit(allocator);

    var w: std.Io.Writer.Allocating = .init(allocator);
    defer w.deinit();
    try signed.encode(&w.writer, allocator);
    var reader = std.Io.Reader.fixed(w.written());
    var decoded = try container_pb.PutRequest.decode(&reader, allocator);
    defer decoded.deinit(allocator);

    try verifySignedRequestMessage(decoded);
}

fn testSignedRequestRoundTrip(
    allocator: std.mem.Allocator,
    signed: anytype,
    comptime ResponseType: type,
) !void {
    var w: std.Io.Writer.Allocating = .init(allocator);
    defer w.deinit();
    try signed.encode(&w.writer, allocator);
    var reader = std.Io.Reader.fixed(w.written());
    var decoded = try ResponseType.decode(&reader, allocator);
    defer decoded.deinit(allocator);
    try verifySignedRequestMessage(decoded);
}

fn testDelegatedSessionTokenV2(
    allocator: std.mem.Allocator,
    container_id: [32]u8,
    verb: session_pb.Verb,
) !session_pb.SessionTokenV2 {
    const crypto_ecdsa = @import("../crypto/ecdsa/keys.zig");
    const user_mod = @import("../user/id.zig");

    const owner_seed = [_]u8{0x31} ** 32;
    const delegate_seed = [_]u8{0x32} ** 32;
    const owner_kp = try crypto_ecdsa.KeyPair.fromSeed(owner_seed);
    const owner = user_mod.ID.fromCompressedPublicKey(owner_kp.publicKeyBytes());

    const now: u64 = 1_700_000_000;
    const subject = try session_v2.newTargetUser(allocator, owner);
    const context = try session_v2.newContext(allocator, container_id, &.{verb});
    const body = try session_v2.buildBody(allocator, owner, &.{subject}, &.{context}, .{
        .iat = now,
        .nbf = now,
        .exp = now + 3600,
    });
    defer {
        var b = body;
        b.deinit(allocator);
    }
    const token_sig = try session_v2.signBody(allocator, .ecdsa_deterministic_sha256, &delegate_seed, body);
    defer {
        var s = token_sig;
        s.deinit(allocator);
    }
    return try session_v2.buildToken(allocator, body, token_sig, null);
}

test "signed session v2 object requests survive protobuf round trip" {
    const allocator = std.testing.allocator;
    const object_pb = @import("../proto/gen/object/types.pb.zig");

    var container_id: [32]u8 = undefined;
    @memset(&container_id, 0x44);
    var object_id: [32]u8 = undefined;
    @memset(&object_id, 0x55);

    const delegate_seed = [_]u8{0x32} ** 32;
    var delegate_signer = signer_mod.LocalSigner{ .secret = &delegate_seed };

    var object_token = try testDelegatedSessionTokenV2(allocator, container_id, .OBJECT_GET);
    defer object_token.deinit(allocator);
    var meta = try defaultMetaHeader(allocator);
    meta.session_token_v2 = try object_token.dupe(allocator);

    const head_req = object_pb.HeadRequest{
        .body = .{
            .address = try makeAddress(allocator, container_id, object_id),
            .raw = true,
        },
        .meta_header = meta,
    };
    var signed_head = try signRequestMessageWithSigner(allocator, delegate_signer.asSigner(), head_req, head_req.meta_header.?);
    defer signed_head.deinit(allocator);
    try testSignedRequestRoundTrip(allocator, signed_head, object_pb.HeadRequest);

    var delete_meta = try defaultMetaHeader(allocator);
    delete_meta.session_token_v2 = try object_token.dupe(allocator);
    const delete_req = object_pb.DeleteRequest{
        .body = .{
            .address = try makeAddress(allocator, container_id, object_id),
        },
        .meta_header = delete_meta,
    };
    var signed_delete = try signRequestMessageWithSigner(allocator, delegate_signer.asSigner(), delete_req, delete_req.meta_header.?);
    defer signed_delete.deinit(allocator);
    try testSignedRequestRoundTrip(allocator, signed_delete, object_pb.DeleteRequest);

    var search_meta = try defaultMetaHeader(allocator);
    search_meta.session_token_v2 = try object_token.dupe(allocator);
    var search_body = object_pb.SearchV2Request.Body{
        .container_id = .{ .value = try allocator.dupe(u8, &container_id) },
        .attributes = .empty,
    };
    try search_body.attributes.append(allocator, try allocator.dupe(u8, "FileName"));
    const search_req = object_pb.SearchV2Request{
        .body = search_body,
        .meta_header = search_meta,
    };
    var signed_search = try signRequestMessageWithSigner(allocator, delegate_signer.asSigner(), search_req, search_req.meta_header.?);
    defer signed_search.deinit(allocator);
    try testSignedRequestRoundTrip(allocator, signed_search, object_pb.SearchV2Request);
}

test "legacy zero container session token v2 normalizes before signing" {
    const allocator = std.testing.allocator;
    const container_pb = @import("../proto/gen/container/types.pb.zig");
    const crypto_ecdsa = @import("../crypto/ecdsa/keys.zig");
    const user_mod = @import("../user/id.zig");

    const delegate_seed = [_]u8{0x42} ** 32;
    const delegate_kp = try crypto_ecdsa.KeyPair.fromSeed(delegate_seed);
    const delegate_user = user_mod.ID.fromCompressedPublicKey(delegate_kp.publicKeyBytes());

    const now: u64 = 1_700_000_000;
    const subject = try session_v2.newTargetUser(allocator, delegate_user);
    const context = try session_v2.newContext(allocator, std.mem.zeroes([32]u8), &.{session_pb.Verb.CONTAINER_PUT});
    const body = try session_v2.buildBody(allocator, delegate_user, &.{subject}, &.{context}, .{
        .iat = now,
        .nbf = now,
        .exp = now + 3600,
    });
    defer {
        var b = body;
        b.deinit(allocator);
    }
    var legacy_token = try session_v2.buildToken(allocator, body, .{
        .scheme = .ECDSA_RFC6979_SHA256,
        .key = &.{},
        .sign = &.{},
    }, null);
    defer legacy_token.deinit(allocator);
    legacy_token.body.?.contexts.items[0].container = .{
        .value = try allocator.dupe(u8, &std.mem.zeroes([32]u8)),
    };

    var meta = try defaultMetaHeader(allocator);
    meta.session_token_v2 = try legacy_token.dupe(allocator);
    const req = container_pb.PutRequest{
        .body = .{},
        .meta_header = meta,
    };

    var delegate_signer = signer_mod.LocalSigner{ .secret = &delegate_seed };
    var signed = try signRequestMessageWithSigner(allocator, delegate_signer.asSigner(), req, req.meta_header.?);
    defer signed.deinit(allocator);
    try std.testing.expect(signed.meta_header.?.session_token_v2.?.body.?.contexts.items[0].container == null);
    try testSignedRequestRoundTrip(allocator, signed, container_pb.PutRequest);
}

test "signed balance request survives protobuf round trip" {
    const allocator = std.testing.allocator;
    const accounting_pb = @import("../proto/gen/accounting/types.pb.zig");
    const user = @import("../user/id.zig");

    const owner = user.ID.fromCompressedPublicKey([_]u8{0x02} ** 33);
    const req = accounting_pb.BalanceRequest{
        .body = .{
            .owner_id = .{ .value = try allocator.dupe(u8, &owner.bytes) },
        },
        .meta_header = try defaultMetaHeader(allocator),
    };
    var signed = try signRequestMessage(allocator, "secret-key-material", req, req.meta_header.?);
    defer signed.deinit(allocator);

    var w: std.Io.Writer.Allocating = .init(allocator);
    defer w.deinit();
    try signed.encode(&w.writer, allocator);
    var reader = std.Io.Reader.fixed(w.written());
    var decoded = try accounting_pb.BalanceRequest.decode(&reader, allocator);
    defer decoded.deinit(allocator);

    try verifySignedRequestMessage(decoded);
}
