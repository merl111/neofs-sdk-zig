const std = @import("std");
const signing = @import("../internal/proto/signing.zig");
const keys = @import("../crypto/ecdsa/keys.zig");
const user = @import("../user/id.zig");
const session_pb = @import("../proto/gen/session/types.pb.zig");
const refs_pb = @import("../proto/gen/refs/types.pb.zig");

pub const CreateResult = struct {
    id: [16]u8,
    session_key: []u8,
};

pub fn parseCreateResponse(allocator: std.mem.Allocator, body: session_pb.CreateResponse.Body) !CreateResult {
    if (body.id.len < 16) return error.InvalidSessionID;
    var id: [16]u8 = undefined;
    @memcpy(&id, body.id[0..16]);
    return .{
        .id = id,
        .session_key = try allocator.dupe(u8, body.session_key),
    };
}

fn buildObjectSessionBody(
    allocator: std.mem.Allocator,
    created: CreateResult,
    owner: user.ID,
    container_id: [32]u8,
    verb: session_pb.ObjectSessionContext.Verb,
    nbf_epoch: u64,
    exp_epoch: u64,
) !session_pb.SessionToken.Body {
    return .{
        .id = try allocator.dupe(u8, &created.id),
        .owner_id = .{ .value = try allocator.dupe(u8, &owner.bytes) },
        .lifetime = .{
            .exp = exp_epoch,
            .nbf = nbf_epoch,
            .iat = nbf_epoch,
        },
        .session_key = try allocator.dupe(u8, created.session_key),
        .context = .{ .object = .{
            .verb = verb,
            .target = blk: {
                var target: session_pb.ObjectSessionContext.Target = .{};
                if (!std.mem.eql(u8, &container_id, &std.mem.zeroes([32]u8))) {
                    target.container = .{ .value = try allocator.dupe(u8, &container_id) };
                }
                break :blk target;
            },
        } },
    };
}

fn signSessionTokenBody(
    allocator: std.mem.Allocator,
    secret_key: []const u8,
    body: session_pb.SessionToken.Body,
) !refs_pb.Signature {
    const body_bytes = try signing.encode(allocator, body);
    defer allocator.free(body_bytes);
    const kp = try keys.KeyPair.fromSecretBytes(secret_key);
    const signature = try kp.sign(allocator, .ecdsa_deterministic_sha256, body_bytes);
    return .{
        .key = signature.key,
        .sign = signature.value,
        .scheme = .ECDSA_RFC6979_SHA256,
    };
}

pub fn objectPutToken(
    allocator: std.mem.Allocator,
    secret_key: []const u8,
    created: CreateResult,
    owner: user.ID,
    container_id: [32]u8,
    nbf_epoch: u64,
    exp_epoch: u64,
) !session_pb.SessionToken {
    const body = try buildObjectSessionBody(allocator, created, owner, container_id, .PUT, nbf_epoch, exp_epoch);
    const signature = try signSessionTokenBody(allocator, secret_key, body);
    return .{ .body = body, .signature = signature };
}

pub fn objectDeleteToken(
    allocator: std.mem.Allocator,
    secret_key: []const u8,
    created: CreateResult,
    owner: user.ID,
    container_id: [32]u8,
    nbf_epoch: u64,
    exp_epoch: u64,
) !session_pb.SessionToken {
    const body = try buildObjectSessionBody(allocator, created, owner, container_id, .DELETE, nbf_epoch, exp_epoch);
    const signature = try signSessionTokenBody(allocator, secret_key, body);
    return .{ .body = body, .signature = signature };
}
