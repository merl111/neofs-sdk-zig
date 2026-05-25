const std = @import("std");
const signing = @import("../internal/proto/signing.zig");
const keys = @import("../crypto/ecdsa/keys.zig");
const user = @import("../user/id.zig");
const version = @import("../version/version.zig");
const tz = @import("../tzhash/root.zig");
const object_pb = @import("../proto/gen/object/types.pb.zig");
const refs_pb = @import("../proto/gen/refs/types.pb.zig");
const session_pb = @import("../proto/gen/session/types.pb.zig");

pub const PreparedObject = struct {
    header: object_pb.Header,
    object_id: [32]u8,
    object_signature: refs_pb.Signature,
};

pub const AttributeKV = struct {
    key: []const u8,
    value: []const u8,
};

pub fn preparePutObject(
    allocator: std.mem.Allocator,
    secret_key: []const u8,
    container_id: [32]u8,
    owner: user.ID,
    payload: []const u8,
    file_name: []const u8,
    creation_epoch: u64,
) !PreparedObject {
    return preparePutObjectCustom(allocator, secret_key, container_id, owner, payload, file_name, "text/plain", &.{}, creation_epoch, null);
}

pub fn preparePutObjectCustom(
    allocator: std.mem.Allocator,
    secret_key: []const u8,
    container_id: [32]u8,
    owner: user.ID,
    payload: []const u8,
    file_name: []const u8,
    content_type: []const u8,
    extra_attributes: []const AttributeKV,
    creation_epoch: u64,
    /// Optional v1 session token to embed in the object header. Required by
    /// neofs-node's AuthenticateObject when the request signer differs from
    /// the object owner (e.g. delegated WalletConnect session).
    header_session: ?session_pb.SessionToken,
) !PreparedObject {
    const kp = try keys.KeyPair.fromSecretBytes(secret_key);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    const homo_digest = tz.sum(payload);

    const v = version.current();

    var attrs: std.ArrayList(object_pb.Header.Attribute) = .{};
    try attrs.append(allocator, .{
        .key = try allocator.dupe(u8, "FileName"),
        .value = try allocator.dupe(u8, file_name),
    });
    try attrs.append(allocator, .{
        .key = try allocator.dupe(u8, "ContentType"),
        .value = try allocator.dupe(u8, content_type),
    });
    for (extra_attributes) |attr| {
        try attrs.append(allocator, .{
            .key = try allocator.dupe(u8, attr.key),
            .value = try allocator.dupe(u8, attr.value),
        });
    }

    const header = object_pb.Header{
        .version = .{ .major = v.major, .minor = v.minor },
        .container_id = .{ .value = try allocator.dupe(u8, &container_id) },
        .owner_id = .{ .value = try allocator.dupe(u8, &owner.bytes) },
        .creation_epoch = creation_epoch,
        .payload_length = payload.len,
        .payload_hash = .{
            .type = .SHA256,
            .sum = try allocator.dupe(u8, &digest),
        },
        .homomorphic_hash = .{
            .type = .TZ,
            .sum = try allocator.dupe(u8, &homo_digest),
        },
        .session_token = if (header_session) |s| try s.dupe(allocator) else null,
        .attributes = attrs,
    };

    const header_bytes = try signing.encode(allocator, header);
    defer allocator.free(header_bytes);
    var oid: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(header_bytes, &oid, .{});

    const oid_msg = refs_pb.ObjectID{ .value = &oid };
    const oid_bytes = try signing.encode(allocator, oid_msg);
    defer allocator.free(oid_bytes);
    const signature = try kp.sign(allocator, .ecdsa_deterministic_sha256, oid_bytes);

    return .{
        .header = header,
        .object_id = oid,
        .object_signature = .{
            .key = signature.key,
            .sign = signature.value,
            .scheme = .ECDSA_RFC6979_SHA256,
        },
    };
}

test {
    _ = @import("put_test.zig");
}

pub fn encodeObjectID(allocator: std.mem.Allocator, id: [32]u8) ![]u8 {
    return @import("../crypto/base58.zig").encode(allocator, &id);
}
