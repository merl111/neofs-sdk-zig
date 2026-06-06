const std = @import("std");
const marshal_stable = @import("testutil/marshal_stable.zig");

const accounting_pb = @import("proto/gen/accounting/types.pb.zig");
const acl_pb = @import("proto/gen/acl/types.pb.zig");
const audit_pb = @import("proto/gen/audit/types.pb.zig");
const container_pb = @import("proto/gen/container/types.pb.zig");
const link_pb = @import("proto/gen/link/types.pb.zig");
const lock_pb = @import("proto/gen/lock/types.pb.zig");
const netmap_pb = @import("proto/gen/netmap/types.pb.zig");
const object_pb = @import("proto/gen/object/types.pb.zig");
const refs_pb = @import("proto/gen/refs/types.pb.zig");
const reputation_pb = @import("proto/gen/reputation/types.pb.zig");
const session_pb = @import("proto/gen/session/types.pb.zig");
const status_pb = @import("proto/gen/status/types.pb.zig");
const storagegroup_pb = @import("proto/gen/storagegroup/types.pb.zig");
const subnet_pb = @import("proto/gen/subnet/types.pb.zig");
const tombstone_pb = @import("proto/gen/tombstone/types.pb.zig");

fn expectGoldenMatch(
    comptime Msg: type,
    allocator: std.mem.Allocator,
    domain: []const u8,
    msg: Msg,
) !void {
    const path = try std.fmt.allocPrint(allocator, "test/vectors/proto/{s}/roundtrip.bin", .{domain});
    defer allocator.free(path);

    const golden = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, std.Io.Limit.limited(1 << 20));
    defer allocator.free(golden);

    const encoded = try marshal_stable.encodeMessage(Msg, allocator, msg);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, golden, encoded);
}

test "proto golden vectors match neofs-sdk-go stable marshal" {
    const allocator = std.testing.allocator;

    try expectGoldenMatch(accounting_pb.Decimal, allocator, "accounting", .{ .value = 1, .precision = 1 });

    try expectGoldenMatch(
        acl_pb.BearerToken.Body.TokenLifetime,
        allocator,
        "acl",
        .{ .exp = 1, .nbf = 2, .iat = 3 },
    );

    try expectGoldenMatch(audit_pb.DataAuditResult, allocator, "audit", .{ .audit_epoch = 1 });

    try expectGoldenMatch(
        container_pb.Container.Attribute,
        allocator,
        "container",
        .{ .key = "k", .value = "v" },
    );

    try expectGoldenMatch(link_pb.Link.MeasuredObject, allocator, "link", .{ .size = 1 });

    {
        const oid_val = try allocator.dupe(u8, &[_]u8{1});
        var lock_msg: lock_pb.Lock = .{};
        try lock_msg.members.append(allocator, .{ .value = oid_val });
        defer lock_msg.deinit(allocator);
        try expectGoldenMatch(lock_pb.Lock, allocator, "lock", lock_msg);
    }

    try expectGoldenMatch(
        netmap_pb.Replica,
        allocator,
        "netmap",
        .{ .count = 1, .selector = "s" },
    );

    try expectGoldenMatch(object_pb.Range, allocator, "object", .{ .offset = 1, .length = 2 });

    try expectGoldenMatch(refs_pb.Version, allocator, "refs", .{ .major = 1, .minor = 2 });

    try expectGoldenMatch(
        reputation_pb.PeerID,
        allocator,
        "reputation",
        .{ .public_key = &[_]u8{1} },
    );

    try expectGoldenMatch(
        session_pb.XHeader,
        allocator,
        "session",
        .{ .key = "k", .value = "v" },
    );

    try expectGoldenMatch(
        status_pb.Status,
        allocator,
        "status",
        .{ .code = 1, .message = "ok" },
    );

    try expectGoldenMatch(
        storagegroup_pb.StorageGroup,
        allocator,
        "storagegroup",
        .{ .validation_data_size = 1 },
    );

    try expectGoldenMatch(
        subnet_pb.SubnetInfo,
        allocator,
        "subnet",
        .{ .owner = .{ .value = &[_]u8{1} } },
    );

    try expectGoldenMatch(
        tombstone_pb.Tombstone,
        allocator,
        "tombstone",
        .{ .expiration_epoch = 1 },
    );
}
