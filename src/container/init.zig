const std = @import("std");
const clock = @import("../util/clock.zig");
const csprng = @import("../crypto/csprng.zig");
const version = @import("../version/version.zig");
const user = @import("../user/id.zig");
const keys = @import("../crypto/ecdsa/keys.zig");
const sig = @import("../crypto/signature.zig");
const stable = @import("../internal/proto/stable.zig");
const container_pb = @import("../proto/gen/container/types.pb.zig");
const netmap_pb = @import("../proto/gen/netmap/types.pb.zig");
const refs_pb = @import("../proto/gen/refs/types.pb.zig");
const acl_mod = @import("acl.zig");
const placement_mod = @import("placement.zig");

pub const public_rw_acl: u32 = acl_mod.public_rw_acl;
pub const acl = acl_mod;
pub const placement = placement_mod;
pub const PlacementPolicy = stable.PlacementPolicy;

pub const CreateOptions = struct {
    basic_acl: u32 = public_rw_acl,
    placement_policy: ?stable.PlacementPolicy = null,
};

/// Build a container with explicit ACL and placement. Caller owns returned
/// `placement_policy.replicas` until `deinitContainer`.
pub fn newContainerWithOptions(
    allocator: std.mem.Allocator,
    owner: user.ID,
    nonce: []const u8,
    name: []const u8,
    opts: CreateOptions,
) !stable.Container {
    var c = try newContainer(allocator, owner, nonce, name);
    c.basic_acl = opts.basic_acl;
    if (c.placement_policy) |*old| {
        stable.deinitPlacementPolicy(allocator, old.*);
        c.placement_policy = null;
    }
    if (opts.placement_policy) |p| {
        c.placement_policy = p;
    }
    return c;
}

pub fn randomNonce(allocator: std.mem.Allocator) ![]u8 {
    var nonce: [16]u8 = undefined;
    csprng.randomBytes(&nonce);
    // NeoFS requires RFC 4122 UUID v4 (same as Go's uuid.New()).
    nonce[6] = (nonce[6] & 0x0F) | 0x40;
    nonce[8] = (nonce[8] & 0x3F) | 0x80;
    return try allocator.dupe(u8, &nonce);
}

pub fn newContainer(
    allocator: std.mem.Allocator,
    owner: user.ID,
    nonce: []const u8,
    name: []const u8,
) !stable.Container {
    const v = version.current();
    const name_value = try allocator.dupe(u8, name);
    errdefer allocator.free(name_value);
    const ts = try std.fmt.allocPrint(allocator, "{d}", .{clock.timestamp()});
    errdefer allocator.free(ts);

    const attrs = try allocator.alloc(stable.ContainerAttribute, 2);
    errdefer allocator.free(attrs);
    attrs[0] = .{ .key = "Name", .value = name_value };
    attrs[1] = .{ .key = "Timestamp", .value = ts };

    const owner_value = try allocator.dupe(u8, &owner.bytes);
    errdefer allocator.free(owner_value);

    const replicas = try allocator.alloc(stable.Replica, 1);
    errdefer allocator.free(replicas);
    replicas[0] = .{ .count = 1 };

    return .{
        .version = .{ .major = v.major, .minor = v.minor },
        .owner_id = .{ .value = owner_value },
        .nonce = nonce,
        .basic_acl = public_rw_acl,
        .attributes = attrs,
        .placement_policy = .{
            .replicas = replicas,
            .backup_factor = 1,
        },
    };
}

pub fn deinitContainer(allocator: std.mem.Allocator, container: stable.Container) void {
    if (container.owner_id) |owner| {
        allocator.free(@constCast(owner.value));
    }
    if (container.placement_policy) |policy| {
        stable.deinitPlacementPolicy(allocator, policy);
    }
    for (container.attributes) |attr| {
        allocator.free(attr.value);
    }
    allocator.free(container.attributes);
}

pub fn signContainer(
    allocator: std.mem.Allocator,
    secret_key: []const u8,
    container: stable.Container,
) !refs_pb.SignatureRFC6979 {
    const kp = try keys.KeyPair.fromSecretBytes(secret_key);
    const data = try stable.marshalMessage(allocator, stable.sizeContainer, stable.marshalContainer, container);
    defer allocator.free(data);
    const signature = try kp.sign(allocator, .ecdsa_deterministic_sha256, data);
    return .{
        .key = signature.key,
        .sign = signature.value,
    };
}

pub fn signContainerID(
    allocator: std.mem.Allocator,
    secret_key: []const u8,
    container_id: [32]u8,
) !refs_pb.SignatureRFC6979 {
    const kp = try keys.KeyPair.fromSecretBytes(secret_key);
    const signature = try kp.sign(allocator, .ecdsa_deterministic_sha256, &container_id);
    return .{
        .key = signature.key,
        .sign = signature.value,
    };
}

fn appendPbFilter(allocator: std.mem.Allocator, out: *std.ArrayList(netmap_pb.Filter), f: stable.Filter) !void {
    var subs: std.ArrayList(netmap_pb.Filter) = .empty;
    errdefer subs.deinit(allocator);
    for (f.filters) |sub| {
        try appendPbFilter(allocator, &subs, sub);
    }
    try out.append(allocator, .{
        .name = try allocator.dupe(u8, f.name),
        .key = try allocator.dupe(u8, f.key),
        .op = @enumFromInt(f.op),
        .value = try allocator.dupe(u8, f.value),
        .filters = subs,
    });
}

fn appendPbSelectors(allocator: std.mem.Allocator, out: *std.ArrayList(netmap_pb.Selector), selectors: []const stable.Selector) !void {
    for (selectors) |s| {
        try out.append(allocator, .{
            .name = try allocator.dupe(u8, s.name),
            .count = s.count,
            .clause = @enumFromInt(s.clause),
            .attribute = try allocator.dupe(u8, s.attribute),
            .filter = try allocator.dupe(u8, s.filter),
        });
    }
}

fn appendPbECRules(allocator: std.mem.Allocator, out: *std.ArrayList(netmap_pb.PlacementPolicy.ECRule), rules: []const stable.ECRule) !void {
    for (rules) |r| {
        try out.append(allocator, .{
            .data_part_num = r.data_part_num,
            .parity_part_num = r.parity_part_num,
            .selector = try allocator.dupe(u8, r.selector),
        });
    }
}

pub fn toPutRequestBody(
    allocator: std.mem.Allocator,
    container: stable.Container,
    container_signature: refs_pb.SignatureRFC6979,
) !container_pb.PutRequest.Body {
    const v = container.version orelse return error.MissingVersion;
    var attrs: std.ArrayList(container_pb.Container.Attribute) = .empty;
    errdefer {
        for (attrs.items) |a| {
            allocator.free(a.key);
            allocator.free(a.value);
        }
        attrs.deinit(allocator);
    }
    for (container.attributes) |a| {
        try attrs.append(allocator, .{
            .key = try allocator.dupe(u8, a.key),
            .value = try allocator.dupe(u8, a.value),
        });
    }
    var replicas: std.ArrayList(netmap_pb.Replica) = .empty;
    errdefer replicas.deinit(allocator);
    var selectors: std.ArrayList(netmap_pb.Selector) = .empty;
    errdefer selectors.deinit(allocator);
    var filters: std.ArrayList(netmap_pb.Filter) = .empty;
    errdefer filters.deinit(allocator);
    var ec_rules: std.ArrayList(netmap_pb.PlacementPolicy.ECRule) = .empty;
    errdefer ec_rules.deinit(allocator);
    if (container.placement_policy) |p| {
        for (p.replicas) |r| {
            try replicas.append(allocator, .{
                .count = @intCast(r.count),
                .selector = try allocator.dupe(u8, r.selector),
            });
        }
        try appendPbSelectors(allocator, &selectors, p.selectors);
        for (p.filters) |f| {
            try appendPbFilter(allocator, &filters, f);
        }
        try appendPbECRules(allocator, &ec_rules, p.ec_rules);
    }
    const owner = container.owner_id orelse return error.MissingOwner;
    return .{
        .container = .{
            .version = .{ .major = v.major, .minor = v.minor },
            .owner_id = .{ .value = try allocator.dupe(u8, owner.value) },
            .nonce = try allocator.dupe(u8, container.nonce),
            .basic_acl = container.basic_acl,
            .attributes = attrs,
            .placement_policy = .{
                .replicas = replicas,
                .container_backup_factor = @intCast(container.placement_policy.?.backup_factor),
                .selectors = selectors,
                .filters = filters,
                .ec_rules = ec_rules,
            },
        },
        .signature = .{
            .key = try allocator.dupe(u8, container_signature.key),
            .sign = try allocator.dupe(u8, container_signature.sign),
        },
    };
}

pub fn encodeID(allocator: std.mem.Allocator, id: [32]u8) ![]u8 {
    return @import("../crypto/base58.zig").encode(allocator, &id);
}

test "random nonce is uuid v4" {
    const nonce = try randomNonce(std.testing.allocator);
    defer std.testing.allocator.free(nonce);
    try std.testing.expectEqual(@as(usize, 16), nonce.len);
    try std.testing.expectEqual(@as(u8, 4), nonce[6] >> 4);
    try std.testing.expectEqual(@as(u8, 0x80), nonce[8] & 0xC0);
}

test "new container stable marshal size is reasonable" {
    const allocator = std.testing.allocator;
    const owner = user.ID.fromCompressedPublicKey([_]u8{0x02} ** 33);
    const nonce = try randomNonce(allocator);
    defer allocator.free(nonce);
    const c = try newContainer(allocator, owner, nonce, "test");
    defer deinitContainer(allocator, c);
    const size = stable.sizeContainer(c);
    try std.testing.expect(size > 0 and size < 4096);
}

test "new container has placement policy" {
    const allocator = std.testing.allocator;
    const owner = user.ID.fromCompressedPublicKey([_]u8{0x02} ** 33);
    const nonce = try randomNonce(allocator);
    defer allocator.free(nonce);
    const c = try newContainer(allocator, owner, nonce, "test");
    defer deinitContainer(allocator, c);
    try std.testing.expect(c.placement_policy != null);
    try std.testing.expectEqual(@as(u32, public_rw_acl), c.basic_acl);
}

test "select policy encodes in put request body" {
    const allocator = std.testing.allocator;
    const owner = user.ID.fromCompressedPublicKey([_]u8{0x02} ** 33);
    const nonce = try randomNonce(allocator);
    defer allocator.free(nonce);

    const replicas = try allocator.alloc(stable.Replica, 1);
    replicas[0] = .{ .count = 1, .selector = try allocator.dupe(u8, "X") };
    const selectors = try allocator.alloc(stable.Selector, 1);
    selectors[0] = .{
        .name = try allocator.dupe(u8, "X"),
        .count = 2,
        .clause = @intFromEnum(netmap_pb.Clause.SAME),
        .attribute = try allocator.dupe(u8, "Location"),
        .filter = try allocator.dupe(u8, "*"),
    };
    const policy = stable.PlacementPolicy{
        .replicas = replicas,
        .backup_factor = 1,
        .selectors = selectors,
    };

    const c = try newContainerWithOptions(allocator, owner, nonce, "select-policy", .{
        .placement_policy = policy,
    });
    defer deinitContainer(allocator, c);

    const container_sig = refs_pb.SignatureRFC6979{ .key = "pub", .sign = "sig" };
    var body = try toPutRequestBody(allocator, c, container_sig);
    defer body.deinit(allocator);
    const container = body.container orelse return error.MissingContainer;
    const pp = container.placement_policy orelse return error.MissingPlacementPolicy;
    try std.testing.expectEqual(@as(usize, 1), pp.selectors.items.len);
    try std.testing.expectEqualStrings("X", pp.selectors.items[0].name);
    try std.testing.expectEqual(@as(u32, 2), pp.selectors.items[0].count);
    try std.testing.expectEqual(netmap_pb.Clause.SAME, pp.selectors.items[0].clause);
    try std.testing.expectEqualStrings("Location", pp.selectors.items[0].attribute);

    var stable_buf: [4096]u8 = undefined;
    const stable_size = stable.sizeContainer(c);
    _ = stable.marshalContainer(c, stable_buf[0..stable_size]);
    const pb_size = @import("../internal/proto/signing.zig").sizeContainer(container);
    var pb_buf: [4096]u8 = undefined;
    _ = @import("../internal/proto/signing.zig").marshalContainer(container, pb_buf[0..pb_size]);
    try std.testing.expectEqual(stable_size, pb_size);
    try std.testing.expectEqualSlices(u8, stable_buf[0..stable_size], pb_buf[0..pb_size]);
}
