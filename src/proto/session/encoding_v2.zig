pub const package_name = "session_v2";

const std = @import("std");
const wire = @import("../../internal/proto/encoding.zig");
const session_pb = @import("../gen/session/types.pb.zig");
const refs_pb = @import("../gen/refs/types.pb.zig");

fn varintLen(v: u64) usize {
    var x = v;
    var n: usize = 1;
    while (x >= 0x80) : (n += 1) x >>= 7;
    return n;
}

fn sizeTag(field: u32, wire_type: u8) usize {
    return varintLen((@as(u64, field) << 3) | wire_type);
}

fn sizeVarint(field: u32, v: anytype) usize {
    const n: u64 = if (@TypeOf(v) == bool) (if (v) 1 else 0) else @as(u64, @intCast(v));
    if (n == 0) return 0;
    return sizeTag(field, 0) + varintLen(n);
}

fn sizeBytes(field: u32, b: []const u8) usize {
    if (b.len == 0) return 0;
    return sizeTag(field, 2) + varintLen(b.len) + b.len;
}

fn sizeEmbedded(field: u32, body: usize) usize {
    if (body == 0) return 0;
    return sizeTag(field, 2) + varintLen(body) + body;
}

fn marshalVarint(out: []u8, field: u32, v: anytype) usize {
    const n: u64 = if (@TypeOf(v) == bool) (if (v) 1 else 0) else @as(u64, @intCast(v));
    if (n == 0) return 0;
    const tag = wire.putTag(out, field, 0);
    const body = wire.putVarint(out[tag..], n);
    return tag + body;
}

fn marshalBytes(out: []u8, field: u32, b: []const u8) usize {
    if (b.len == 0) return 0;
    const tag = wire.putTag(out, field, 2);
    const len = wire.putVarint(out[tag..], b.len);
    @memcpy(out[tag + len ..][0..b.len], b);
    return tag + len + b.len;
}

fn sizeOwnerID(id: refs_pb.OwnerID) usize {
    return sizeBytes(1, id.value);
}

fn marshalOwnerID(id: refs_pb.OwnerID, out: []u8) usize {
    return marshalBytes(out, 1, id.value);
}

fn sizeSignature(s: refs_pb.Signature) usize {
    return sizeBytes(1, s.key) + sizeBytes(2, s.sign) + sizeVarint(3, @as(u64, @intCast(@intFromEnum(s.scheme))));
}

fn marshalSignature(s: refs_pb.Signature, out: []u8) usize {
    var off = marshalBytes(out, 1, s.key);
    off += marshalBytes(out[off..], 2, s.sign);
    off += marshalVarint(out[off..], 3, @as(u64, @intCast(@intFromEnum(s.scheme))));
    return off;
}

fn sizeContainerID(cid: refs_pb.ContainerID) usize {
    return sizeBytes(1, cid.value);
}

fn marshalContainerID(cid: refs_pb.ContainerID, out: []u8) usize {
    return marshalBytes(out, 1, cid.value);
}

pub fn sizeTokenLifetime(lifetime: ?session_pb.TokenLifetime) usize {
    if (lifetime == null) return 0;
    const l = lifetime.?;
    return sizeVarint(1, l.exp) + sizeVarint(2, l.nbf) + sizeVarint(3, l.iat);
}

pub fn marshalTokenLifetime(lifetime: ?session_pb.TokenLifetime, out: []u8) usize {
    if (lifetime == null) return 0;
    const l = lifetime.?;
    var off = marshalVarint(out, 1, l.exp);
    off += marshalVarint(out[off..], 2, l.nbf);
    off += marshalVarint(out[off..], 3, l.iat);
    return off;
}

pub fn sizeTarget(target: session_pb.Target) usize {
    if (target.identifier == null) return 0;
    return switch (target.identifier.?) {
        .owner_id => |owner| sizeEmbedded(1, sizeOwnerID(owner)),
        .nns_name => |name| sizeBytes(2, name),
    };
}

pub fn marshalTarget(target: session_pb.Target, out: []u8) usize {
    if (target.identifier == null) return 0;
    return switch (target.identifier.?) {
        .owner_id => |owner| blk: {
            const body_sz = sizeOwnerID(owner);
            const tag = wire.putTag(out, 1, 2);
            const len = wire.putVarint(out[tag..], body_sz);
            _ = marshalOwnerID(owner, out[tag + len ..][0..body_sz]);
            break :blk tag + len + body_sz;
        },
        .nns_name => |name| marshalBytes(out, 2, name),
    };
}

pub fn sizeSessionContextV2(ctx: session_pb.SessionContextV2) usize {
    var total: usize = 0;
    if (ctx.container) |cid| total += sizeEmbedded(1, sizeContainerID(cid));
    // proto3 repeated scalar/enum fields are packed by default. Go's stable
    // marshaler uses MarshalToRepeatedVarint, which emits a single LEN-prefixed
    // entry containing concatenated varints.
    if (ctx.verbs.items.len > 0) {
        var body_sz: usize = 0;
        for (ctx.verbs.items) |v| {
            body_sz += varintLen(@as(u64, @intCast(@intFromEnum(v))));
        }
        total += sizeTag(2, 2) + varintLen(body_sz) + body_sz;
    }
    return total;
}

pub fn marshalSessionContextV2(ctx: session_pb.SessionContextV2, out: []u8) usize {
    var off: usize = 0;
    if (ctx.container) |cid| {
        const body_sz = sizeContainerID(cid);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalContainerID(cid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (ctx.verbs.items.len > 0) {
        var body_sz: usize = 0;
        for (ctx.verbs.items) |v| {
            body_sz += varintLen(@as(u64, @intCast(@intFromEnum(v))));
        }
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        off += tag + len;
        for (ctx.verbs.items) |v| {
            off += wire.putVarint(out[off..], @as(u64, @intCast(@intFromEnum(v))));
        }
    }
    return off;
}

pub fn sizeSessionTokenV2Body(body: session_pb.SessionTokenV2.Body) usize {
    var total: usize = 0;
    total += sizeVarint(1, body.version);
    total += sizeBytes(2, body.appdata);
    if (body.issuer) |issuer| total += sizeEmbedded(3, sizeOwnerID(issuer));
    for (body.subjects.items) |subject| total += sizeEmbedded(4, sizeTarget(subject));
    total += sizeEmbedded(5, sizeTokenLifetime(body.lifetime));
    for (body.contexts.items) |ctx| total += sizeEmbedded(6, sizeSessionContextV2(ctx));
    total += sizeVarint(7, body.final);
    return total;
}

pub fn marshalSessionTokenV2Body(body: session_pb.SessionTokenV2.Body, out: []u8) usize {
    var off = marshalVarint(out, 1, body.version);
    off += marshalBytes(out[off..], 2, body.appdata);
    if (body.issuer) |issuer| {
        const body_sz = sizeOwnerID(issuer);
        const tag = wire.putTag(out[off..], 3, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalOwnerID(issuer, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (body.subjects.items) |subject| {
        const body_sz = sizeTarget(subject);
        const tag = wire.putTag(out[off..], 4, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalTarget(subject, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    {
        const body_sz = sizeTokenLifetime(body.lifetime);
        const tag = wire.putTag(out[off..], 5, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalTokenLifetime(body.lifetime, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (body.contexts.items) |ctx| {
        const body_sz = sizeSessionContextV2(ctx);
        const tag = wire.putTag(out[off..], 6, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSessionContextV2(ctx, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 7, body.final);
    return off;
}

pub fn sizeSessionTokenV2(tok: session_pb.SessionTokenV2) usize {
    var total: usize = 0;
    if (tok.body) |body| total += sizeEmbedded(1, sizeSessionTokenV2Body(body));
    if (tok.signature) |sig| total += sizeEmbedded(2, sizeSignature(sig));
    if (tok.origin) |origin| total += sizeEmbedded(3, sizeSessionTokenV2(origin.*));
    return total;
}

pub fn marshalSessionTokenV2(tok: session_pb.SessionTokenV2, out: []u8) usize {
    var off: usize = 0;
    if (tok.body) |body| {
        const body_sz = sizeSessionTokenV2Body(body);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSessionTokenV2Body(body, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (tok.signature) |sig| {
        const body_sz = sizeSignature(sig);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSignature(sig, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (tok.origin) |origin| {
        const body_sz = sizeSessionTokenV2(origin.*);
        const tag = wire.putTag(out[off..], 3, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSessionTokenV2(origin.*, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

pub fn encodeSessionTokenV2Body(allocator: std.mem.Allocator, body: session_pb.SessionTokenV2.Body) ![]u8 {
    const size = sizeSessionTokenV2Body(body);
    const out = try allocator.alloc(u8, size);
    _ = marshalSessionTokenV2Body(body, out);
    return out;
}

test "session token v2 signature uses refs field order" {
    const sig_msg: refs_pb.Signature = .{
        .scheme = .ECDSA_RFC6979_SHA256_WALLET_CONNECT,
        .key = &[_]u8{0x02} ** 33,
        .sign = &[_]u8{0xAB} ** 80,
    };

    var buf: [256]u8 = undefined;
    const n = marshalSignature(sig_msg, &buf);
    try std.testing.expect(n > 0);
    // refs.Signature marshals key first (field 1, wire type 2 -> tag 0x0a).
    try std.testing.expectEqual(@as(u8, 0x0a), buf[0]);
}
