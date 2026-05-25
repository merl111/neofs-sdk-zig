const std = @import("std");
const wire = @import("encoding.zig");

pub fn marshalMessage(allocator: std.mem.Allocator, comptime sizeFn: anytype, comptime marshalFn: anytype, ctx: anytype) ![]u8 {
    const size = sizeFn(ctx);
    const out = try allocator.alloc(u8, size);
    _ = marshalFn(ctx, out);
    return out;
}

pub fn sizeVarint(field_num: u32, v: u64) usize {
    if (v == 0) return 0;
    var tmp: [12]u8 = undefined;
    return wire.putTag(&tmp, field_num, 0) + wire.putVarint(&tmp, v);
}

pub fn sizeBytes(field_num: u32, data: []const u8) usize {
    if (data.len == 0) return 0;
    var tmp: [12]u8 = undefined;
    return wire.putTag(&tmp, field_num, 2) + wire.putVarint(&tmp, data.len) + data.len;
}

pub fn marshalVarint(out: []u8, field_num: u32, v: u64) usize {
    if (v == 0) return 0;
    const off = wire.putTag(out, field_num, 0);
    return off + wire.putVarint(out[off..], v);
}

pub fn marshalBytes(out: []u8, field_num: u32, data: []const u8) usize {
    if (data.len == 0) return 0;
    const off = wire.putTag(out, field_num, 2);
    const len_off = wire.putVarint(out[off..], data.len);
    @memcpy(out[off + len_off .. off + len_off + data.len], data);
    return off + len_off + data.len;
}

pub const Version = struct {
    major: u32,
    minor: u32,
};

pub fn sizeVersion(v: Version) usize {
    return sizeVarint(1, v.major) + sizeVarint(2, v.minor);
}

pub fn marshalVersion(v: Version, out: []u8) usize {
    var off: usize = 0;
    off += marshalVarint(out[off..], 1, v.major);
    off += marshalVarint(out[off..], 2, v.minor);
    return off;
}

pub const OwnerID = struct { value: []const u8 };
pub fn sizeOwnerID(o: OwnerID) usize {
    return sizeBytes(1, o.value);
}
pub fn marshalOwnerID(o: OwnerID, out: []u8) usize {
    return marshalBytes(out, 1, o.value);
}

pub const ContainerID = struct { value: []const u8 };
pub fn sizeContainerID(c: ContainerID) usize {
    return sizeBytes(1, c.value);
}
pub fn marshalContainerID(c: ContainerID, out: []u8) usize {
    return marshalBytes(out, 1, c.value);
}

pub const ObjectID = struct { value: []const u8 };
pub fn sizeObjectID(o: ObjectID) usize {
    return sizeBytes(1, o.value);
}
pub fn marshalObjectID(o: ObjectID, out: []u8) usize {
    return marshalBytes(out, 1, o.value);
}

pub const Checksum = struct { typ: u32, sum: []const u8 };
pub fn sizeChecksum(c: Checksum) usize {
    return sizeVarint(1, c.typ) + sizeBytes(2, c.sum);
}
pub fn marshalChecksum(c: Checksum, out: []u8) usize {
    var off: usize = 0;
    off += marshalVarint(out[off..], 1, c.typ);
    off += marshalBytes(out[off..], 2, c.sum);
    return off;
}

pub const SignatureRFC6979 = struct { key: []const u8, sign: []const u8 };
pub fn sizeSignatureRFC6979(s: SignatureRFC6979) usize {
    return sizeBytes(1, s.key) + sizeBytes(2, s.sign);
}
pub fn marshalSignatureRFC6979(s: SignatureRFC6979, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, s.key);
    off += marshalBytes(out[off..], 2, s.sign);
    return off;
}

pub const Signature = struct { key: []const u8, sign: []const u8, scheme: u32 };
pub fn sizeSignature(s: Signature) usize {
    return sizeBytes(1, s.key) + sizeBytes(2, s.sign) + sizeVarint(3, s.scheme);
}
pub fn marshalSignature(s: Signature, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, s.key);
    off += marshalBytes(out[off..], 2, s.sign);
    off += marshalVarint(out[off..], 3, s.scheme);
    return off;
}

pub const ContainerAttribute = struct { key: []const u8, value: []const u8 };
pub fn sizeContainerAttribute(a: ContainerAttribute) usize {
    return sizeBytes(1, a.key) + sizeBytes(2, a.value);
}
pub fn marshalContainerAttribute(a: ContainerAttribute, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, a.key);
    off += marshalBytes(out[off..], 2, a.value);
    return off;
}

pub const Replica = struct { count: u64, selector: []const u8 = "" };
pub fn sizeReplica(r: Replica) usize {
    return sizeVarint(1, r.count) + sizeBytes(2, r.selector);
}
pub fn marshalReplica(r: Replica, out: []u8) usize {
    var off: usize = 0;
    off += marshalVarint(out[off..], 1, r.count);
    off += marshalBytes(out[off..], 2, r.selector);
    return off;
}

pub const Filter = struct {
    name: []const u8 = "",
    key: []const u8 = "",
    op: i32 = 0,
    value: []const u8 = "",
    filters: []const Filter = &.{},
};

pub fn sizeFilter(f: Filter) usize {
    var total = sizeBytes(1, f.name) + sizeBytes(2, f.key) + sizeVarint(3, @intCast(@max(f.op, 0))) + sizeBytes(4, f.value);
    for (f.filters) |sub| {
        const sz = sizeFilter(sub);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 5, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    return total;
}

pub fn marshalFilter(f: Filter, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, f.name);
    off += marshalBytes(out[off..], 2, f.key);
    off += marshalVarint(out[off..], 3, @intCast(@max(f.op, 0)));
    off += marshalBytes(out[off..], 4, f.value);
    for (f.filters) |sub| {
        const body_sz = sizeFilter(sub);
        const tag = wire.putTag(out[off..], 5, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalFilter(sub, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

pub fn deinitFilter(allocator: std.mem.Allocator, f: Filter) void {
    if (f.name.len > 0) allocator.free(@constCast(f.name));
    if (f.key.len > 0) allocator.free(@constCast(f.key));
    if (f.value.len > 0) allocator.free(@constCast(f.value));
    for (f.filters) |sub| deinitFilter(allocator, sub);
    if (f.filters.len > 0) allocator.free(@constCast(f.filters));
}

pub const Selector = struct {
    name: []const u8 = "",
    count: u32 = 0,
    clause: i32 = 0,
    attribute: []const u8 = "",
    filter: []const u8 = "",
};

pub fn sizeSelector(s: Selector) usize {
    return sizeBytes(1, s.name) +
        sizeVarint(2, s.count) +
        sizeVarint(3, @intCast(@max(s.clause, 0))) +
        sizeBytes(4, s.attribute) +
        sizeBytes(5, s.filter);
}

pub fn marshalSelector(s: Selector, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, s.name);
    off += marshalVarint(out[off..], 2, s.count);
    off += marshalVarint(out[off..], 3, @intCast(@max(s.clause, 0)));
    off += marshalBytes(out[off..], 4, s.attribute);
    off += marshalBytes(out[off..], 5, s.filter);
    return off;
}

pub fn deinitSelector(allocator: std.mem.Allocator, s: Selector) void {
    if (s.name.len > 0) allocator.free(@constCast(s.name));
    if (s.attribute.len > 0) allocator.free(@constCast(s.attribute));
    if (s.filter.len > 0) allocator.free(@constCast(s.filter));
}

pub const ECRule = struct {
    data_part_num: u32 = 0,
    parity_part_num: u32 = 0,
    selector: []const u8 = "",
};

pub fn sizeECRule(r: ECRule) usize {
    return sizeVarint(1, r.data_part_num) +
        sizeVarint(2, r.parity_part_num) +
        sizeBytes(3, r.selector);
}

pub fn marshalECRule(r: ECRule, out: []u8) usize {
    var off: usize = 0;
    off += marshalVarint(out[off..], 1, r.data_part_num);
    off += marshalVarint(out[off..], 2, r.parity_part_num);
    off += marshalBytes(out[off..], 3, r.selector);
    return off;
}

pub fn deinitECRule(allocator: std.mem.Allocator, r: ECRule) void {
    if (r.selector.len > 0) allocator.free(@constCast(r.selector));
}

pub const PlacementPolicy = struct {
    replicas: []const Replica,
    backup_factor: u64 = 1,
    selectors: []const Selector = &.{},
    filters: []const Filter = &.{},
    ec_rules: []const ECRule = &.{},
};

pub fn deinitPlacementPolicy(allocator: std.mem.Allocator, p: PlacementPolicy) void {
    for (p.replicas) |r| {
        if (r.selector.len > 0) allocator.free(@constCast(r.selector));
    }
    if (p.replicas.len > 0) allocator.free(@constCast(p.replicas));
    for (p.selectors) |s| deinitSelector(allocator, s);
    if (p.selectors.len > 0) allocator.free(@constCast(p.selectors));
    for (p.filters) |f| deinitFilter(allocator, f);
    if (p.filters.len > 0) allocator.free(@constCast(p.filters));
    for (p.ec_rules) |r| deinitECRule(allocator, r);
    if (p.ec_rules.len > 0) allocator.free(@constCast(p.ec_rules));
}

pub fn sizePlacementPolicy(p: PlacementPolicy) usize {
    var total: usize = 0;
    for (p.replicas) |r| {
        const sz = sizeReplica(r);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 1, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    total += sizeVarint(2, p.backup_factor);
    for (p.selectors) |s| {
        const sz = sizeSelector(s);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 3, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    for (p.filters) |f| {
        const sz = sizeFilter(f);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 4, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    for (p.ec_rules) |rule| {
        const sz = sizeECRule(rule);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 6, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    return total;
}
pub fn marshalPlacementPolicy(p: PlacementPolicy, out: []u8) usize {
    var off: usize = 0;
    for (p.replicas) |r| {
        const tag = wire.putTag(out[off..], 1, 2);
        const body_sz = sizeReplica(r);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalReplica(r, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 2, p.backup_factor);
    for (p.selectors) |s| {
        const tag = wire.putTag(out[off..], 3, 2);
        const body_sz = sizeSelector(s);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSelector(s, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (p.filters) |f| {
        const tag = wire.putTag(out[off..], 4, 2);
        const body_sz = sizeFilter(f);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalFilter(f, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (p.ec_rules) |rule| {
        const tag = wire.putTag(out[off..], 6, 2);
        const body_sz = sizeECRule(rule);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalECRule(rule, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

pub const Container = struct {
    version: ?Version = null,
    owner_id: ?OwnerID = null,
    nonce: []const u8 = "",
    basic_acl: u32 = 0,
    attributes: []const ContainerAttribute = &.{},
    placement_policy: ?PlacementPolicy = null,
};

pub fn sizeContainer(c: Container) usize {
    var total: usize = 0;
    if (c.version) |v| {
        const sz = sizeVersion(v);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 1, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    if (c.owner_id) |o| {
        const sz = sizeOwnerID(o);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 2, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    total += sizeBytes(3, c.nonce);
    total += sizeVarint(4, c.basic_acl);
    for (c.attributes) |a| {
        const sz = sizeContainerAttribute(a);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 5, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    if (c.placement_policy) |p| {
        const sz = sizePlacementPolicy(p);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 6, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    return total;
}

pub fn marshalContainer(c: Container, out: []u8) usize {
    var off: usize = 0;
    if (c.version) |v| {
        const tag = wire.putTag(out[off..], 1, 2);
        const body_sz = sizeVersion(v);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalVersion(v, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (c.owner_id) |o| {
        const tag = wire.putTag(out[off..], 2, 2);
        const body_sz = sizeOwnerID(o);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalOwnerID(o, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalBytes(out[off..], 3, c.nonce);
    off += marshalVarint(out[off..], 4, c.basic_acl);
    for (c.attributes) |a| {
        const tag = wire.putTag(out[off..], 5, 2);
        const body_sz = sizeContainerAttribute(a);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalContainerAttribute(a, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (c.placement_policy) |p| {
        const tag = wire.putTag(out[off..], 6, 2);
        const body_sz = sizePlacementPolicy(p);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalPlacementPolicy(p, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

pub fn containerID(c: Container) [32]u8 {
    var out: [32]u8 = undefined;
    var buf: [4096]u8 = undefined;
    const size = sizeContainer(c);
    _ = marshalContainer(c, buf[0..size]);
    std.crypto.hash.sha2.Sha256.hash(buf[0..size], &out, .{});
    return out;
}

pub const HeaderAttribute = struct { key: []const u8, value: []const u8 };
pub fn sizeHeaderAttribute(a: HeaderAttribute) usize {
    return sizeBytes(1, a.key) + sizeBytes(2, a.value);
}
pub fn marshalHeaderAttribute(a: HeaderAttribute, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, a.key);
    off += marshalBytes(out[off..], 2, a.value);
    return off;
}

pub const Header = struct {
    version: ?Version = null,
    container_id: ?ContainerID = null,
    owner_id: ?OwnerID = null,
    creation_epoch: u64 = 0,
    payload_length: u64 = 0,
    payload_hash: ?Checksum = null,
    object_type: u64 = 0,
    homomorphic_hash: ?Checksum = null,
    attributes: []const HeaderAttribute = &.{},
};

pub fn sizeHeader(h: Header) usize {
    var total: usize = 0;
    if (h.version) |v| {
        const sz = sizeVersion(v);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 1, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    if (h.container_id) |c| {
        const sz = sizeContainerID(c);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 2, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    if (h.owner_id) |o| {
        const sz = sizeOwnerID(o);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 3, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    total += sizeVarint(4, h.creation_epoch);
    total += sizeVarint(5, h.payload_length);
    if (h.payload_hash) |cs| {
        const sz = sizeChecksum(cs);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 6, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    total += sizeVarint(7, h.object_type);
    if (h.homomorphic_hash) |cs| {
        const sz = sizeChecksum(cs);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 8, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    for (h.attributes) |a| {
        const sz = sizeHeaderAttribute(a);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 10, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    return total;
}

pub fn marshalHeader(h: Header, out: []u8) usize {
    var off: usize = 0;
    if (h.version) |v| {
        const tag = wire.putTag(out[off..], 1, 2);
        const body_sz = sizeVersion(v);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalVersion(v, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (h.container_id) |c| {
        const tag = wire.putTag(out[off..], 2, 2);
        const body_sz = sizeContainerID(c);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalContainerID(c, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (h.owner_id) |o| {
        const tag = wire.putTag(out[off..], 3, 2);
        const body_sz = sizeOwnerID(o);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalOwnerID(o, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 4, h.creation_epoch);
    off += marshalVarint(out[off..], 5, h.payload_length);
    if (h.payload_hash) |cs| {
        const tag = wire.putTag(out[off..], 6, 2);
        const body_sz = sizeChecksum(cs);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalChecksum(cs, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 7, h.object_type);
    if (h.homomorphic_hash) |cs| {
        const tag = wire.putTag(out[off..], 8, 2);
        const body_sz = sizeChecksum(cs);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalChecksum(cs, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (h.attributes) |a| {
        const tag = wire.putTag(out[off..], 10, 2);
        const body_sz = sizeHeaderAttribute(a);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalHeaderAttribute(a, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

pub fn objectIDFromHeader(h: Header) [32]u8 {
    var out: [32]u8 = undefined;
    var buf: [4096]u8 = undefined;
    const size = sizeHeader(h);
    _ = marshalHeader(h, buf[0..size]);
    std.crypto.hash.sha2.Sha256.hash(buf[0..size], &out, .{});
    return out;
}

pub const TokenLifetime = struct { exp: u64, nbf: u64, iat: u64 };
pub fn sizeTokenLifetime(l: TokenLifetime) usize {
    return sizeVarint(1, l.exp) + sizeVarint(2, l.nbf) + sizeVarint(3, l.iat);
}
pub fn marshalTokenLifetime(l: TokenLifetime, out: []u8) usize {
    var off: usize = 0;
    off += marshalVarint(out[off..], 1, l.exp);
    off += marshalVarint(out[off..], 2, l.nbf);
    off += marshalVarint(out[off..], 3, l.iat);
    return off;
}

pub const ObjectSessionTarget = struct { container_id: ?ContainerID = null };
pub fn sizeObjectSessionTarget(t: ObjectSessionTarget) usize {
    if (t.container_id) |c| {
        const sz = sizeContainerID(c);
        var tmp: [12]u8 = undefined;
        return wire.putTag(&tmp, 1, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    return 0;
}
pub fn marshalObjectSessionTarget(t: ObjectSessionTarget, out: []u8) usize {
    if (t.container_id) |c| {
        const tag = wire.putTag(out, 1, 2);
        const body_sz = sizeContainerID(c);
        const len = wire.putVarint(out[tag..], body_sz);
        _ = marshalContainerID(c, out[tag + len ..][0..body_sz]);
        return tag + len + body_sz;
    }
    return 0;
}

pub const ObjectSessionContext = struct {
    verb: u64,
    target: ?ObjectSessionTarget = null,
};
pub fn sizeObjectSessionContext(c: ObjectSessionContext) usize {
    var total = sizeVarint(1, c.verb);
    if (c.target) |t| {
        const sz = sizeObjectSessionTarget(t);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 2, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    return total;
}
pub fn marshalObjectSessionContext(c: ObjectSessionContext, out: []u8) usize {
    var off = marshalVarint(out, 1, c.verb);
    if (c.target) |t| {
        const tag = wire.putTag(out[off..], 2, 2);
        const body_sz = sizeObjectSessionTarget(t);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectSessionTarget(t, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

pub const SessionTokenBody = struct {
    id: []const u8,
    owner_id: ?OwnerID = null,
    lifetime: ?TokenLifetime = null,
    session_key: []const u8 = "",
    object_ctx: ?ObjectSessionContext = null,
};

pub fn sizeSessionTokenBody(b: SessionTokenBody) usize {
    var total = sizeBytes(1, b.id);
    if (b.owner_id) |o| {
        const sz = sizeOwnerID(o);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 2, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    if (b.lifetime) |l| {
        const sz = sizeTokenLifetime(l);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 3, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    total += sizeBytes(4, b.session_key);
    if (b.object_ctx) |c| {
        const sz = sizeObjectSessionContext(c);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 5, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    return total;
}

pub fn marshalSessionTokenBody(b: SessionTokenBody, out: []u8) usize {
    var off = marshalBytes(out, 1, b.id);
    if (b.owner_id) |o| {
        const tag = wire.putTag(out[off..], 2, 2);
        const body_sz = sizeOwnerID(o);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalOwnerID(o, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (b.lifetime) |l| {
        const tag = wire.putTag(out[off..], 3, 2);
        const body_sz = sizeTokenLifetime(l);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalTokenLifetime(l, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalBytes(out[off..], 4, b.session_key);
    if (b.object_ctx) |c| {
        const tag = wire.putTag(out[off..], 5, 2);
        const body_sz = sizeObjectSessionContext(c);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectSessionContext(c, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

pub const SessionToken = struct {
    body: ?SessionTokenBody = null,
    signature: ?Signature = null,
};

pub fn sizeSessionToken(t: SessionToken) usize {
    var total: usize = 0;
    if (t.body) |b| {
        const sz = sizeSessionTokenBody(b);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 1, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    if (t.signature) |s| {
        const sz = sizeSignature(s);
        var tmp: [12]u8 = undefined;
        total += wire.putTag(&tmp, 2, 2) + wire.putVarint(&tmp, sz) + sz;
    }
    return total;
}

pub fn marshalSessionToken(t: SessionToken, out: []u8) usize {
    var off: usize = 0;
    if (t.body) |b| {
        const tag = wire.putTag(out[off..], 1, 2);
        const body_sz = sizeSessionTokenBody(b);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSessionTokenBody(b, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (t.signature) |s| {
        const tag = wire.putTag(out[off..], 2, 2);
        const body_sz = sizeSignature(s);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSignature(s, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

test "container stable marshal is deterministic" {
    const c = Container{
        .version = .{ .major = 2, .minor = 22 },
        .owner_id = .{ .value = &[_]u8{ 1, 2, 3 } },
        .nonce = &[_]u8{ 9, 8, 7 },
        .basic_acl = 0x1fbfbfff,
        .placement_policy = .{
            .replicas = &[_]Replica{.{ .count = 1 }},
            .backup_factor = 1,
        },
    };
    const id1 = containerID(c);
    const id2 = containerID(c);
    try std.testing.expectEqualSlices(u8, &id1, &id2);
}
