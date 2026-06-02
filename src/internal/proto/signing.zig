const std = @import("std");
const wire = @import("encoding.zig");
const session_pb = @import("../../proto/gen/session/types.pb.zig");
const session_v2_enc = @import("../../proto/session/encoding_v2.zig");
const container_pb = @import("../../proto/gen/container/types.pb.zig");
const object_pb = @import("../../proto/gen/object/types.pb.zig");
const accounting_pb = @import("../../proto/gen/accounting/types.pb.zig");
const reputation_pb = @import("../../proto/gen/reputation/types.pb.zig");
const refs_pb = @import("../../proto/gen/refs/types.pb.zig");
const netmap_pb = @import("../../proto/gen/netmap/types.pb.zig");
const acl_pb = @import("../../proto/gen/acl/types.pb.zig");

fn sizeEmpty(_: anytype) usize {
    return 0;
}
fn marshalEmpty(_: anytype, _: []u8) usize {
    return 0;
}

fn sizeVarint(field_num: u32, v: u64) usize {
    if (v == 0) return 0;
    var tmp: [12]u8 = undefined;
    return wire.putTag(&tmp, field_num, 0) + wire.putVarint(&tmp, v);
}

fn sizeVersion(v: refs_pb.Version) usize {
    return sizeVarint(1, v.major) + sizeVarint(2, v.minor);
}

fn sizeBytes(field_num: u32, data: []const u8) usize {
    if (data.len == 0) return 0;
    var tmp: [12]u8 = undefined;
    return wire.putTag(&tmp, field_num, 2) + wire.putVarint(&tmp, data.len) + data.len;
}

fn sizeEmbedded(field_num: u32, body_sz: usize) usize {
    if (body_sz == 0) return 0;
    var tmp: [12]u8 = undefined;
    return wire.putTag(&tmp, field_num, 2) + wire.putVarint(&tmp, body_sz) + body_sz;
}

fn marshalVarint(out: []u8, field_num: u32, v: u64) usize {
    if (v == 0) return 0;
    const off = wire.putTag(out, field_num, 0);
    return off + wire.putVarint(out[off..], v);
}

fn marshalBytes(out: []u8, field_num: u32, data: []const u8) usize {
    if (data.len == 0) return 0;
    const off = wire.putTag(out, field_num, 2);
    const len = wire.putVarint(out[off..], data.len);
    @memcpy(out[off + len .. off + len + data.len], data);
    return off + len + data.len;
}

fn marshalEmbedded(out: []u8, field_num: u32, body_sz: usize, body: []const u8) usize {
    if (body_sz == 0) return 0;
    const tag = wire.putTag(out, field_num, 2);
    const len = wire.putVarint(out[tag..], body_sz);
    @memcpy(out[tag + len .. tag + len + body_sz], body);
    return tag + len + body_sz;
}

fn marshalVersion(v: refs_pb.Version, out: []u8) usize {
    var off: usize = 0;
    off += marshalVarint(out[off..], 1, v.major);
    off += marshalVarint(out[off..], 2, v.minor);
    return off;
}

fn sizeOwnerID(o: refs_pb.OwnerID) usize {
    return sizeBytes(1, o.value);
}

fn marshalOwnerID(o: refs_pb.OwnerID, out: []u8) usize {
    return marshalBytes(out, 1, o.value);
}

fn sizeContainerID(c: refs_pb.ContainerID) usize {
    return sizeBytes(1, c.value);
}

fn marshalContainerID(c: refs_pb.ContainerID, out: []u8) usize {
    return marshalBytes(out, 1, c.value);
}

fn sizeSignatureRFC6979(s: refs_pb.SignatureRFC6979) usize {
    return sizeBytes(1, s.key) + sizeBytes(2, s.sign);
}

fn marshalSignatureRFC6979(s: refs_pb.SignatureRFC6979, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, s.key);
    off += marshalBytes(out[off..], 2, s.sign);
    return off;
}

fn sizeSignature(s: refs_pb.Signature) usize {
    return sizeBytes(1, s.key) + sizeBytes(2, s.sign) + sizeVarint(3, @intCast(@intFromEnum(s.scheme)));
}

fn marshalSignature(s: refs_pb.Signature, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, s.key);
    off += marshalBytes(out[off..], 2, s.sign);
    off += marshalVarint(out[off..], 3, @intCast(@intFromEnum(s.scheme)));
    return off;
}

fn sizeReplica(r: netmap_pb.Replica) usize {
    return sizeVarint(1, r.count) + sizeBytes(2, r.selector);
}

fn marshalReplica(r: netmap_pb.Replica, out: []u8) usize {
    var off: usize = 0;
    off += marshalVarint(out[off..], 1, r.count);
    off += marshalBytes(out[off..], 2, r.selector);
    return off;
}

fn sizePlacementPolicy(p: netmap_pb.PlacementPolicy) usize {
    var total: usize = 0;
    for (p.replicas.items) |r| {
        const sz = sizeReplica(r);
        total += sizeEmbedded(1, sz);
    }
    total += sizeVarint(2, p.container_backup_factor);
    for (p.selectors.items) |s| {
        const sz = sizeSelector(s);
        total += sizeEmbedded(3, sz);
    }
    for (p.filters.items) |f| {
        const sz = sizeFilter(f);
        total += sizeEmbedded(4, sz);
    }
    if (p.subnet_id) |sid| {
        const sz = sizeSubnetID(sid);
        total += sizeEmbedded(5, sz);
    }
    for (p.ec_rules.items) |rule| {
        const sz = sizeECRule(rule);
        total += sizeEmbedded(6, sz);
    }
    if (p.initial) |initial| {
        const sz = sizePlacementInitial(initial);
        total += sizeEmbedded(7, sz);
    }
    return total;
}

fn marshalPlacementPolicy(p: netmap_pb.PlacementPolicy, out: []u8) usize {
    var off: usize = 0;
    for (p.replicas.items) |r| {
        const body_sz = sizeReplica(r);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalReplica(r, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 2, p.container_backup_factor);
    for (p.selectors.items) |s| {
        const body_sz = sizeSelector(s);
        const tag = wire.putTag(out[off..], 3, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSelector(s, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (p.filters.items) |f| {
        const body_sz = sizeFilter(f);
        const tag = wire.putTag(out[off..], 4, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalFilter(f, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (p.subnet_id) |sid| {
        const body_sz = sizeSubnetID(sid);
        const tag = wire.putTag(out[off..], 5, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSubnetID(sid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (p.ec_rules.items) |rule| {
        const body_sz = sizeECRule(rule);
        const tag = wire.putTag(out[off..], 6, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalECRule(rule, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (p.initial) |initial| {
        const body_sz = sizePlacementInitial(initial);
        const tag = wire.putTag(out[off..], 7, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalPlacementInitial(initial, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

fn sizeSelector(s: netmap_pb.Selector) usize {
    return sizeBytes(1, s.name) +
        sizeVarint(2, s.count) +
        sizeVarint(3, @intCast(@max(@intFromEnum(s.clause), 0))) +
        sizeBytes(4, s.attribute) +
        sizeBytes(5, s.filter);
}
fn marshalSelector(s: netmap_pb.Selector, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, s.name);
    off += marshalVarint(out[off..], 2, s.count);
    off += marshalVarint(out[off..], 3, @intCast(@max(@intFromEnum(s.clause), 0)));
    off += marshalBytes(out[off..], 4, s.attribute);
    off += marshalBytes(out[off..], 5, s.filter);
    return off;
}
fn sizeFilter(f: netmap_pb.Filter) usize {
    var total = sizeBytes(1, f.name) + sizeBytes(2, f.key) + sizeVarint(3, @intCast(@max(@intFromEnum(f.op), 0))) + sizeBytes(4, f.value);
    for (f.filters.items) |sub| {
        const sz = sizeFilter(sub);
        total += sizeEmbedded(5, sz);
    }
    return total;
}
fn marshalFilter(f: netmap_pb.Filter, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, f.name);
    off += marshalBytes(out[off..], 2, f.key);
    off += marshalVarint(out[off..], 3, @intCast(@max(@intFromEnum(f.op), 0)));
    off += marshalBytes(out[off..], 4, f.value);
    for (f.filters.items) |sub| {
        const body_sz = sizeFilter(sub);
        const tag = wire.putTag(out[off..], 5, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalFilter(sub, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}
fn sizeSubnetID(s: refs_pb.SubnetID) usize {
    return sizeVarint(1, s.value);
}
fn marshalSubnetID(s: refs_pb.SubnetID, out: []u8) usize {
    return marshalVarint(out, 1, s.value);
}
fn sizeECRule(r: netmap_pb.PlacementPolicy.ECRule) usize {
    return sizeVarint(1, r.data_part_num) +
        sizeVarint(2, r.parity_part_num) +
        sizeBytes(3, r.selector);
}
fn marshalECRule(r: netmap_pb.PlacementPolicy.ECRule, out: []u8) usize {
    var off: usize = 0;
    off += marshalVarint(out[off..], 1, r.data_part_num);
    off += marshalVarint(out[off..], 2, r.parity_part_num);
    off += marshalBytes(out[off..], 3, r.selector);
    return off;
}
fn sizePlacementInitial(i: netmap_pb.PlacementPolicy.Initial) usize {
    _ = i;
    return 0;
}
fn marshalPlacementInitial(i: netmap_pb.PlacementPolicy.Initial, out: []u8) usize {
    _ = i;
    _ = out;
    return 0;
}

fn sizeContainerAttribute(a: container_pb.Container.Attribute) usize {
    return sizeBytes(1, a.key) + sizeBytes(2, a.value);
}

fn marshalContainerAttribute(a: container_pb.Container.Attribute, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, a.key);
    off += marshalBytes(out[off..], 2, a.value);
    return off;
}

pub fn sizeContainer(c: container_pb.Container) usize {
    var total: usize = 0;
    if (c.version) |v| {
        const sz = sizeVersion(v);
        total += sizeEmbedded(1, sz);
    }
    if (c.owner_id) |o| {
        const sz = sizeOwnerID(o);
        total += sizeEmbedded(2, sz);
    }
    total += sizeBytes(3, c.nonce);
    total += sizeVarint(4, c.basic_acl);
    for (c.attributes.items) |a| {
        const sz = sizeContainerAttribute(a);
        total += sizeEmbedded(5, sz);
    }
    if (c.placement_policy) |p| {
        const sz = sizePlacementPolicy(p);
        total += sizeEmbedded(6, sz);
    }
    return total;
}

pub fn marshalContainer(c: container_pb.Container, out: []u8) usize {
    var off: usize = 0;
    if (c.version) |v| {
        const body_sz = sizeVersion(v);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalVersion(v, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (c.owner_id) |o| {
        const body_sz = sizeOwnerID(o);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalOwnerID(o, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalBytes(out[off..], 3, c.nonce);
    off += marshalVarint(out[off..], 4, c.basic_acl);
    for (c.attributes.items) |a| {
        const body_sz = sizeContainerAttribute(a);
        const tag = wire.putTag(out[off..], 5, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalContainerAttribute(a, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (c.placement_policy) |p| {
        const body_sz = sizePlacementPolicy(p);
        const tag = wire.putTag(out[off..], 6, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalPlacementPolicy(p, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

fn sizePutRequestBody(b: container_pb.PutRequest.Body) usize {
    var total: usize = 0;
    if (b.container) |c| {
        total += sizeEmbedded(1, sizeContainer(c));
    }
    if (b.signature) |s| {
        total += sizeEmbedded(2, sizeSignatureRFC6979(s));
    }
    return total;
}

fn marshalPutRequestBody(b: container_pb.PutRequest.Body, out: []u8) usize {
    var off: usize = 0;
    if (b.container) |c| {
        const c_sz = sizeContainer(c);
        const c_tag = wire.putTag(out[off..], 1, 2);
        const c_len = wire.putVarint(out[off + c_tag ..], c_sz);
        _ = marshalContainer(c, out[off + c_tag + c_len ..][0..c_sz]);
        off += c_tag + c_len + c_sz;
    }
    if (b.signature) |s| {
        const s_sz = sizeSignatureRFC6979(s);
        const s_tag = wire.putTag(out[off..], 2, 2);
        const s_len = wire.putVarint(out[off + s_tag ..], s_sz);
        _ = marshalSignatureRFC6979(s, out[off + s_tag + s_len ..][0..s_sz]);
        off += s_tag + s_len + s_sz;
    }
    return off;
}

fn sizeListRequestBody(b: container_pb.ListRequest.Body) usize {
    if (b.owner_id) |o| {
        return sizeEmbedded(1, sizeOwnerID(o));
    }
    return 0;
}

fn marshalListRequestBody(b: container_pb.ListRequest.Body, out: []u8) usize {
    if (b.owner_id) |o| {
        const body_sz = sizeOwnerID(o);
        const tag = wire.putTag(out, 1, 2);
        const len = wire.putVarint(out[tag..], body_sz);
        _ = marshalOwnerID(o, out[tag + len ..][0..body_sz]);
        return tag + len + body_sz;
    }
    return 0;
}

fn sizeGetRequestBody(b: container_pb.GetRequest.Body) usize {
    if (b.container_id) |cid| {
        return sizeEmbedded(1, sizeContainerID(cid));
    }
    return 0;
}

fn sizeGetExtendedACLRequestBody(b: container_pb.GetExtendedACLRequest.Body) usize {
    if (b.container_id) |cid| {
        return sizeEmbedded(1, sizeContainerID(cid));
    }
    return 0;
}

fn marshalGetRequestBody(b: container_pb.GetRequest.Body, out: []u8) usize {
    if (b.container_id) |cid| {
        const body_sz = sizeContainerID(cid);
        const tag = wire.putTag(out, 1, 2);
        const len = wire.putVarint(out[tag..], body_sz);
        _ = marshalContainerID(cid, out[tag + len ..][0..body_sz]);
        return tag + len + body_sz;
    }
    return 0;
}

fn marshalGetExtendedACLRequestBody(b: container_pb.GetExtendedACLRequest.Body, out: []u8) usize {
    if (b.container_id) |cid| {
        const body_sz = sizeContainerID(cid);
        const tag = wire.putTag(out, 1, 2);
        const len = wire.putVarint(out[tag..], body_sz);
        _ = marshalContainerID(cid, out[tag + len ..][0..body_sz]);
        return tag + len + body_sz;
    }
    return 0;
}

fn sizeDeleteRequestBody(b: container_pb.DeleteRequest.Body) usize {
    var total: usize = 0;
    if (b.container_id) |cid| {
        total += sizeEmbedded(1, sizeContainerID(cid));
    }
    if (b.signature) |s| {
        total += sizeEmbedded(2, sizeSignatureRFC6979(s));
    }
    return total;
}

fn marshalDeleteRequestBody(b: container_pb.DeleteRequest.Body, out: []u8) usize {
    var off: usize = 0;
    if (b.container_id) |cid| {
        const body_sz = sizeContainerID(cid);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalContainerID(cid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (b.signature) |s| {
        const s_sz = sizeSignatureRFC6979(s);
        const s_tag = wire.putTag(out[off..], 2, 2);
        const s_len = wire.putVarint(out[off + s_tag ..], s_sz);
        _ = marshalSignatureRFC6979(s, out[off + s_tag + s_len ..][0..s_sz]);
        off += s_tag + s_len + s_sz;
    }
    return off;
}

fn sizeCreateRequestBody(b: session_pb.CreateRequest.Body) usize {
    var total: usize = 0;
    if (b.owner_id) |o| {
        total += sizeEmbedded(1, sizeOwnerID(o));
    }
    total += sizeVarint(2, b.expiration);
    return total;
}

fn marshalCreateRequestBody(b: session_pb.CreateRequest.Body, out: []u8) usize {
    var off: usize = 0;
    if (b.owner_id) |o| {
        const body_sz = sizeOwnerID(o);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalOwnerID(o, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 2, b.expiration);
    return off;
}

fn sizeObjectDeleteRequestBody(b: object_pb.DeleteRequest.Body) usize {
    if (b.address) |addr| {
        return sizeEmbedded(1, sizeAddress(addr));
    }
    return 0;
}

fn marshalObjectDeleteRequestBody(b: object_pb.DeleteRequest.Body, out: []u8) usize {
    if (b.address) |addr| {
        const body_sz = sizeAddress(addr);
        const tag = wire.putTag(out, 1, 2);
        const len = wire.putVarint(out[tag..], body_sz);
        _ = marshalAddress(addr, out[tag + len ..][0..body_sz]);
        return tag + len + body_sz;
    }
    return 0;
}

fn sizeBalanceRequestBody(b: accounting_pb.BalanceRequest.Body) usize {
    if (b.owner_id) |owner_id| {
        return sizeEmbedded(1, sizeOwnerID(owner_id));
    }
    return 0;
}

fn marshalBalanceRequestBody(b: accounting_pb.BalanceRequest.Body, out: []u8) usize {
    if (b.owner_id) |owner_id| {
        const body_sz = sizeOwnerID(owner_id);
        const tag = wire.putTag(out, 1, 2);
        const len = wire.putVarint(out[tag..], body_sz);
        _ = marshalOwnerID(owner_id, out[tag + len ..][0..body_sz]);
        return tag + len + body_sz;
    }
    return 0;
}

fn sizeRange(r: object_pb.Range) usize {
    return sizeVarint(1, r.offset) + sizeVarint(2, r.length);
}

fn marshalRange(r: object_pb.Range, out: []u8) usize {
    var off = marshalVarint(out, 1, r.offset);
    off += marshalVarint(out[off..], 2, r.length);
    return off;
}

fn sizeObjectGetRequestBody(b: object_pb.GetRequest.Body) usize {
    var total: usize = 0;
    if (b.address) |addr| total += sizeEmbedded(1, sizeAddress(addr));
    total += sizeBool(2, b.raw);
    if (b.range) |rng| total += sizeEmbedded(3, sizeRange(rng));
    total += sizeBool(4, b.payload_only);
    return total;
}

fn marshalObjectGetRequestBody(b: object_pb.GetRequest.Body, out: []u8) usize {
    var off: usize = 0;
    if (b.address) |addr| {
        const body_sz = sizeAddress(addr);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalAddress(addr, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalBool(out[off..], 2, b.raw);
    if (b.range) |rng| {
        const body_sz = sizeRange(rng);
        const tag = wire.putTag(out[off..], 3, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalRange(rng, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalBool(out[off..], 4, b.payload_only);
    return off;
}

fn sizeObjectHeadRequestBody(b: object_pb.HeadRequest.Body) usize {
    var total: usize = 0;
    if (b.address) |addr| total += sizeEmbedded(1, sizeAddress(addr));
    total += sizeBool(2, b.main_only);
    total += sizeBool(3, b.raw);
    return total;
}

fn marshalObjectHeadRequestBody(b: object_pb.HeadRequest.Body, out: []u8) usize {
    var off: usize = 0;
    if (b.address) |addr| {
        const body_sz = sizeAddress(addr);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalAddress(addr, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalBool(out[off..], 2, b.main_only);
    off += marshalBool(out[off..], 3, b.raw);
    return off;
}

fn sizeAddress(a: refs_pb.Address) usize {
    var total: usize = 0;
    if (a.container_id) |cid| {
        total += sizeEmbedded(1, sizeContainerID(cid));
    }
    if (a.object_id) |oid| {
        total += sizeEmbedded(2, sizeObjectID(oid));
    }
    return total;
}

fn marshalAddress(a: refs_pb.Address, out: []u8) usize {
    var off: usize = 0;
    if (a.container_id) |cid| {
        const body_sz = sizeContainerID(cid);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalContainerID(cid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (a.object_id) |oid| {
        const body_sz = sizeObjectID(oid);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectID(oid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

fn sizeObjectID(o: refs_pb.ObjectID) usize {
    return sizeBytes(1, o.value);
}

fn marshalObjectID(o: refs_pb.ObjectID, out: []u8) usize {
    return marshalBytes(out, 1, o.value);
}

fn sizeXHeader(h: session_pb.XHeader) usize {
    return sizeBytes(1, h.key) + sizeBytes(2, h.value);
}

fn marshalXHeader(h: session_pb.XHeader, out: []u8) usize {
    var off: usize = 0;
    off += marshalBytes(out[off..], 1, h.key);
    off += marshalBytes(out[off..], 2, h.value);
    return off;
}

pub fn sizeRequestMetaHeader(m: session_pb.RequestMetaHeader) usize {
    var total: usize = 0;
    if (m.version) |v| {
        total += sizeEmbedded(1, sizeVersion(v));
    }
    total += sizeVarint(2, m.epoch);
    total += sizeVarint(3, m.ttl);
    for (m.x_headers.items) |h| {
        total += sizeEmbedded(4, sizeXHeader(h));
    }
    if (m.session_token) |tok| {
        total += sizeEmbedded(5, sizeSessionToken(tok));
    }
    if (m.bearer_token) |tok| {
        total += sizeEmbedded(6, sizeBearerToken(tok));
    }
    if (m.origin) |origin| {
        total += sizeEmbedded(7, sizeRequestMetaHeader(origin.*));
    }
    total += sizeVarint(8, m.magic_number);
    if (m.session_token_v2) |tok| {
        total += sizeEmbedded(9, sizeSessionTokenV2(tok));
    }
    return total;
}

pub fn marshalRequestMetaHeader(m: session_pb.RequestMetaHeader, out: []u8) usize {
    var off: usize = 0;
    if (m.version) |v| {
        const body_sz = sizeVersion(v);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalVersion(v, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 2, m.epoch);
    off += marshalVarint(out[off..], 3, m.ttl);
    for (m.x_headers.items) |h| {
        const body_sz = sizeXHeader(h);
        const tag = wire.putTag(out[off..], 4, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalXHeader(h, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (m.session_token) |tok| {
        const body_sz = sizeSessionToken(tok);
        if (body_sz > 0) {
            const tag = wire.putTag(out[off..], 5, 2);
            const len = wire.putVarint(out[off + tag ..], body_sz);
            _ = marshalSessionToken(tok, out[off + tag + len ..][0..body_sz]);
            off += tag + len + body_sz;
        }
    }
    if (m.bearer_token) |tok| {
        const body_sz = sizeBearerToken(tok);
        if (body_sz > 0) {
            const tag = wire.putTag(out[off..], 6, 2);
            const len = wire.putVarint(out[off + tag ..], body_sz);
            _ = marshalBearerToken(tok, out[off + tag + len ..][0..body_sz]);
            off += tag + len + body_sz;
        }
    }
    if (m.origin) |origin| {
        const body_sz = sizeRequestMetaHeader(origin.*);
        const tag = wire.putTag(out[off..], 7, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalRequestMetaHeader(origin.*, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 8, m.magic_number);
    if (m.session_token_v2) |tok| {
        const body_sz = sizeSessionTokenV2(tok);
        if (body_sz > 0) {
            const tag = wire.putTag(out[off..], 9, 2);
            const len = wire.putVarint(out[off + tag ..], body_sz);
            _ = marshalSessionTokenV2(tok, out[off + tag + len ..][0..body_sz]);
            off += tag + len + body_sz;
        }
    }
    return off;
}

fn sizeBool(field_num: u32, v: bool) usize {
    return sizeVarint(field_num, if (v) 1 else 0);
}

fn marshalBool(out: []u8, field_num: u32, v: bool) usize {
    return marshalVarint(out, field_num, if (v) 1 else 0);
}

fn sizeTokenLifetime(l: session_pb.SessionToken.Body.TokenLifetime) usize {
    return sizeVarint(1, l.exp) + sizeVarint(2, l.nbf) + sizeVarint(3, l.iat);
}

fn marshalTokenLifetime(l: session_pb.SessionToken.Body.TokenLifetime, out: []u8) usize {
    var off = marshalVarint(out, 1, l.exp);
    off += marshalVarint(out[off..], 2, l.nbf);
    off += marshalVarint(out[off..], 3, l.iat);
    return off;
}

fn sizeObjectSessionContextTarget(t: session_pb.ObjectSessionContext.Target) usize {
    var total: usize = 0;
    if (t.container) |cid| total += sizeEmbedded(1, sizeContainerID(cid));
    for (t.objects.items) |oid| total += sizeEmbedded(2, sizeObjectID(oid));
    return total;
}

fn marshalObjectSessionContextTarget(t: session_pb.ObjectSessionContext.Target, out: []u8) usize {
    var off: usize = 0;
    if (t.container) |cid| {
        const body_sz = sizeContainerID(cid);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalContainerID(cid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (t.objects.items) |oid| {
        const body_sz = sizeObjectID(oid);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectID(oid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

fn sizeObjectSessionContext(ctx: session_pb.ObjectSessionContext) usize {
    var total = sizeVarint(1, @intCast(@intFromEnum(ctx.verb)));
    if (ctx.target) |t| total += sizeEmbedded(2, sizeObjectSessionContextTarget(t));
    return total;
}

fn marshalObjectSessionContext(ctx: session_pb.ObjectSessionContext, out: []u8) usize {
    var off = marshalVarint(out, 1, @intCast(@intFromEnum(ctx.verb)));
    if (ctx.target) |t| {
        const body_sz = sizeObjectSessionContextTarget(t);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectSessionContextTarget(t, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

fn sizeContainerSessionContext(ctx: session_pb.ContainerSessionContext) usize {
    var total = sizeVarint(1, @intCast(@intFromEnum(ctx.verb)));
    total += sizeBool(2, ctx.wildcard);
    if (ctx.container_id) |cid| total += sizeEmbedded(3, sizeContainerID(cid));
    return total;
}

fn marshalContainerSessionContext(ctx: session_pb.ContainerSessionContext, out: []u8) usize {
    var off = marshalVarint(out, 1, @intCast(@intFromEnum(ctx.verb)));
    off += marshalBool(out[off..], 2, ctx.wildcard);
    if (ctx.container_id) |cid| {
        const body_sz = sizeContainerID(cid);
        const tag = wire.putTag(out[off..], 3, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalContainerID(cid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

fn sizeSessionTokenBody(body: session_pb.SessionToken.Body) usize {
    var total = sizeBytes(1, body.id);
    if (body.owner_id) |o| total += sizeEmbedded(2, sizeOwnerID(o));
    if (body.lifetime) |l| total += sizeEmbedded(3, sizeTokenLifetime(l));
    total += sizeBytes(4, body.session_key);
    if (body.context) |ctx| {
        total += switch (ctx) {
            .object => |object_ctx| sizeEmbedded(5, sizeObjectSessionContext(object_ctx)),
            .container => |container_ctx| sizeEmbedded(6, sizeContainerSessionContext(container_ctx)),
        };
    }
    return total;
}

fn marshalSessionTokenBody(body: session_pb.SessionToken.Body, out: []u8) usize {
    var off = marshalBytes(out, 1, body.id);
    if (body.owner_id) |o| {
        const body_sz = sizeOwnerID(o);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalOwnerID(o, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (body.lifetime) |l| {
        const body_sz = sizeTokenLifetime(l);
        const tag = wire.putTag(out[off..], 3, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalTokenLifetime(l, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalBytes(out[off..], 4, body.session_key);
    if (body.context) |ctx| {
        switch (ctx) {
            .object => |object_ctx| {
                const body_sz = sizeObjectSessionContext(object_ctx);
                const tag = wire.putTag(out[off..], 5, 2);
                const len = wire.putVarint(out[off + tag ..], body_sz);
                _ = marshalObjectSessionContext(object_ctx, out[off + tag + len ..][0..body_sz]);
                off += tag + len + body_sz;
            },
            .container => |container_ctx| {
                const body_sz = sizeContainerSessionContext(container_ctx);
                const tag = wire.putTag(out[off..], 6, 2);
                const len = wire.putVarint(out[off + tag ..], body_sz);
                _ = marshalContainerSessionContext(container_ctx, out[off + tag + len ..][0..body_sz]);
                off += tag + len + body_sz;
            },
        }
    }
    return off;
}

fn sizeSessionToken(tok: session_pb.SessionToken) usize {
    var total: usize = 0;
    if (tok.body) |body| total += sizeEmbedded(1, sizeSessionTokenBody(body));
    if (tok.signature) |s| total += sizeEmbedded(2, sizeSignature(s));
    return total;
}

fn marshalSessionToken(tok: session_pb.SessionToken, out: []u8) usize {
    var off: usize = 0;
    if (tok.body) |body| {
        const body_sz = sizeSessionTokenBody(body);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSessionTokenBody(body, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (tok.signature) |s| {
        const body_sz = sizeSignature(s);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSignature(s, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

fn sizeSessionTokenV2(tok: session_pb.SessionTokenV2) usize {
    return session_v2_enc.sizeSessionTokenV2(tok);
}
fn marshalSessionTokenV2(tok: session_pb.SessionTokenV2, out: []u8) usize {
    return session_v2_enc.marshalSessionTokenV2(tok, out);
}
fn sizeBearerToken(_: @import("../../proto/gen/acl/types.pb.zig").BearerToken) usize {
    return 0;
}
fn marshalBearerToken(_: @import("../../proto/gen/acl/types.pb.zig").BearerToken, _: []u8) usize {
    return 0;
}

fn sizeAnnounceLocalTrustBody(b: reputation_pb.AnnounceLocalTrustRequest.Body) usize {
    return sizeVarint(1, b.epoch);
}

fn marshalAnnounceLocalTrustBody(b: reputation_pb.AnnounceLocalTrustRequest.Body, out: []u8) usize {
    return marshalVarint(out, 1, b.epoch);
}

fn sizeAnnounceIntermediateResultBody(b: reputation_pb.AnnounceIntermediateResultRequest.Body) usize {
    var total = sizeVarint(1, b.epoch);
    total += sizeVarint(2, b.iteration);
    return total;
}

fn marshalAnnounceIntermediateResultBody(b: reputation_pb.AnnounceIntermediateResultRequest.Body, out: []u8) usize {
    var off = marshalVarint(out, 1, b.epoch);
    off += marshalVarint(out[off..], 2, b.iteration);
    return off;
}

fn sizeChecksum(c: refs_pb.Checksum) usize {
    return sizeVarint(1, @intCast(@intFromEnum(c.type))) + sizeBytes(2, c.sum);
}

fn marshalChecksum(c: refs_pb.Checksum, out: []u8) usize {
    var off = marshalVarint(out, 1, @intCast(@intFromEnum(c.type)));
    off += marshalBytes(out[off..], 2, c.sum);
    return off;
}

fn sizeObjectHeaderAttribute(a: object_pb.Header.Attribute) usize {
    return sizeBytes(1, a.key) + sizeBytes(2, a.value);
}

fn marshalObjectHeaderAttribute(a: object_pb.Header.Attribute, out: []u8) usize {
    var off = marshalBytes(out, 1, a.key);
    off += marshalBytes(out[off..], 2, a.value);
    return off;
}

fn sizeObjectHeader(h: object_pb.Header) usize {
    var total: usize = 0;
    if (h.version) |v| total += sizeEmbedded(1, sizeVersion(v));
    if (h.container_id) |cid| total += sizeEmbedded(2, sizeContainerID(cid));
    if (h.owner_id) |o| total += sizeEmbedded(3, sizeOwnerID(o));
    total += sizeVarint(4, h.creation_epoch);
    total += sizeVarint(5, h.payload_length);
    if (h.payload_hash) |cs| total += sizeEmbedded(6, sizeChecksum(cs));
    total += sizeVarint(7, @intCast(@intFromEnum(h.object_type)));
    if (h.homomorphic_hash) |cs| total += sizeEmbedded(8, sizeChecksum(cs));
    if (h.session_token) |tok| total += sizeEmbedded(9, sizeSessionToken(tok));
    for (h.attributes.items) |a| total += sizeEmbedded(10, sizeObjectHeaderAttribute(a));
    if (h.split) |split| total += sizeEmbedded(11, sizeObjectHeaderSplit(split.*));
    if (h.session_token_v2) |tok| total += sizeEmbedded(12, sizeSessionTokenV2(tok));
    return total;
}

fn marshalObjectHeader(h: object_pb.Header, out: []u8) usize {
    var off: usize = 0;
    if (h.version) |v| {
        const body_sz = sizeVersion(v);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalVersion(v, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (h.container_id) |cid| {
        const body_sz = sizeContainerID(cid);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalContainerID(cid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (h.owner_id) |o| {
        const body_sz = sizeOwnerID(o);
        const tag = wire.putTag(out[off..], 3, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalOwnerID(o, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 4, h.creation_epoch);
    off += marshalVarint(out[off..], 5, h.payload_length);
    if (h.payload_hash) |cs| {
        const body_sz = sizeChecksum(cs);
        const tag = wire.putTag(out[off..], 6, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalChecksum(cs, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 7, @intCast(@intFromEnum(h.object_type)));
    if (h.homomorphic_hash) |cs| {
        const body_sz = sizeChecksum(cs);
        const tag = wire.putTag(out[off..], 8, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalChecksum(cs, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (h.session_token) |tok| {
        const body_sz = sizeSessionToken(tok);
        const tag = wire.putTag(out[off..], 9, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSessionToken(tok, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (h.attributes.items) |a| {
        const body_sz = sizeObjectHeaderAttribute(a);
        const tag = wire.putTag(out[off..], 10, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectHeaderAttribute(a, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (h.split) |split| {
        const body_sz = sizeObjectHeaderSplit(split.*);
        if (body_sz > 0) {
            const tag = wire.putTag(out[off..], 11, 2);
            const len = wire.putVarint(out[off + tag ..], body_sz);
            _ = marshalObjectHeaderSplit(split.*, out[off + tag + len ..][0..body_sz]);
            off += tag + len + body_sz;
        }
    }
    if (h.session_token_v2) |tok| {
        const body_sz = sizeSessionTokenV2(tok);
        const tag = wire.putTag(out[off..], 12, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSessionTokenV2(tok, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

fn sizeObjectHeaderSplit(s: object_pb.Split) usize {
    var total: usize = 0;
    if (s.parent) |p| total += sizeEmbedded(1, sizeObjectID(p));
    if (s.previous) |p| total += sizeEmbedded(2, sizeObjectID(p));
    for (s.children.items) |c| total += sizeEmbedded(5, sizeObjectID(c));
    if (s.split_id.len > 0) total += sizeBytes(6, s.split_id);
    if (s.first) |f| total += sizeEmbedded(7, sizeObjectID(f));
    return total;
}

fn marshalObjectHeaderSplit(s: object_pb.Split, out: []u8) usize {
    var off: usize = 0;
    if (s.parent) |p| {
        const body_sz = sizeObjectID(p);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectID(p, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (s.previous) |p| {
        const body_sz = sizeObjectID(p);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectID(p, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (s.children.items) |c| {
        const body_sz = sizeObjectID(c);
        const tag = wire.putTag(out[off..], 5, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectID(c, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (s.split_id.len > 0) {
        off += marshalBytes(out[off..], 6, s.split_id);
    }
    if (s.first) |f| {
        const body_sz = sizeObjectID(f);
        const tag = wire.putTag(out[off..], 7, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectID(f, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

fn sizeObjectPutRequestInit(init: object_pb.PutRequest.Body.Init) usize {
    var total: usize = 0;
    if (init.object_id) |oid| total += sizeEmbedded(1, sizeObjectID(oid));
    if (init.signature) |s| total += sizeEmbedded(2, sizeSignature(s));
    if (init.header) |h| total += sizeEmbedded(3, sizeObjectHeader(h));
    total += sizeVarint(4, init.copies_number);
    return total;
}

fn marshalObjectPutRequestInit(init: object_pb.PutRequest.Body.Init, out: []u8) usize {
    var off: usize = 0;
    if (init.object_id) |oid| {
        const body_sz = sizeObjectID(oid);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectID(oid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (init.signature) |s| {
        const body_sz = sizeSignature(s);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSignature(s, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (init.header) |h| {
        const body_sz = sizeObjectHeader(h);
        const tag = wire.putTag(out[off..], 3, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalObjectHeader(h, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 4, init.copies_number);
    return off;
}

fn sizeObjectPutRequestBody(b: object_pb.PutRequest.Body) usize {
    const part = b.object_part orelse return 0;
    return switch (part) {
        .init => |init| sizeEmbedded(1, sizeObjectPutRequestInit(init)),
        .chunk => |chunk| sizeBytes(2, chunk),
    };
}

fn marshalObjectPutRequestBody(b: object_pb.PutRequest.Body, out: []u8) usize {
    const part = b.object_part orelse return 0;
    return switch (part) {
        .init => |init| blk: {
            const body_sz = sizeObjectPutRequestInit(init);
            const tag = wire.putTag(out, 1, 2);
            const len = wire.putVarint(out[tag..], body_sz);
            _ = marshalObjectPutRequestInit(init, out[tag + len ..][0..body_sz]);
            break :blk tag + len + body_sz;
        },
        .chunk => |chunk| marshalBytes(out, 2, chunk),
    };
}

fn sizeSearchFilter(f: object_pb.SearchFilter) usize {
    return sizeVarint(1, @intCast(@intFromEnum(f.match_type))) + sizeBytes(2, f.key) + sizeBytes(3, f.value);
}

fn marshalSearchFilter(f: object_pb.SearchFilter, out: []u8) usize {
    var off = marshalVarint(out, 1, @intCast(@intFromEnum(f.match_type)));
    off += marshalBytes(out[off..], 2, f.key);
    off += marshalBytes(out[off..], 3, f.value);
    return off;
}

fn sizeSearchV2RequestBody(b: object_pb.SearchV2Request.Body) usize {
    var total: usize = 0;
    if (b.container_id) |cid| total += sizeEmbedded(1, sizeContainerID(cid));
    total += sizeVarint(2, b.version);
    for (b.filters.items) |f| total += sizeEmbedded(3, sizeSearchFilter(f));
    total += sizeBytes(4, b.cursor);
    total += sizeVarint(5, b.count);
    for (b.attributes.items) |attr| total += sizeBytes(6, attr);
    return total;
}

fn marshalSearchV2RequestBody(b: object_pb.SearchV2Request.Body, out: []u8) usize {
    var off: usize = 0;
    if (b.container_id) |cid| {
        const body_sz = sizeContainerID(cid);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalContainerID(cid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalVarint(out[off..], 2, b.version);
    for (b.filters.items) |f| {
        const body_sz = sizeSearchFilter(f);
        const tag = wire.putTag(out[off..], 3, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSearchFilter(f, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    off += marshalBytes(out[off..], 4, b.cursor);
    off += marshalVarint(out[off..], 5, b.count);
    for (b.attributes.items) |attr| off += marshalBytes(out[off..], 6, attr);
    return off;
}

fn sizeEACLRecordTarget(t: acl_pb.EACLRecord.Target) usize {
    var total = sizeVarint(1, @intCast(@intFromEnum(t.role)));
    for (t.keys.items) |key| total += sizeBytes(2, key);
    return total;
}

fn marshalEACLRecordTarget(t: acl_pb.EACLRecord.Target, out: []u8) usize {
    var off = marshalVarint(out, 1, @intCast(@intFromEnum(t.role)));
    for (t.keys.items) |key| off += marshalBytes(out[off..], 2, key);
    return off;
}

fn sizeEACLRecordFilter(f: acl_pb.EACLRecord.Filter) usize {
    return sizeVarint(1, @intCast(@intFromEnum(f.header_type))) +
        sizeVarint(2, @intCast(@intFromEnum(f.match_type))) +
        sizeBytes(3, f.key) +
        sizeBytes(4, f.value);
}

fn marshalEACLRecordFilter(f: acl_pb.EACLRecord.Filter, out: []u8) usize {
    var off = marshalVarint(out, 1, @intCast(@intFromEnum(f.header_type)));
    off += marshalVarint(out[off..], 2, @intCast(@intFromEnum(f.match_type)));
    off += marshalBytes(out[off..], 3, f.key);
    off += marshalBytes(out[off..], 4, f.value);
    return off;
}

fn sizeEACLRecord(r: acl_pb.EACLRecord) usize {
    var total = sizeVarint(1, @intCast(@intFromEnum(r.operation)));
    total += sizeVarint(2, @intCast(@intFromEnum(r.action)));
    for (r.filters.items) |f| total += sizeEmbedded(3, sizeEACLRecordFilter(f));
    for (r.targets.items) |t| total += sizeEmbedded(4, sizeEACLRecordTarget(t));
    return total;
}

fn marshalEACLRecord(r: acl_pb.EACLRecord, out: []u8) usize {
    var off = marshalVarint(out, 1, @intCast(@intFromEnum(r.operation)));
    off += marshalVarint(out[off..], 2, @intCast(@intFromEnum(r.action)));
    for (r.filters.items) |f| {
        const body_sz = sizeEACLRecordFilter(f);
        const tag = wire.putTag(out[off..], 3, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalEACLRecordFilter(f, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (r.targets.items) |t| {
        const body_sz = sizeEACLRecordTarget(t);
        const tag = wire.putTag(out[off..], 4, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalEACLRecordTarget(t, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

fn sizeEACLTable(t: acl_pb.EACLTable) usize {
    var total: usize = 0;
    if (t.version) |v| total += sizeEmbedded(1, sizeVersion(v));
    if (t.container_id) |cid| total += sizeEmbedded(2, sizeContainerID(cid));
    for (t.records.items) |r| total += sizeEmbedded(3, sizeEACLRecord(r));
    return total;
}

fn marshalEACLTable(t: acl_pb.EACLTable, out: []u8) usize {
    var off: usize = 0;
    if (t.version) |v| {
        const body_sz = sizeVersion(v);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalVersion(v, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (t.container_id) |cid| {
        const body_sz = sizeContainerID(cid);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalContainerID(cid, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    for (t.records.items) |r| {
        const body_sz = sizeEACLRecord(r);
        const tag = wire.putTag(out[off..], 3, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalEACLRecord(r, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

fn sizeSetExtendedACLRequestBody(b: container_pb.SetExtendedACLRequest.Body) usize {
    var total: usize = 0;
    if (b.eacl) |table| total += sizeEmbedded(1, sizeEACLTable(table));
    if (b.signature) |s| total += sizeEmbedded(2, sizeSignatureRFC6979(s));
    return total;
}

fn marshalSetExtendedACLRequestBody(b: container_pb.SetExtendedACLRequest.Body, out: []u8) usize {
    var off: usize = 0;
    if (b.eacl) |table| {
        const body_sz = sizeEACLTable(table);
        const tag = wire.putTag(out[off..], 1, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalEACLTable(table, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    if (b.signature) |s| {
        const body_sz = sizeSignatureRFC6979(s);
        const tag = wire.putTag(out[off..], 2, 2);
        const len = wire.putVarint(out[off + tag ..], body_sz);
        _ = marshalSignatureRFC6979(s, out[off + tag + len ..][0..body_sz]);
        off += tag + len + body_sz;
    }
    return off;
}

pub fn sizeMessage(msg: anytype) usize {
    const T = @TypeOf(msg);
    return switch (T) {
        session_pb.RequestMetaHeader => sizeRequestMetaHeader(msg),
        refs_pb.ObjectID => sizeObjectID(msg),
        object_pb.Header => sizeObjectHeader(msg),
        container_pb.PutRequest.Body => sizePutRequestBody(msg),
        container_pb.ListRequest.Body => sizeListRequestBody(msg),
        container_pb.GetRequest.Body => sizeGetRequestBody(msg),
        container_pb.GetExtendedACLRequest.Body => sizeGetExtendedACLRequestBody(msg),
        container_pb.DeleteRequest.Body => sizeDeleteRequestBody(msg),
        session_pb.CreateRequest.Body => sizeCreateRequestBody(msg),
        object_pb.DeleteRequest.Body => sizeObjectDeleteRequestBody(msg),
        object_pb.GetRequest.Body => sizeObjectGetRequestBody(msg),
        object_pb.HeadRequest.Body => sizeObjectHeadRequestBody(msg),
        accounting_pb.BalanceRequest.Body => sizeBalanceRequestBody(msg),
        object_pb.PutRequest.Body => sizeObjectPutRequestBody(msg),
        object_pb.SearchV2Request.Body => sizeSearchV2RequestBody(msg),
        session_pb.SessionToken.Body => sizeSessionTokenBody(msg),
        session_pb.SessionTokenV2.Body => session_v2_enc.sizeSessionTokenV2Body(msg),
        reputation_pb.AnnounceLocalTrustRequest.Body => sizeAnnounceLocalTrustBody(msg),
        reputation_pb.AnnounceIntermediateResultRequest.Body => sizeAnnounceIntermediateResultBody(msg),
        netmap_pb.NetworkInfoRequest.Body => sizeEmpty(msg),
        container_pb.SetExtendedACLRequest.Body => sizeSetExtendedACLRequestBody(msg),
        acl_pb.EACLTable => sizeEACLTable(msg),
        else => @compileError("unsupported stable signing message type: " ++ @typeName(T)),
    };
}

pub fn marshalMessage(msg: anytype, out: []u8) usize {
    const T = @TypeOf(msg);
    return switch (T) {
        session_pb.RequestMetaHeader => marshalRequestMetaHeader(msg, out),
        refs_pb.ObjectID => marshalObjectID(msg, out),
        object_pb.Header => marshalObjectHeader(msg, out),
        container_pb.PutRequest.Body => marshalPutRequestBody(msg, out),
        container_pb.ListRequest.Body => marshalListRequestBody(msg, out),
        container_pb.GetRequest.Body => marshalGetRequestBody(msg, out),
        container_pb.GetExtendedACLRequest.Body => marshalGetExtendedACLRequestBody(msg, out),
        container_pb.DeleteRequest.Body => marshalDeleteRequestBody(msg, out),
        session_pb.CreateRequest.Body => marshalCreateRequestBody(msg, out),
        object_pb.DeleteRequest.Body => marshalObjectDeleteRequestBody(msg, out),
        object_pb.GetRequest.Body => marshalObjectGetRequestBody(msg, out),
        object_pb.HeadRequest.Body => marshalObjectHeadRequestBody(msg, out),
        accounting_pb.BalanceRequest.Body => marshalBalanceRequestBody(msg, out),
        object_pb.PutRequest.Body => marshalObjectPutRequestBody(msg, out),
        object_pb.SearchV2Request.Body => marshalSearchV2RequestBody(msg, out),
        session_pb.SessionToken.Body => marshalSessionTokenBody(msg, out),
        session_pb.SessionTokenV2.Body => session_v2_enc.marshalSessionTokenV2Body(msg, out),
        reputation_pb.AnnounceLocalTrustRequest.Body => marshalAnnounceLocalTrustBody(msg, out),
        reputation_pb.AnnounceIntermediateResultRequest.Body => marshalAnnounceIntermediateResultBody(msg, out),
        netmap_pb.NetworkInfoRequest.Body => marshalEmpty(msg, out),
        container_pb.SetExtendedACLRequest.Body => marshalSetExtendedACLRequestBody(msg, out),
        acl_pb.EACLTable => marshalEACLTable(msg, out),
        else => @compileError("unsupported stable signing message type: " ++ @typeName(T)),
    };
}

pub fn encode(allocator: std.mem.Allocator, msg: anytype) ![]u8 {
    const sz = sizeMessage(msg);
    const out = try allocator.alloc(u8, sz);
    _ = marshalMessage(msg, out);
    return out;
}

test "default request meta header matches go stable marshal" {
    const v = @import("../../version/version.zig").current();
    const meta = session_pb.RequestMetaHeader{
        .version = .{ .major = v.major, .minor = v.minor },
        .ttl = 2,
        .epoch = 0,
    };
    const bytes = try encode(std.testing.allocator, meta);
    defer std.testing.allocator.free(bytes);
    const expected = [_]u8{ 0x0a, 0x04, 0x08, 0x02, 0x10, 0x16, 0x18, 0x02 };
    try std.testing.expectEqualSlices(u8, expected[0..], bytes);
}

test "put request body stable marshal matches stable container bytes" {
    const allocator = std.testing.allocator;
    const init = @import("../../container/init.zig");
    const stable = @import("stable.zig");
    const user = @import("../../user/id.zig");

    const owner = user.ID.fromCompressedPublicKey([_]u8{0x02} ** 33);
    const nonce = try init.randomNonce(allocator);
    defer allocator.free(nonce);
    const c = try init.newContainer(allocator, owner, nonce, "test");
    defer init.deinitContainer(allocator, c);

    const sig = refs_pb.SignatureRFC6979{ .key = "pub", .sign = "sig" };
    var body = try init.toPutRequestBody(allocator, c, sig);
    defer body.deinit(allocator);

    var stable_buf: [4096]u8 = undefined;
    const stable_size = stable.sizeContainer(c);
    _ = stable.marshalContainer(c, stable_buf[0..stable_size]);

    const container = body.container orelse return error.MissingContainer;
    const pb_size = sizeContainer(container);
    var pb_buf: [4096]u8 = undefined;
    _ = marshalContainer(container, pb_buf[0..pb_size]);

    try std.testing.expectEqual(stable_size, pb_size);
    try std.testing.expectEqualSlices(u8, stable_buf[0..stable_size], pb_buf[0..pb_size]);
}
