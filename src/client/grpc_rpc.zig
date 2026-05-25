const std = @import("std");
const request = @import("request.zig");
const signer_mod = @import("../crypto/signer.zig");
const accounting = @import("../accounting/decimal.zig");
const object_stream = @import("object_stream.zig");
const container_mod = @import("../container/container.zig");
const container_init = @import("../container/init.zig");
const object_mod = @import("../object/object.zig");
const object_put = @import("../object/put.zig");
const session_mod = @import("../session/token.zig");
const session_object = @import("../session/object_session.zig");
const stable = @import("../internal/proto/stable.zig");
const user = @import("../user/id.zig");
const failure = @import("status/failure.zig");
const grpc_transport = @import("../transport/grpc.zig");
const accounting_pb = @import("../proto/gen/accounting/types.pb.zig");
const netmap_pb = @import("../proto/gen/netmap/types.pb.zig");
const session_pb = @import("../proto/gen/session/types.pb.zig");
const container_pb = @import("../proto/gen/container/types.pb.zig");
const object_pb = @import("../proto/gen/object/types.pb.zig");
const acl_pb = @import("../proto/gen/acl/types.pb.zig");
const refs_pb = @import("../proto/gen/refs/types.pb.zig");
const reputation_pb = @import("../proto/gen/reputation/types.pb.zig");

pub fn grpcUnary(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    msg: anytype,
    path: []const u8,
    comptime ResponseType: type,
) !ResponseType {
    var w: std.Io.Writer.Allocating = .init(allocator);
    defer w.deinit();
    try msg.encode(&w.writer, allocator);
    const response_bytes = try grpc_client.unaryCall(path, w.written());
    defer allocator.free(response_bytes);
    var reader = std.Io.Reader.fixed(response_bytes);
    return ResponseType.decode(&reader, allocator);
}

pub fn networkInfo(allocator: std.mem.Allocator, grpc_client: anytype, signer_key: []const u8) !u64 {
    const req = netmap_pb.NetworkInfoRequest{
        .body = .{},
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.netmap.NetmapService/NetworkInfo", netmap_pb.NetworkInfoResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return error.InvalidResponse;
    const info = body.network_info orelse return error.InvalidResponse;
    return info.current_epoch;
}

pub fn networkInfoWithSigner(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer: signer_mod.Signer,
) !u64 {
    const req = netmap_pb.NetworkInfoRequest{
        .body = .{},
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessageWithSigner(allocator, signer, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.netmap.NetmapService/NetworkInfo", netmap_pb.NetworkInfoResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return error.InvalidResponse;
    const info = body.network_info orelse return error.InvalidResponse;
    return info.current_epoch;
}

pub fn sessionCreate(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer_key: []const u8,
    owner: user.ID,
    exp_epoch: u64,
) !session_object.CreateResult {
    const req = session_pb.CreateRequest{
        .body = .{
            .owner_id = .{ .value = try allocator.dupe(u8, &owner.bytes) },
            .expiration = exp_epoch,
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.session.SessionService/Create", session_pb.CreateResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return error.InvalidResponse;
    return try session_object.parseCreateResponse(allocator, body);
}

pub fn sessionCreateWithSigner(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer: signer_mod.Signer,
    owner: user.ID,
    exp_epoch: u64,
) !session_object.CreateResult {
    const req = session_pb.CreateRequest{
        .body = .{
            .owner_id = .{ .value = try allocator.dupe(u8, &owner.bytes) },
            .expiration = exp_epoch,
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessageWithSigner(allocator, signer, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.session.SessionService/Create", session_pb.CreateResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return error.InvalidResponse;
    return try session_object.parseCreateResponse(allocator, body);
}

pub fn balanceGet(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer_key: []const u8,
    owner: user.ID,
) !accounting.Decimal {
    const req = accounting_pb.BalanceRequest{
        .body = .{
            .owner_id = .{ .value = try allocator.dupe(u8, &owner.bytes) },
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.accounting.AccountingService/Balance", accounting_pb.BalanceResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return error.InvalidResponse;
    const balance = body.balance orelse return error.InvalidResponse;
    if (balance.value < 0) return error.InvalidResponse;
    return accounting.Decimal.fromProto(balance.value, balance.precision);
}

/// Balance for any owner using a local transport signer (not the account owner).
pub fn balanceGetForOwner(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    owner: user.ID,
) !accounting.Decimal {
    var transport_signer = signer_mod.LocalSigner{ .secret = "neofs-sdk-zig-transport-signer" };
    return balanceGetWithSigner(allocator, grpc_client, transport_signer.asSigner(), owner);
}

pub fn balanceGetWithSigner(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer: signer_mod.Signer,
    owner: user.ID,
) !accounting.Decimal {
    const req = accounting_pb.BalanceRequest{
        .body = .{
            .owner_id = .{ .value = try allocator.dupe(u8, &owner.bytes) },
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessageWithSigner(allocator, signer, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.accounting.AccountingService/Balance", accounting_pb.BalanceResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return error.InvalidResponse;
    const balance = body.balance orelse return error.InvalidResponse;
    if (balance.value < 0) return error.InvalidResponse;
    return accounting.Decimal.fromProto(balance.value, balance.precision);
}

pub fn containerPut(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer_key: []const u8,
    container: stable.Container,
) ![32]u8 {
    const container_sig = try container_init.signContainer(allocator, signer_key, container);
    const body = try container_init.toPutRequestBody(allocator, container, container_sig);
    const req = container_pb.PutRequest{
        .body = body,
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.container.ContainerService/Put", container_pb.PutResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const resp_body = resp.body orelse return error.InvalidResponse;
    const cid = resp_body.container_id orelse return error.InvalidResponse;
    if (cid.value.len < 32) return error.InvalidResponse;
    var out: [32]u8 = undefined;
    @memcpy(&out, cid.value[0..32]);
    return out;
}

pub fn containerPutWithSigner(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer: signer_mod.Signer,
    container: stable.Container,
    container_sig: refs_pb.SignatureRFC6979,
) ![32]u8 {
    return containerPutWithSessionV2(allocator, grpc_client, signer, container, container_sig, null);
}

pub fn containerPutWithSessionV2(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer: signer_mod.Signer,
    container: stable.Container,
    container_sig: refs_pb.SignatureRFC6979,
    session_token_v2: ?session_pb.SessionTokenV2,
) ![32]u8 {
    const body = try container_init.toPutRequestBody(allocator, container, container_sig);
    var meta = try request.defaultMetaHeader(allocator);
    if (session_token_v2) |tok| {
        meta.session_token_v2 = try tok.dupe(allocator);
    }
    const req = container_pb.PutRequest{
        .body = body,
        .meta_header = meta,
    };
    var signed = try request.signRequestMessageWithSigner(allocator, signer, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.container.ContainerService/Put", container_pb.PutResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const resp_body = resp.body orelse return error.InvalidResponse;
    const cid = resp_body.container_id orelse return error.InvalidResponse;
    if (cid.value.len < 32) return error.InvalidResponse;
    var out: [32]u8 = undefined;
    @memcpy(&out, cid.value[0..32]);
    return out;
}

pub fn containerGet(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer_key: []const u8,
    id: [32]u8,
) !container_mod.Container {
    const req = container_pb.GetRequest{
        .body = .{ .container_id = try request.makeContainerID(allocator, id) },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.container.ContainerService/Get", container_pb.GetResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return error.InvalidResponse;
    const cont = body.container orelse return error.InvalidResponse;
    const owner = cont.owner_id orelse return error.InvalidResponse;
    var out = try container_mod.Container.init(allocator, owner.value, cont.nonce);
    errdefer out.deinit();
    for (cont.attributes.items) |attr| {
        try out.putAttribute(attr.key, attr.value);
    }
    return out;
}

pub fn containerGetWithSigner(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer: signer_mod.Signer,
    id: [32]u8,
) !container_mod.Container {
    const req = container_pb.GetRequest{
        .body = .{ .container_id = try request.makeContainerID(allocator, id) },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessageWithSigner(allocator, signer, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.container.ContainerService/Get", container_pb.GetResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return error.InvalidResponse;
    const cont = body.container orelse return error.InvalidResponse;
    const owner = cont.owner_id orelse return error.InvalidResponse;
    var out = try container_mod.Container.init(allocator, owner.value, cont.nonce);
    errdefer out.deinit();
    for (cont.attributes.items) |attr| {
        try out.putAttribute(attr.key, attr.value);
    }
    return out;
}

pub fn containerList(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer_key: []const u8,
    owner: user.ID,
) ![][32]u8 {
    const req = container_pb.ListRequest{
        .body = .{ .owner_id = .{ .value = try allocator.dupe(u8, &owner.bytes) } },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.container.ContainerService/List", container_pb.ListResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    var out: std.ArrayList([32]u8) = .{};
    if (resp.body) |body| {
        for (body.container_ids.items) |cid| {
            if (cid.value.len >= 32) {
                var cid_bytes: [32]u8 = undefined;
                @memcpy(&cid_bytes, cid.value[0..32]);
                try out.append(allocator, cid_bytes);
            }
        }
    }
    return out.toOwnedSlice(allocator);
}

pub fn containerListWithSigner(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer: signer_mod.Signer,
    owner: user.ID,
) ![][32]u8 {
    const req = container_pb.ListRequest{
        .body = .{ .owner_id = .{ .value = try allocator.dupe(u8, &owner.bytes) } },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessageWithSigner(allocator, signer, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.container.ContainerService/List", container_pb.ListResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    var out: std.ArrayList([32]u8) = .{};
    if (resp.body) |body| {
        for (body.container_ids.items) |cid| {
            if (cid.value.len >= 32) {
                var cid_bytes: [32]u8 = undefined;
                @memcpy(&cid_bytes, cid.value[0..32]);
                try out.append(allocator, cid_bytes);
            }
        }
    }
    return out.toOwnedSlice(allocator);
}

pub fn containerDelete(allocator: std.mem.Allocator, grpc_client: anytype, signer_key: []const u8, id: [32]u8) !void {
    const container_sig = try container_init.signContainerID(allocator, signer_key, id);
    const req = container_pb.DeleteRequest{
        .body = .{
            .container_id = try request.makeContainerID(allocator, id),
            .signature = container_sig,
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.container.ContainerService/Delete", container_pb.DeleteResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
}

pub fn containerDeleteWithSigner(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer: signer_mod.Signer,
    id: [32]u8,
    container_sig: refs_pb.SignatureRFC6979,
) !void {
    const req = container_pb.DeleteRequest{
        .body = .{
            .container_id = try request.makeContainerID(allocator, id),
            .signature = container_sig,
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessageWithSigner(allocator, signer, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.container.ContainerService/Delete", container_pb.DeleteResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
}

pub fn containerEaclGet(allocator: std.mem.Allocator, grpc_client: anytype, id: [32]u8) ![]u8 {
    var req = container_pb.GetExtendedACLRequest{
        .body = .{ .container_id = try request.makeContainerID(allocator, id) },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    defer req.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, req, "/neo.fs.v2.container.ContainerService/GetExtendedACL", container_pb.GetExtendedACLResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return try allocator.dupe(u8, "");
    const eacl = body.eacl orelse return try allocator.dupe(u8, "");
    return try request.encodeMessage(allocator, eacl);
}

pub fn containerEaclSet(allocator: std.mem.Allocator, grpc_client: anytype, signer_key: []const u8, id: [32]u8, eacl_bin: []const u8) !void {
    var table: acl_pb.EACLTable = if (eacl_bin.len == 0) .{} else blk: {
        var reader = std.Io.Reader.fixed(eacl_bin);
        break :blk try acl_pb.EACLTable.decode(&reader, allocator);
    };
    if (table.container_id) |*existing| existing.deinit(allocator);
    table.container_id = try request.makeContainerID(allocator, id);

    const req = container_pb.SetExtendedACLRequest{
        .body = .{
            .eacl = table,
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.container.ContainerService/SetExtendedACL", container_pb.SetExtendedACLResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
}

pub fn containerEaclSetWithSigner(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer: signer_mod.Signer,
    id: [32]u8,
    eacl_bin: []const u8,
) !void {
    var table: acl_pb.EACLTable = if (eacl_bin.len == 0) .{} else blk: {
        var reader = std.Io.Reader.fixed(eacl_bin);
        break :blk try acl_pb.EACLTable.decode(&reader, allocator);
    };
    if (table.container_id) |*existing| existing.deinit(allocator);
    table.container_id = try request.makeContainerID(allocator, id);

    const req = container_pb.SetExtendedACLRequest{
        .body = .{
            .eacl = table,
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessageWithSigner(allocator, signer, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.container.ContainerService/SetExtendedACL", container_pb.SetExtendedACLResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
}

pub fn setContainerAttribute(allocator: std.mem.Allocator, grpc_client: anytype, id: [32]u8, attr_key: []const u8, value: []const u8) !void {
    var req = container_pb.SetAttributeRequest{
        .body = .{
            .parameters = .{
                .container_id = try request.makeContainerID(allocator, id),
                .attribute = try allocator.dupe(u8, attr_key),
                .value = try allocator.dupe(u8, value),
                .valid_until = @intCast(std.time.timestamp() + 3600),
            },
        },
    };
    defer req.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, req, "/neo.fs.v2.container.ContainerService/SetAttribute", container_pb.SetAttributeResponse);
    defer resp.deinit(allocator);
}

pub fn removeContainerAttribute(allocator: std.mem.Allocator, grpc_client: anytype, id: [32]u8, attr_key: []const u8) !void {
    var req = container_pb.RemoveAttributeRequest{
        .body = .{
            .parameters = .{
                .container_id = try request.makeContainerID(allocator, id),
                .attribute = try allocator.dupe(u8, attr_key),
                .valid_until = @intCast(std.time.timestamp() + 3600),
            },
        },
    };
    defer req.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, req, "/neo.fs.v2.container.ContainerService/RemoveAttribute", container_pb.RemoveAttributeResponse);
    defer resp.deinit(allocator);
}

pub fn objectHead(allocator: std.mem.Allocator, grpc_client: anytype, container_id: [32]u8, object_id: [32]u8) !object_mod.Object {
    var req = object_pb.HeadRequest{
        .body = .{
            .address = try request.makeAddress(allocator, container_id, object_id),
            .raw = true,
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    defer req.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, req, "/neo.fs.v2.object.ObjectService/Head", object_pb.HeadResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return error.InvalidResponse;
    const head = body.head orelse return error.InvalidResponse;
    return switch (head) {
        .header => |h| blk: {
            const hdr = h.header orelse return error.InvalidResponse;
            const owner = hdr.owner_id orelse return error.InvalidResponse;
            break :blk .{
                .container_id = container_id,
                .owner = owner.value,
                .payload = "",
                .payload_checksum = null,
            };
        },
        else => error.InvalidResponse,
    };
}

pub fn objectHeadWithSessionV2(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer_key: []const u8,
    container_id: [32]u8,
    object_id: [32]u8,
    session_token_v2: session_pb.SessionTokenV2,
) !object_mod.Object {
    var req = object_pb.HeadRequest{
        .body = .{
            .address = try request.makeAddress(allocator, container_id, object_id),
            .raw = true,
        },
        .meta_header = blk: {
            var meta = try request.defaultMetaHeader(allocator);
            meta.session_token_v2 = try session_token_v2.dupe(allocator);
            break :blk meta;
        },
    };
    defer req.deinit(allocator);
    var local_signer = signer_mod.LocalSigner{ .secret = signer_key };
    var signed = try request.signRequestMessageWithSigner(allocator, local_signer.asSigner(), req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.object.ObjectService/Head", object_pb.HeadResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return error.InvalidResponse;
    const head = body.head orelse return error.InvalidResponse;
    return switch (head) {
        .header => |h| blk: {
            const hdr = h.header orelse return error.InvalidResponse;
            const owner = hdr.owner_id orelse return error.InvalidResponse;
            break :blk .{
                .container_id = container_id,
                .owner = owner.value,
                .payload = "",
                .payload_checksum = null,
            };
        },
        else => error.InvalidResponse,
    };
}

pub fn objectDelete(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer_key: []const u8,
    owner: user.ID,
    container_id: [32]u8,
    object_id: [32]u8,
    session_token: session_pb.SessionToken,
) !void {
    _ = owner;
    const req = object_pb.DeleteRequest{
        .body = .{
            .address = try request.makeAddress(allocator, container_id, object_id),
        },
        .meta_header = blk: {
            var meta = try request.defaultMetaHeader(allocator);
            meta.session_token = try session_token.dupe(allocator);
            break :blk meta;
        },
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.object.ObjectService/Delete", object_pb.DeleteResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
}

pub fn objectDeleteWithSessionV2(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer_key: []const u8,
    owner: user.ID,
    container_id: [32]u8,
    object_id: [32]u8,
    session_token_v2: session_pb.SessionTokenV2,
) !void {
    _ = owner;
    const req = object_pb.DeleteRequest{
        .body = .{
            .address = try request.makeAddress(allocator, container_id, object_id),
        },
        .meta_header = blk: {
            var meta = try request.defaultMetaHeader(allocator);
            meta.session_token_v2 = try session_token_v2.dupe(allocator);
            break :blk meta;
        },
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.object.ObjectService/Delete", object_pb.DeleteResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
}

pub fn buildObjectPutRequest(
    allocator: std.mem.Allocator,
    signer_key: []const u8,
    prepared: object_put.PreparedObject,
    session_token: session_pb.SessionToken,
) !object_pb.PutRequest {
    const req = object_pb.PutRequest{
        .body = .{
            .object_part = .{
                .init = .{
                    .object_id = .{ .value = try allocator.dupe(u8, &prepared.object_id) },
                    .signature = prepared.object_signature,
                    .header = prepared.header,
                },
            },
        },
        .meta_header = blk: {
            var meta = try request.defaultMetaHeader(allocator);
            meta.session_token = try session_token.dupe(allocator);
            break :blk meta;
        },
    };
    return try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
}

pub fn buildObjectPutRequestWithSessionV2(
    allocator: std.mem.Allocator,
    signer_key: []const u8,
    prepared: object_put.PreparedObject,
    session_token_v2: session_pb.SessionTokenV2,
) !object_pb.PutRequest {
    const req = object_pb.PutRequest{
        .body = .{
            .object_part = .{
                .init = .{
                    .object_id = .{ .value = try allocator.dupe(u8, &prepared.object_id) },
                    .signature = prepared.object_signature,
                    .header = prepared.header,
                },
            },
        },
        .meta_header = blk: {
            var meta = try request.defaultMetaHeader(allocator);
            meta.session_token_v2 = try session_token_v2.dupe(allocator);
            break :blk meta;
        },
    };
    return try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
}

pub fn objectHash(allocator: std.mem.Allocator, grpc_client: anytype, container_id: [32]u8, object_id: [32]u8) ![32]u8 {
    var req = object_pb.GetRangeHashRequest{
        .body = .{
            .address = try request.makeAddress(allocator, container_id, object_id),
            .ranges = .{},
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    defer req.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, req, "/neo.fs.v2.object.ObjectService/GetRangeHash", object_pb.GetRangeHashResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const body = resp.body orelse return error.InvalidResponse;
    if (body.hash_list.items.len == 0) return error.InvalidResponse;
    const h = body.hash_list.items[0];
    if (h.len < 32) return error.InvalidResponse;
    var out: [32]u8 = undefined;
    @memcpy(&out, h[0..32]);
    return out;
}

pub fn searchObjects(allocator: std.mem.Allocator, grpc_client: anytype, container_id: [32]u8) ![][32]u8 {
    var reader = try object_stream.objectSearchInit(allocator, grpc_client, container_id);
    defer reader.deinit();
    var out: std.ArrayList([32]u8) = .{};
    while (try reader.nextObjectID()) |id| {
        try out.append(allocator, id);
    }
    return out.toOwnedSlice(allocator);
}

pub fn searchObjectsV2(allocator: std.mem.Allocator, grpc_client: anytype, container_id: [32]u8) ![][32]u8 {
    const entries = try searchObjectsDetailed(allocator, grpc_client, container_id, &.{ "Name", "FileName" });
    defer deinitSearchObjectEntries(allocator, entries);
    var out: std.ArrayList([32]u8) = .{};
    for (entries) |entry| {
        try out.append(allocator, entry.id);
    }
    return out.toOwnedSlice(allocator);
}

pub const SearchObjectEntry = struct {
    id: [32]u8,
    attribute_values: []const []const u8,
};

pub fn deinitSearchObjectEntries(allocator: std.mem.Allocator, entries: []SearchObjectEntry) void {
    for (entries) |entry| {
        for (entry.attribute_values) |value| allocator.free(value);
        allocator.free(entry.attribute_values);
    }
    allocator.free(entries);
}

pub fn searchObjectsDetailed(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    container_id: [32]u8,
    attribute_names: []const []const u8,
) ![]SearchObjectEntry {
    var body = object_pb.SearchV2Request.Body{
        .container_id = .{ .value = try allocator.dupe(u8, &container_id) },
        .attributes = .{},
    };
    errdefer body.deinit(allocator);
    for (attribute_names) |name| {
        try body.attributes.append(allocator, try allocator.dupe(u8, name));
    }

    var req = object_pb.SearchV2Request{
        .body = body,
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    defer req.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, req, "/neo.fs.v2.object.ObjectService/SearchV2", object_pb.SearchV2Response);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const resp_body = resp.body orelse return error.InvalidResponse;

    var out: std.ArrayList(SearchObjectEntry) = .{};
    errdefer {
        for (out.items) |entry| {
            for (entry.attribute_values) |value| allocator.free(value);
            allocator.free(entry.attribute_values);
        }
        out.deinit(allocator);
    }

    for (resp_body.result.items) |item| {
        const oid = item.id orelse continue;
        if (oid.value.len < 32) continue;
        var id: [32]u8 = undefined;
        @memcpy(&id, oid.value[0..32]);

        var values: std.ArrayList([]const u8) = .{};
        errdefer {
            for (values.items) |value| allocator.free(value);
            values.deinit(allocator);
        }
        for (item.attributes.items) |value| {
            try values.append(allocator, try allocator.dupe(u8, value));
        }
        try out.append(allocator, .{
            .id = id,
            .attribute_values = try values.toOwnedSlice(allocator),
        });
    }
    return out.toOwnedSlice(allocator);
}

pub fn searchObjectsDetailedWithSessionV2(
    allocator: std.mem.Allocator,
    grpc_client: anytype,
    signer_key: []const u8,
    container_id: [32]u8,
    attribute_names: []const []const u8,
    session_token_v2: session_pb.SessionTokenV2,
) ![]SearchObjectEntry {
    // Build the request inline so its body is owned by the (single) `signed`
    // struct that we deinit on exit. Earlier code kept a separate `body`
    // value with its own errdefer, which aliased the same container_id.value
    // pointer that lives inside `signed.body` and caused a double-free.
    var req = object_pb.SearchV2Request{
        .body = .{
            .container_id = .{ .value = try allocator.dupe(u8, &container_id) },
            // NeoFS SearchV2 requires query-language version >= 1; version 0
            // (default) is rejected with status 1024 "unsupported query version".
            .version = 1,
            // Server rejects count=0 with "zero count". 1000 is the documented
            // max page size for SearchV2.
            .count = 1000,
            .attributes = .{},
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    errdefer req.deinit(allocator);
    for (attribute_names) |name| {
        try req.body.?.attributes.append(allocator, try allocator.dupe(u8, name));
    }
    req.meta_header.?.session_token_v2 = try session_token_v2.dupe(allocator);

    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    // signed now owns everything that was in req; suppress the errdefer.
    req = .{};
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.object.ObjectService/SearchV2", object_pb.SearchV2Response);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
    const resp_body = resp.body orelse return error.InvalidResponse;

    var out: std.ArrayList(SearchObjectEntry) = .{};
    errdefer {
        for (out.items) |entry| {
            for (entry.attribute_values) |value| allocator.free(value);
            allocator.free(entry.attribute_values);
        }
        out.deinit(allocator);
    }

    for (resp_body.result.items) |item| {
        const oid = item.id orelse continue;
        if (oid.value.len < 32) continue;
        var id: [32]u8 = undefined;
        @memcpy(&id, oid.value[0..32]);

        var values: std.ArrayList([]const u8) = .{};
        errdefer {
            for (values.items) |value| allocator.free(value);
            values.deinit(allocator);
        }
        for (item.attributes.items) |value| {
            try values.append(allocator, try allocator.dupe(u8, value));
        }
        try out.append(allocator, .{
            .id = id,
            .attribute_values = try values.toOwnedSlice(allocator),
        });
    }
    return out.toOwnedSlice(allocator);
}

pub fn announceLocalTrust(allocator: std.mem.Allocator, grpc_client: anytype, signer_key: []const u8, epoch: u64) !void {
    const req = reputation_pb.AnnounceLocalTrustRequest{
        .body = .{ .epoch = epoch, .trusts = .{} },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(allocator, grpc_client, signed, "/neo.fs.v2.reputation.ReputationService/AnnounceLocalTrust", reputation_pb.AnnounceLocalTrustResponse);
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
}

pub fn announceIntermediateTrust(allocator: std.mem.Allocator, grpc_client: anytype, signer_key: []const u8, epoch: u64) !void {
    const req = reputation_pb.AnnounceIntermediateResultRequest{
        .body = .{ .epoch = epoch, .iteration = 0 },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    var signed = try request.signRequestMessage(allocator, signer_key, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var resp = try grpcUnary(
        allocator,
        grpc_client,
        signed,
        "/neo.fs.v2.reputation.ReputationService/AnnounceIntermediateResult",
        reputation_pb.AnnounceIntermediateResultResponse,
    );
    defer resp.deinit(allocator);
    try failure.validate(allocator, resp.meta_header);
}
