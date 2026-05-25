const std = @import("std");
const version = @import("../version/version.zig");
const checksum = @import("../checksum/checksum.zig");
const accounting = @import("../accounting/decimal.zig");
const object = @import("../object/object.zig");
const container = @import("../container/container.zig");
const session = @import("../session/token.zig");
const session_v2 = @import("../session/v2/token.zig");
const signer = @import("../crypto/signature.zig");
const status = @import("status/errors.zig");
const status_failure = @import("status/failure.zig");
const accounting_pb = @import("../proto/gen/accounting/types.pb.zig");
const netmap_pb = @import("../proto/gen/netmap/types.pb.zig");
const session_pb = @import("../proto/gen/session/types.pb.zig");
const grpc_transport = @import("../transport/grpc.zig");
const object_stream = @import("object_stream.zig");
const grpc_rpc = @import("grpc_rpc.zig");
const stable = @import("../internal/proto/stable.zig");
const signer_mod = @import("../crypto/signer.zig");
const refs_pb = @import("../proto/gen/refs/types.pb.zig");

pub const SearchObjectEntry = grpc_rpc.SearchObjectEntry;
const container_init = @import("../container/init.zig");
const session_object = @import("../session/object_session.zig");
const object_put = @import("../object/put.zig");
const user = @import("../user/id.zig");

pub const TransportMode = enum {
    memory,
    grpc,
};

pub const Transport = struct {
    endpoint: []const u8,
    tls: bool,
    timeout_ms: u64,
    mode: TransportMode = .memory,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    transport: ?Transport = null,
    grpc: ?*grpc_transport.Client = null,
    containers: std.ArrayList(ContainerRecord),
    objects: std.ArrayList(ObjectRecord),
    replications: std.ArrayList([32]u8),
    trust_announcements: usize = 0,
    signer_key: ?[]const u8 = null,
    session_v2_cache: std.StringHashMap(session_pb.SessionTokenV2),

    const ContainerRecord = struct {
        id: [32]u8,
        owner: []u8,
        nonce: []u8,
        attributes: std.StringHashMap([]u8),
        eacl_bin: []u8,
    };

    const ObjectRecord = struct {
        id: [32]u8,
        container_id: [32]u8,
        owner: []u8,
        payload: []u8,
    };

    pub fn init(allocator: std.mem.Allocator) Client {
        return .{
            .allocator = allocator,
            .containers = .{},
            .objects = .{},
            .replications = .{},
            .session_v2_cache = std.StringHashMap(session_pb.SessionTokenV2).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        for (self.containers.items) |*rec| {
            var it = rec.attributes.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            rec.attributes.deinit();
            self.allocator.free(rec.owner);
            self.allocator.free(rec.nonce);
            self.allocator.free(rec.eacl_bin);
        }
        self.containers.deinit(self.allocator);

        for (self.objects.items) |rec| {
            self.allocator.free(rec.owner);
            self.allocator.free(rec.payload);
        }
        self.objects.deinit(self.allocator);
        self.replications.deinit(self.allocator);
        var tok_it = self.session_v2_cache.iterator();
        while (tok_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var tok = entry.value_ptr.*;
            tok.deinit(self.allocator);
        }
        self.session_v2_cache.deinit();
        if (self.grpc) |g| {
            g.deinit();
            self.allocator.destroy(g);
            self.grpc = null;
        }
    }

    pub fn dial(self: *Client, endpoint: []const u8, tls: bool, timeout_ms: u64) !void {
        self.transport = .{
            .endpoint = endpoint,
            .tls = tls,
            .timeout_ms = timeout_ms,
            .mode = transportMode(endpoint),
        };
        if (self.transport.?.mode == .grpc) {
            const host_port = endpointTarget(endpoint);
            var host_buf: [256]u8 = undefined;
            const host = try parseHostPort(host_port, &host_buf);
            const port = try parsePort(host_port);
            const grpc_client = try self.allocator.create(grpc_transport.Client);
            errdefer self.allocator.destroy(grpc_client);
            grpc_client.* = try grpc_transport.Client.connect(self.allocator, host, port, tls);
            self.grpc = grpc_client;
        }
    }

    pub fn setSignerKey(self: *Client, key: []const u8) void {
        self.signer_key = key;
    }

    pub fn signerKey(self: *Client) ?[]const u8 {
        return self.signer_key;
    }

    pub fn isGrpc(self: *Client) bool {
        return self.transport != null and self.transport.?.mode == .grpc;
    }

    pub fn close(self: *Client) void {
        if (self.grpc) |g| {
            g.deinit();
            self.allocator.destroy(g);
            self.grpc = null;
        }
        self.transport = null;
    }

    pub fn endpointInfo(self: *Client) ![]const u8 {
        if (self.transport == null) return error.NotConnected;
        if (self.transport.?.mode == .grpc) {
            const req = netmap_pb.LocalNodeInfoRequest{};
            var resp = try self.grpcUnary(req, "/neo.fs.v2.netmap.NetmapService/LocalNodeInfo", netmap_pb.LocalNodeInfoResponse);
            defer resp.deinit(self.allocator);
            try status_failure.validate(self.allocator, resp.meta_header);
        }
        return self.transport.?.endpoint;
    }

    pub fn networkInfo(self: *Client) !u64 {
        if (self.transport == null) return error.NotConnected;
        if (self.isGrpc()) {
            const key = self.signer_key orelse return error.MissingSigner;
            return grpc_rpc.networkInfo(self.allocator, self.grpc.?, key);
        }
        return version.current().minor;
    }

    pub fn sessionCreate(self: *Client, owner: user.ID, exp_epoch: u64) !session_object.CreateResult {
        if (self.isGrpc()) {
            const key = self.signer_key orelse return error.MissingSigner;
            return grpc_rpc.sessionCreate(self.allocator, self.grpc.?, key, owner, exp_epoch);
        }
        var id: [16]u8 = undefined;
        std.crypto.random.bytes(&id);
        return .{
            .id = id,
            .session_key = try self.allocator.dupe(u8, &[_]u8{}),
        };
    }

    pub fn networkInfoWithSigner(self: *Client, request_signer: signer_mod.Signer) !u64 {
        if (!self.isGrpc()) return error.NotConnected;
        return grpc_rpc.networkInfoWithSigner(self.allocator, self.grpc.?, request_signer);
    }

    pub fn sessionCreateWithSigner(self: *Client, owner: user.ID, exp_epoch: u64, request_signer: signer_mod.Signer) !session_object.CreateResult {
        if (!self.isGrpc()) return error.NotConnected;
        return grpc_rpc.sessionCreateWithSigner(self.allocator, self.grpc.?, request_signer, owner, exp_epoch);
    }

    pub fn putContainerWithSigner(
        self: *Client,
        request_signer: signer_mod.Signer,
        cont: stable.Container,
        container_sig: refs_pb.SignatureRFC6979,
    ) ![32]u8 {
        if (!self.isGrpc()) return error.NotConnected;
        return grpc_rpc.containerPutWithSigner(self.allocator, self.grpc.?, request_signer, cont, container_sig);
    }

    pub fn putContainerWithSessionV2(
        self: *Client,
        request_signer: signer_mod.Signer,
        cont: stable.Container,
        container_sig: refs_pb.SignatureRFC6979,
        session_token_v2: session_pb.SessionTokenV2,
    ) ![32]u8 {
        if (!self.isGrpc()) return error.NotConnected;
        return grpc_rpc.containerPutWithSessionV2(
            self.allocator,
            self.grpc.?,
            request_signer,
            cont,
            container_sig,
            session_token_v2,
        );
    }

    pub fn containerGetWithSigner(self: *Client, request_signer: signer_mod.Signer, id: [32]u8) !container.Container {
        if (!self.isGrpc()) return error.NotConnected;
        return grpc_rpc.containerGetWithSigner(self.allocator, self.grpc.?, request_signer, id);
    }

    pub fn containerListWithSigner(self: *Client, request_signer: signer_mod.Signer, owner: user.ID) ![][32]u8 {
        if (!self.isGrpc()) return error.NotConnected;
        return grpc_rpc.containerListWithSigner(self.allocator, self.grpc.?, request_signer, owner);
    }

    pub fn containerDeleteWithSigner(
        self: *Client,
        request_signer: signer_mod.Signer,
        id: [32]u8,
        container_sig: refs_pb.SignatureRFC6979,
    ) !void {
        if (!self.isGrpc()) return error.NotConnected;
        return grpc_rpc.containerDeleteWithSigner(self.allocator, self.grpc.?, request_signer, id, container_sig);
    }

    pub fn containerEaclSetWithSigner(self: *Client, request_signer: signer_mod.Signer, id: [32]u8, eacl_bin: []const u8) !void {
        if (!self.isGrpc()) return error.NotConnected;
        return grpc_rpc.containerEaclSetWithSigner(self.allocator, self.grpc.?, request_signer, id, eacl_bin);
    }

    pub fn balanceGetWithSigner(self: *Client, request_signer: signer_mod.Signer, owner: user.ID) !accounting.Decimal {
        if (!self.isGrpc()) return error.NotConnected;
        return grpc_rpc.balanceGetWithSigner(self.allocator, self.grpc.?, request_signer, owner);
    }

    /// Read balance for `owner` using a local transport signature (no owner key required).
    pub fn balanceGetForOwner(self: *Client, owner: user.ID) !accounting.Decimal {
        if (!self.isGrpc()) return error.NotConnected;
        return grpc_rpc.balanceGetForOwner(self.allocator, self.grpc.?, owner);
    }

    pub fn putContainer(self: *Client, cont: stable.Container) ![32]u8 {
        if (self.isGrpc()) {
            const key = self.signer_key orelse return error.MissingSigner;
            return grpc_rpc.containerPut(self.allocator, self.grpc.?, key, cont);
        }
        try self.requireMemoryBackend();
        var tmp = try container.Container.init(self.allocator, "", "");
        defer tmp.deinit();
        return self.containerPut(tmp);
    }

    pub fn containerPut(self: *Client, c: container.Container) ![32]u8 {
        if (self.isGrpc()) {
            const key = self.signer_key orelse return error.MissingSigner;
            var attrs: std.ArrayList(stable.ContainerAttribute) = .{};
            defer attrs.deinit(self.allocator);

            var it = c.attributes.iterator();
            while (it.next()) |entry| {
                try attrs.append(self.allocator, .{
                    .key = entry.key_ptr.*,
                    .value = entry.value_ptr.*,
                });
            }

            const v = version.current();
            const replicas = [_]stable.Replica{.{ .count = 1, .selector = "" }};
            const cont: stable.Container = .{
                .version = .{ .major = v.major, .minor = v.minor },
                .owner_id = .{ .value = c.owner },
                .nonce = c.nonce,
                .basic_acl = container_init.public_rw_acl,
                .attributes = attrs.items,
                .placement_policy = .{
                    .replicas = replicas[0..],
                    .backup_factor = 1,
                },
            };
            return grpc_rpc.containerPut(self.allocator, self.grpc.?, key, cont);
        }
        try self.requireMemoryBackend();
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(c.nonce, &h, .{});
        var attrs = std.StringHashMap([]u8).init(self.allocator);
        var it = c.attributes.iterator();
        while (it.next()) |entry| {
            try attrs.put(
                try self.allocator.dupe(u8, entry.key_ptr.*),
                try self.allocator.dupe(u8, entry.value_ptr.*),
            );
        }
        try self.containers.append(self.allocator, .{
            .id = h,
            .owner = try self.allocator.dupe(u8, c.owner),
            .nonce = try self.allocator.dupe(u8, c.nonce),
            .attributes = attrs,
            .eacl_bin = try self.allocator.dupe(u8, &[_]u8{}),
        });
        return h;
    }

    pub fn containerGet(self: *Client, id: [32]u8) !container.Container {
        if (self.isGrpc()) {
            const key = self.signer_key orelse return error.MissingSigner;
            return grpc_rpc.containerGet(self.allocator, self.grpc.?, key, id);
        }
        try self.requireMemoryBackend();
        const rec = self.findContainer(id) orelse return error.ContainerNotFound;
        var out = try container.Container.init(self.allocator, rec.owner, rec.nonce);
        errdefer out.deinit();
        var it = rec.attributes.iterator();
        while (it.next()) |entry| {
            try out.putAttribute(entry.key_ptr.*, entry.value_ptr.*);
        }
        return out;
    }

    pub fn containerList(self: *Client, owner: user.ID) ![][32]u8 {
        if (self.isGrpc()) {
            const key = self.signer_key orelse return error.MissingSigner;
            return grpc_rpc.containerList(self.allocator, self.grpc.?, key, owner);
        }
        try self.requireMemoryBackend();
        var out: std.ArrayList([32]u8) = .{};
        for (self.containers.items) |rec| {
            if (rec.owner.len == user.IDSize and std.mem.eql(u8, rec.owner, &owner.bytes)) {
                try out.append(self.allocator, rec.id);
            }
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn containerDelete(self: *Client, id: [32]u8) !void {
        if (self.isGrpc()) {
            const key = self.signer_key orelse return error.MissingSigner;
            return grpc_rpc.containerDelete(self.allocator, self.grpc.?, key, id);
        }
        try self.requireMemoryBackend();
        const idx = self.findContainerIndex(id) orelse return error.ContainerNotFound;
        var rec = self.containers.orderedRemove(idx);
        var it = rec.attributes.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        rec.attributes.deinit();
        self.allocator.free(rec.owner);
        self.allocator.free(rec.nonce);
        self.allocator.free(rec.eacl_bin);
    }

    pub fn containerEaclGet(self: *Client, id: [32]u8) ![]const u8 {
        if (self.isGrpc()) {
            const bin = try grpc_rpc.containerEaclGet(self.allocator, self.grpc.?, id);
            return bin;
        }
        try self.requireMemoryBackend();
        const rec = self.findContainer(id) orelse return error.ContainerNotFound;
        return rec.eacl_bin;
    }

    pub fn containerEaclSet(self: *Client, id: [32]u8, eacl_bin: []const u8) !void {
        if (self.isGrpc()) {
            const key = self.signer_key orelse return error.MissingSigner;
            return grpc_rpc.containerEaclSet(self.allocator, self.grpc.?, key, id, eacl_bin);
        }
        try self.requireMemoryBackend();
        const idx = self.findContainerIndex(id) orelse return error.ContainerNotFound;
        self.allocator.free(self.containers.items[idx].eacl_bin);
        self.containers.items[idx].eacl_bin = try self.allocator.dupe(u8, eacl_bin);
    }

    pub fn setContainerAttribute(self: *Client, id: [32]u8, key: []const u8, value: []const u8) !void {
        if (self.isGrpc()) return grpc_rpc.setContainerAttribute(self.allocator, self.grpc.?, id, key, value);
        try self.requireMemoryBackend();
        const idx = self.findContainerIndex(id) orelse return error.ContainerNotFound;
        const rec = &self.containers.items[idx];
        if (rec.attributes.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }
        try rec.attributes.put(
            try self.allocator.dupe(u8, key),
            try self.allocator.dupe(u8, value),
        );
    }

    pub fn removeContainerAttribute(self: *Client, id: [32]u8, key: []const u8) !void {
        if (self.isGrpc()) return grpc_rpc.removeContainerAttribute(self.allocator, self.grpc.?, id, key);
        try self.requireMemoryBackend();
        const idx = self.findContainerIndex(id) orelse return error.ContainerNotFound;
        const rec = &self.containers.items[idx];
        if (rec.attributes.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }
    }

    pub fn objectPut(self: *Client, obj: object.Object) ![32]u8 {
        try self.requireMemoryBackend();
        const id = object.calcID(obj);
        try self.objects.append(self.allocator, .{
            .id = id,
            .container_id = obj.container_id,
            .owner = try self.allocator.dupe(u8, obj.owner),
            .payload = try self.allocator.dupe(u8, obj.payload),
        });
        return id;
    }

    pub fn objectGet(self: *Client, id: [32]u8) !object.Object {
        try self.requireMemoryBackend();
        const rec = self.findObject(id) orelse return error.ObjectNotFound;
        const payload_checksum = try checksum.newFromData(self.allocator, .sha256, rec.payload);
        return .{
            .container_id = rec.container_id,
            .owner = rec.owner,
            .payload = rec.payload,
            .payload_checksum = payload_checksum,
        };
    }

    pub fn objectHead(self: *Client, id: [32]u8) !object.Object {
        if (self.isGrpc()) {
            const rec = self.findObject(id) orelse return error.ObjectNotFound;
            return grpc_rpc.objectHead(self.allocator, self.grpc.?, rec.container_id, id);
        }
        try self.requireMemoryBackend();
        return self.objectGet(id);
    }

    pub fn objectDeleteInContainer(self: *Client, container_id: [32]u8, object_id: [32]u8, owner: user.ID, session_created: session_object.CreateResult, nbf_epoch: u64, exp_epoch: u64) !void {
        if (self.isGrpc()) {
            const key = self.signer_key orelse return error.MissingSigner;
            var token = try session_object.objectDeleteToken(self.allocator, key, session_created, owner, container_id, nbf_epoch, exp_epoch);
            defer token.deinit(self.allocator);
            return grpc_rpc.objectDelete(self.allocator, self.grpc.?, key, owner, container_id, object_id, token);
        }
        try self.requireMemoryBackend();
        const idx = self.findObjectIndex(object_id) orelse return error.ObjectNotFound;
        const rec = self.objects.orderedRemove(idx);
        self.allocator.free(rec.owner);
        self.allocator.free(rec.payload);
    }

    pub fn objectDelete(self: *Client, id: [32]u8) !void {
        if (self.isGrpc()) {
            const rec = self.findObject(id) orelse return error.ObjectNotFound;
            const key = self.signer_key orelse return error.MissingSigner;
            return grpc_rpc.objectDelete(self.allocator, self.grpc.?, key, user.ID.fromPublicKey(rec.owner), rec.container_id, id, .{});
        }
        try self.requireMemoryBackend();
        const idx = self.findObjectIndex(id) orelse return error.ObjectNotFound;
        const rec = self.objects.orderedRemove(idx);
        self.allocator.free(rec.owner);
        self.allocator.free(rec.payload);
    }

    pub fn objectHash(self: *Client, id: [32]u8) ![32]u8 {
        if (self.isGrpc()) {
            const rec = self.findObject(id) orelse return error.ObjectNotFound;
            return grpc_rpc.objectHash(self.allocator, self.grpc.?, rec.container_id, id);
        }
        try self.requireMemoryBackend();
        const rec = self.findObject(id) orelse return error.ObjectNotFound;
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(rec.payload, &h, .{});
        return h;
    }

    pub fn objectSearchInit(self: *Client, container_id: [32]u8) !object_stream.SearchReader {
        const grpc_client = self.grpc orelse return error.NotConnected;
        return object_stream.objectSearchInit(self.allocator, grpc_client, container_id);
    }

    pub fn searchObjects(self: *Client, container_id: [32]u8) ![][32]u8 {
        if (self.isGrpc()) return grpc_rpc.searchObjectsV2(self.allocator, self.grpc.?, container_id);
        try self.requireMemoryBackend();
        var out: std.ArrayList([32]u8) = .{};
        for (self.objects.items) |rec| {
            if (std.mem.eql(u8, &rec.container_id, &container_id)) {
                try out.append(self.allocator, rec.id);
            }
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn searchObjectsDetailed(self: *Client, container_id: [32]u8) ![]grpc_rpc.SearchObjectEntry {
        if (self.isGrpc()) {
            return grpc_rpc.searchObjectsDetailed(self.allocator, self.grpc.?, container_id, &.{ "Name", "FileName" });
        }
        try self.requireMemoryBackend();
        var out: std.ArrayList(SearchObjectEntry) = .{};
        for (self.objects.items) |rec| {
            if (std.mem.eql(u8, &rec.container_id, &container_id)) {
                try out.append(self.allocator, .{ .id = rec.id, .attribute_values = &.{} });
            }
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn freeSearchObjects(self: *Client, entries: []grpc_rpc.SearchObjectEntry) void {
        grpc_rpc.deinitSearchObjectEntries(self.allocator, entries);
    }

    pub fn objectRangeInit(self: *Client, id: [32]u8, offset: u64, length: u64) ![]const u8 {
        try self.requireMemoryBackend();
        const rec = self.findObject(id) orelse return error.ObjectNotFound;
        if (offset > rec.payload.len) return error.InvalidRange;
        const start: usize = @intCast(offset);
        const end = @min(rec.payload.len, start + @as(usize, @intCast(length)));
        return rec.payload[start..end];
    }

    pub fn replicateObject(self: *Client, id: [32]u8, node_key: []const u8) !void {
        if (self.isGrpc()) return error.NotImplemented;
        try self.requireMemoryBackend();
        _ = node_key;
        _ = self.findObject(id) orelse return error.ObjectNotFound;
        try self.replications.append(self.allocator, id);
    }

    pub fn isReplicated(self: *Client, id: [32]u8) bool {
        if (self.transport != null and self.transport.?.mode == .grpc) return false;
        for (self.replications.items) |rep| {
            if (std.mem.eql(u8, &rep, &id)) return true;
        }
        return false;
    }

    pub fn objectPutInit(self: *Client, init_request: ?@import("../proto/gen/object/types.pb.zig").PutRequest) !object_stream.ObjectWriter {
        const grpc_client = self.grpc orelse return error.NotConnected;
        if (init_request != null) return error.UnsupportedObjectPutInit;
        return .{
            .allocator = self.allocator,
            .grpc_client = grpc_client,
            .chunks = .{},
        };
    }

    pub fn prepareObjectPut(
        self: *Client,
        container_id: [32]u8,
        owner: user.ID,
        payload: []const u8,
        file_name: []const u8,
        session_created: session_object.CreateResult,
        nbf_epoch: u64,
        exp_epoch: u64,
        creation_epoch: u64,
    ) !object_stream.ObjectWriter {
        const key = self.signer_key orelse return error.MissingSigner;
        const prepared = try object_put.preparePutObject(self.allocator, key, container_id, owner, payload, file_name, creation_epoch);
        var token = try session_object.objectPutToken(self.allocator, key, session_created, owner, container_id, nbf_epoch, exp_epoch);
        defer token.deinit(self.allocator);
        const put_req = try grpc_rpc.buildObjectPutRequest(self.allocator, key, prepared, token);
        const grpc_client = self.grpc orelse return error.NotConnected;
        return try object_stream.objectPutInit(self.allocator, grpc_client, put_req, key, prepared.object_id);
    }

    pub fn prepareObjectPutV2(
        self: *Client,
        container_id: [32]u8,
        owner: user.ID,
        payload: []const u8,
        file_name: []const u8,
        session_token_v2: session_pb.SessionTokenV2,
        creation_epoch: u64,
    ) !object_stream.ObjectWriter {
        return self.prepareObjectPutV2WithHeaderSession(container_id, owner, payload, file_name, session_token_v2, creation_epoch, null);
    }

    /// Like `prepareObjectPutV2` but also embeds a v1 session token in the
    /// object header. Required by neofs-node's `AuthenticateObject` when the
    /// request signer differs from the object owner (i.e. delegated keys).
    pub fn prepareObjectPutV2WithHeaderSession(
        self: *Client,
        container_id: [32]u8,
        owner: user.ID,
        payload: []const u8,
        file_name: []const u8,
        session_token_v2: session_pb.SessionTokenV2,
        creation_epoch: u64,
        header_session_v1: ?session_pb.SessionToken,
    ) !object_stream.ObjectWriter {
        const key = self.signer_key orelse return error.MissingSigner;
        const prepared = try object_put.preparePutObjectCustom(
            self.allocator,
            key,
            container_id,
            owner,
            payload,
            file_name,
            "text/plain",
            &.{},
            creation_epoch,
            header_session_v1,
        );
        const put_req = try grpc_rpc.buildObjectPutRequestWithSessionV2(self.allocator, key, prepared, session_token_v2);
        const grpc_client = self.grpc orelse return error.NotConnected;
        return try object_stream.objectPutInit(self.allocator, grpc_client, put_req, key, prepared.object_id);
    }

    pub fn objectGetInit(self: *Client, container_id: [32]u8, object_id: [32]u8) !object_stream.GetInitResult {
        const grpc_client = self.grpc orelse return error.NotConnected;
        const key = self.signer_key orelse return error.MissingSigner;
        return object_stream.objectGetInit(self.allocator, grpc_client, key, container_id, object_id, .{});
    }

    pub fn objectGetInitV2(
        self: *Client,
        container_id: [32]u8,
        object_id: [32]u8,
        session_token_v2: session_pb.SessionTokenV2,
    ) !object_stream.GetInitResult {
        const grpc_client = self.grpc orelse return error.NotConnected;
        const key = self.signer_key orelse return error.MissingSigner;
        var local_signer = @import("../crypto/signer.zig").LocalSigner{ .secret = key };
        return object_stream.objectGetInitWithSigner(self.allocator, grpc_client, local_signer.asSigner(), container_id, object_id, .{}, session_token_v2);
    }

    pub fn objectGetRangeInit(
        self: *Client,
        container_id: [32]u8,
        object_id: [32]u8,
        offset: u64,
        length: u64,
    ) !object_stream.ObjectRangeReader {
        const grpc_client = self.grpc orelse return error.NotConnected;
        const key = self.signer_key orelse return error.MissingSigner;
        return object_stream.objectRangeInit(self.allocator, grpc_client, key, container_id, object_id, offset, length);
    }

    pub fn balanceGet(self: *Client, owner: []const u8) !accounting.Decimal {
        if (self.transport == null) return error.NotConnected;
        if (self.transport.?.mode == .grpc) {
            const key = self.signer_key orelse return error.MissingSigner;
            if (owner.len != user.IDSize) return error.InvalidOwnerID;
            var owner_id: user.ID = undefined;
            @memcpy(&owner_id.bytes, owner[0..user.IDSize]);
            return grpc_rpc.balanceGet(self.allocator, self.grpc.?, key, owner_id);
        }

        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(owner, &digest, .{});
        return accounting.Decimal.fromProto(@intCast(std.mem.readInt(u64, digest[0..8], .big)), 0);
    }

    pub fn netMapSnapshot(self: *Client) ![]const u8 {
        if (self.transport == null) return error.NotConnected;
        if (self.transport.?.mode == .grpc) {
            const req = netmap_pb.NetmapSnapshotRequest{};
            var resp = try self.grpcUnary(req, "/neo.fs.v2.netmap.NetmapService/NetmapSnapshot", netmap_pb.NetmapSnapshotResponse);
            defer resp.deinit(self.allocator);
            try status_failure.validate(self.allocator, resp.meta_header);
            const body = resp.body orelse return error.InvalidResponse;
            const nm = body.netmap orelse return error.InvalidResponse;
            return std.fmt.allocPrint(self.allocator, "snapshot:epoch={d},nodes={d}", .{ nm.epoch, nm.nodes.items.len });
        }
        return "snapshot:v2.22";
    }

    pub fn announceLocalTrust(self: *Client, payload: []const u8) !void {
        if (self.isGrpc()) {
            _ = payload;
            const key = self.signer_key orelse return error.MissingSigner;
            return grpc_rpc.announceLocalTrust(self.allocator, self.grpc.?, key, 0);
        }
        try self.requireMemoryBackend();
        _ = payload;
        self.trust_announcements += 1;
    }

    pub fn announceIntermediateTrust(self: *Client, payload: []const u8) !void {
        if (self.isGrpc()) {
            _ = payload;
            const key = self.signer_key orelse return error.MissingSigner;
            return grpc_rpc.announceIntermediateTrust(self.allocator, self.grpc.?, key, 0);
        }
        try self.requireMemoryBackend();
        _ = payload;
        self.trust_announcements += 1;
    }

    pub fn trustAnnouncementCount(self: *Client) usize {
        return self.trust_announcements;
    }

    pub fn signRequest(self: *Client, key: []const u8, body: []const u8) !signer.Signature {
        if (self.transport == null) return error.NotConnected;
        return signer.sign(self.allocator, .ecdsa_deterministic_sha256, key, body);
    }

    pub fn objectDeleteV2(
        self: *Client,
        owner: user.ID,
        container_id: [32]u8,
        object_id: [32]u8,
        session_token_v2: session_pb.SessionTokenV2,
    ) !void {
        if (!self.isGrpc()) return error.NotImplementedOverGrpc;
        const key = self.signer_key orelse return error.MissingSigner;
        return grpc_rpc.objectDeleteWithSessionV2(self.allocator, self.grpc.?, key, owner, container_id, object_id, session_token_v2);
    }

    pub fn objectHeadV2(
        self: *Client,
        container_id: [32]u8,
        object_id: [32]u8,
        session_token_v2: session_pb.SessionTokenV2,
    ) !object.Object {
        if (!self.isGrpc()) return error.NotImplementedOverGrpc;
        const key = self.signer_key orelse return error.MissingSigner;
        return grpc_rpc.objectHeadWithSessionV2(self.allocator, self.grpc.?, key, container_id, object_id, session_token_v2);
    }

    pub fn searchObjectsDetailedV2(
        self: *Client,
        container_id: [32]u8,
        attribute_names: []const []const u8,
        session_token_v2: session_pb.SessionTokenV2,
    ) ![]SearchObjectEntry {
        if (!self.isGrpc()) return error.NotImplementedOverGrpc;
        const key = self.signer_key orelse return error.MissingSigner;
        return grpc_rpc.searchObjectsDetailedWithSessionV2(self.allocator, self.grpc.?, key, container_id, attribute_names, session_token_v2);
    }

    pub fn sessionV2CachePut(self: *Client, key: []const u8, token: session_pb.SessionTokenV2) !void {
        const owned_key = try self.allocator.dupe(u8, key);
        const owned_tok = try token.dupe(self.allocator);
        if (self.session_v2_cache.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            var old = kv.value;
            old.deinit(self.allocator);
        }
        try self.session_v2_cache.put(owned_key, owned_tok);
    }

    pub fn sessionV2CacheGet(self: *Client, key: []const u8) !?session_pb.SessionTokenV2 {
        const tok = self.session_v2_cache.get(key) orelse return null;
        return tok.dupe(self.allocator);
    }

    pub fn mapStatusCode(_: *Client, code: i32) status.Error {
        return status.fromCode(code);
    }

    fn findContainer(self: *Client, id: [32]u8) ?*ContainerRecord {
        for (self.containers.items) |*rec| {
            if (std.mem.eql(u8, &rec.id, &id)) return rec;
        }
        return null;
    }

    fn findContainerIndex(self: *Client, id: [32]u8) ?usize {
        for (self.containers.items, 0..) |rec, i| {
            if (std.mem.eql(u8, &rec.id, &id)) return i;
        }
        return null;
    }

    fn findObject(self: *Client, id: [32]u8) ?*ObjectRecord {
        for (self.objects.items) |*rec| {
            if (std.mem.eql(u8, &rec.id, &id)) return rec;
        }
        return null;
    }

    fn findObjectIndex(self: *Client, id: [32]u8) ?usize {
        for (self.objects.items, 0..) |rec, i| {
            if (std.mem.eql(u8, &rec.id, &id)) return i;
        }
        return null;
    }

    fn grpcUnary(self: *Client, request: anytype, path: []const u8, comptime ResponseType: type) !ResponseType {
        return grpc_rpc.grpcUnary(self.allocator, self.grpc orelse return error.NotConnected, request, path, ResponseType);
    }

    fn requireMemoryBackend(self: *Client) !void {
        if (self.transport != null and self.transport.?.mode == .grpc) {
            return error.NotImplementedOverGrpc;
        }
    }
};

fn transportMode(endpoint: []const u8) TransportMode {
    if (std.mem.startsWith(u8, endpoint, "grpc://") or std.mem.startsWith(u8, endpoint, "grpcs://")) {
        return .grpc;
    }
    return .memory;
}

fn endpointTarget(endpoint: []const u8) []const u8 {
    if (std.mem.startsWith(u8, endpoint, "grpc://")) return endpoint["grpc://".len..];
    if (std.mem.startsWith(u8, endpoint, "grpcs://")) return endpoint["grpcs://".len..];
    return endpoint;
}

fn parseHostPort(host_port: []const u8, out: []u8) ![]const u8 {
    if (std.mem.indexOfScalar(u8, host_port, ':')) |idx| {
        if (idx >= out.len) return error.HostTooLong;
        @memcpy(out[0..idx], host_port[0..idx]);
        return out[0..idx];
    }
    if (host_port.len >= out.len) return error.HostTooLong;
    @memcpy(out[0..host_port.len], host_port);
    return out[0..host_port.len];
}

fn parsePort(host_port: []const u8) !u16 {
    if (std.mem.indexOfScalar(u8, host_port, ':')) |idx| {
        return try std.fmt.parseInt(u16, host_port[idx + 1 ..], 10);
    }
    return 8080;
}

test "client lifecycle" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var c = Client.init(gpa.allocator());
    defer c.deinit();
    try c.dial("mem://localhost:8080", false, 1000);
    const ep = try c.endpointInfo();
    try std.testing.expectEqualStrings("mem://localhost:8080", ep);
}

test "container and object lifecycle" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var c = Client.init(gpa.allocator());
    defer c.deinit();
    try c.dial("mem://localhost:8080", false, 1000);

    var cont = try container.Container.init(gpa.allocator(), "owner-1", "nonce-1");
    defer cont.deinit();
    const cid = try c.containerPut(cont);
    try c.setContainerAttribute(cid, "k", "v");
    try c.containerEaclSet(cid, "eacl-bin");
    var got = try c.containerGet(cid);
    defer got.deinit();
    try std.testing.expectEqualStrings("owner-1", got.owner);
    try std.testing.expectEqualStrings("eacl-bin", try c.containerEaclGet(cid));

    const oid = try c.objectPut(.{
        .container_id = cid,
        .owner = "owner-1",
        .payload = "payload-12345",
    });
    const ogot = try c.objectGet(oid);
    defer if (ogot.payload_checksum) |sum| c.allocator.free(sum.value);
    try std.testing.expectEqualStrings("payload-12345", ogot.payload);

    const rng = try c.objectRangeInit(oid, 2, 4);
    try std.testing.expectEqualStrings("yloa", rng);
    try c.replicateObject(oid, "node-pubkey");
    try std.testing.expect(c.isReplicated(oid));
}

test "transport mode detection" {
    try std.testing.expectEqual(TransportMode.memory, transportMode("mem://n1:8080"));
    try std.testing.expectEqual(TransportMode.grpc, transportMode("grpc://n1:8080"));
    try std.testing.expectEqual(TransportMode.grpc, transportMode("grpcs://n1:8080"));
    try std.testing.expectEqualStrings("n1:8080", endpointTarget("grpc://n1:8080"));
    try std.testing.expectEqualStrings("n1:8080", endpointTarget("grpcs://n1:8080"));
}
