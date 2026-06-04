const std = @import("std");
const user = @import("../user/id.zig");
const user_signer = @import("../user/signer.zig");
const sig = @import("../crypto/signature.zig");
const acl_pb = @import("../proto/gen/acl/types.pb.zig");
const refs_pb = @import("../proto/gen/refs/types.pb.zig");
const marshal_stable = @import("../testutil/marshal_stable.zig");

pub const Token = struct {
    owner: ?user.ID = null,
    issuer: ?user.ID = null,
    nbf: u64 = 0,
    exp: u64 = 0,
    iat: u64 = 0,
    container_id: ?[32]u8 = null,
    eacl_table_bin: ?[]const u8 = null,
    signature: ?sig.Signature = null,

    pub fn setEaclTableBin(self: *Token, bin: []const u8) void {
        self.eacl_table_bin = bin;
    }

    pub fn validAt(self: Token, epoch: u64) bool {
        if (self.nbf == 0 and self.iat == 0 and self.exp == 0) return epoch == 0;
        return self.nbf <= epoch and self.iat <= epoch and self.exp >= epoch;
    }

    pub fn forUser(self: *Token, id: user.ID) void {
        self.owner = id;
    }

    pub fn assertUser(self: Token, id: user.ID) bool {
        const owner = self.owner orelse return true;
        return std.mem.eql(u8, &owner.bytes, &id.bytes);
    }

    pub fn setIssuer(self: *Token, id: user.ID) void {
        self.issuer = id;
    }

    pub fn issuerID(self: Token) ?user.ID {
        return self.issuer;
    }

    pub fn assertContainer(self: Token, id: [32]u8) bool {
        const cid = self.container_id orelse return true;
        return std.mem.eql(u8, &cid, &id);
    }

    pub fn setContainer(self: *Token, id: [32]u8) void {
        self.container_id = id;
    }

    pub fn fillBody(self: Token, allocator: std.mem.Allocator) !?acl_pb.BearerToken.Body {
        const lifetime_set = self.iat != 0 or self.nbf != 0 or self.exp != 0;
        const owner_set = self.owner != null;
        const issuer_set = self.issuer != null;
        if (!lifetime_set and !owner_set and !issuer_set) return null;

        var body: acl_pb.BearerToken.Body = .{};
        if (owner_set) {
            body.owner_id = .{ .value = try allocator.dupe(u8, &self.owner.?.bytes) };
        }
        if (issuer_set) {
            body.issuer = .{ .value = try allocator.dupe(u8, &self.issuer.?.bytes) };
        }
        if (lifetime_set) {
            body.lifetime = .{ .exp = self.exp, .nbf = self.nbf, .iat = self.iat };
        }
        if (self.eacl_table_bin) |bin| {
            var reader = std.Io.Reader.fixed(bin);
            var table = try acl_pb.EACLTable.decode(&reader, allocator);
            errdefer table.deinit(allocator);
            body.eacl_table = table;
        }
        return body;
    }

    pub fn signedData(self: Token, allocator: std.mem.Allocator) ![]u8 {
        var body = (try self.fillBody(allocator)) orelse return &[_]u8{};
        defer body.deinit(allocator);
        return marshal_stable.encodeMessage(acl_pb.BearerToken.Body, allocator, body);
    }

    pub fn sign(self: *Token, allocator: std.mem.Allocator, signer: user_signer.Signer) !void {
        self.setIssuer(signer.userID());
        const data = try self.signedData(allocator);
        defer allocator.free(data);
        self.signature = try signer.sign(allocator, data);
    }

    pub fn verifySignature(self: Token, allocator: std.mem.Allocator) bool {
        const signature = self.signature orelse return false;
        const data = self.signedData(allocator) catch return false;
        defer allocator.free(data);
        return sig.verify(signature.key, data, signature);
    }

    pub fn protoMessage(self: Token, allocator: std.mem.Allocator) !acl_pb.BearerToken {
        var msg: acl_pb.BearerToken = .{};
        if (try self.fillBody(allocator)) |body| {
            msg.body = body;
        }
        if (self.signature) |s| {
            msg.signature = .{
                .key = try allocator.dupe(u8, s.key),
                .sign = try allocator.dupe(u8, s.value),
                .scheme = switch (s.scheme) {
                    .ecdsa_sha512 => .ECDSA_SHA512,
                    .ecdsa_deterministic_sha256 => .ECDSA_RFC6979_SHA256,
                    .ecdsa_walletconnect => .ECDSA_RFC6979_SHA256_WALLET_CONNECT,
                    .n3 => .N3,
                },
            };
        }
        return msg;
    }

    pub fn fromProtoMessage(self: *Token, allocator: std.mem.Allocator, m: acl_pb.BearerToken) !void {
        const body = m.body orelse return;
        if (body.owner_id) |oid| {
            if (oid.value.len == user.IDSize) {
                var raw: [user.IDSize]u8 = undefined;
                @memcpy(&raw, oid.value[0..user.IDSize]);
                self.owner = try user.ID.fromRaw(raw);
            }
        }
        if (body.issuer) |iss| {
            if (iss.value.len == user.IDSize) {
                var raw: [user.IDSize]u8 = undefined;
                @memcpy(&raw, iss.value[0..user.IDSize]);
                self.issuer = try user.ID.fromRaw(raw);
            }
        }
        if (body.lifetime) |lt| {
            self.exp = lt.exp;
            self.nbf = lt.nbf;
            self.iat = lt.iat;
        }
        if (m.signature) |s| {
            self.signature = .{
                .scheme = switch (s.scheme) {
                    .ECDSA_SHA512 => .ecdsa_sha512,
                    .ECDSA_RFC6979_SHA256 => .ecdsa_deterministic_sha256,
                    .ECDSA_RFC6979_SHA256_WALLET_CONNECT => .ecdsa_walletconnect,
                    .N3 => .n3,
                    else => .ecdsa_deterministic_sha256,
                },
                .key = try allocator.dupe(u8, s.key),
                .value = try allocator.dupe(u8, s.sign),
            };
        }
    }

    pub fn marshal(self: Token, allocator: std.mem.Allocator) ![]u8 {
        var msg = try self.protoMessage(allocator);
        defer msg.deinit(allocator);
        return marshal_stable.encodeMessage(acl_pb.BearerToken, allocator, msg);
    }

    pub fn unmarshal(self: *Token, allocator: std.mem.Allocator, data: []const u8) !void {
        var msg = try marshal_stable.decodeMessage(acl_pb.BearerToken, allocator, data);
        defer msg.deinit(allocator);
        try self.fromProtoMessage(allocator, msg);
    }
};

test {
    _ = @import("token_test.zig");
}
