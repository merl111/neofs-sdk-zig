const std = @import("std");
const sig = @import("signature.zig");
const signer_mod = @import("signer.zig");
const wire = @import("../internal/proto/encoding.zig");

pub const RequestVerificationHeader = struct {
    body_signature: ?sig.Signature = null,
    meta_signature: sig.Signature,
    origin_signature: sig.Signature,
    origin: ?*RequestVerificationHeader = null,
};

pub const SignedRequest = struct {
    body: []const u8,
    /// `meta_chain[0]` is the current request meta; deeper entries correspond to origin headers.
    meta_chain: []const []const u8,
    verify_header: ?*RequestVerificationHeader = null,
};

pub fn signRequestWithBuffer(
    allocator: std.mem.Allocator,
    signer: signer_mod.Signer,
    req: SignedRequest,
    scratch: []u8,
) !*RequestVerificationHeader {
    _ = scratch;
    if (req.meta_chain.len == 0) return error.MissingMetaHeader;

    const origin_blob = if (req.verify_header) |vh| try marshalVerificationHeader(allocator, vh) else try allocator.dupe(u8, "");
    defer allocator.free(origin_blob);

    const meta_sig = try signer.sign(allocator, req.meta_chain[0]);
    const origin_sig = try signer.sign(allocator, origin_blob);

    var body_sig: ?sig.Signature = null;
    if (req.verify_header == null) {
        body_sig = try signer.sign(allocator, req.body);
    }

    const res = try allocator.create(RequestVerificationHeader);
    res.* = .{
        .body_signature = body_sig,
        .meta_signature = meta_sig,
        .origin_signature = origin_sig,
        .origin = req.verify_header,
    };
    return res;
}

pub fn verifyRequestWithBuffer(
    key: []const u8,
    req: SignedRequest,
    verify_header: *const RequestVerificationHeader,
    scratch: []u8,
) !bool {
    _ = scratch;
    if (req.meta_chain.len == 0) return error.MissingMetaHeader;

    var allocator = std.heap.page_allocator;
    var depth: usize = 0;
    var visited: usize = 0;
    var vh: ?*const RequestVerificationHeader = verify_header;
    while (vh) |cur| : (depth += 1) {
        visited += 1;
        if (depth >= req.meta_chain.len) return error.IncorrectNumberOfVerificationHeaders;

        if (!sig.verify(key, req.meta_chain[depth], cur.meta_signature)) {
            return false;
        }

        if (cur.origin) |orig| {
            if (cur.body_signature != null) return error.NonOriginBodySignature;
            const blob = try marshalVerificationHeader(allocator, orig);
            defer allocator.free(blob);
            if (!sig.verify(key, blob, cur.origin_signature)) {
                return false;
            }
            vh = orig;
        } else {
            if (cur.body_signature == null) return error.MissingBodySignature;
            if (!sig.verify(key, req.body, cur.body_signature.?)) return false;
            if (!sig.verify(key, "", cur.origin_signature)) return false;
            vh = null;
        }
    }

    return visited == req.meta_chain.len;
}

pub fn freeVerificationHeader(allocator: std.mem.Allocator, vh: *RequestVerificationHeader) void {
    freeSignature(allocator, &vh.meta_signature);
    freeSignature(allocator, &vh.origin_signature);
    if (vh.body_signature) |*bs| freeSignature(allocator, bs);
    allocator.destroy(vh);
}

fn freeSignature(allocator: std.mem.Allocator, s: *sig.Signature) void {
    allocator.free(s.key);
    allocator.free(s.value);
}

fn marshalVerificationHeader(allocator: std.mem.Allocator, vh: *const RequestVerificationHeader) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    if (vh.body_signature) |b| {
        try appendSignatureField(allocator, &out, 1, b);
    }
    try appendSignatureField(allocator, &out, 2, vh.meta_signature);
    try appendSignatureField(allocator, &out, 3, vh.origin_signature);
    if (vh.origin) |orig| {
        const nested = try marshalVerificationHeader(allocator, orig);
        defer allocator.free(nested);
        try appendBytesField(allocator, &out, 4, nested);
    }
    return out.toOwnedSlice(allocator);
}

fn appendSignatureField(allocator: std.mem.Allocator, out: *std.ArrayList(u8), field_num: u32, s: sig.Signature) !void {
    var msg = std.ArrayList(u8).empty;
    defer msg.deinit(allocator);
    try appendBytesField(allocator, &msg, 1, s.key);
    try appendBytesField(allocator, &msg, 2, s.value);
    try appendVarintField(allocator, &msg, 3, @intFromEnum(s.scheme));
    const nested = try msg.toOwnedSlice(allocator);
    defer allocator.free(nested);
    try appendBytesField(allocator, out, field_num, nested);
}

fn appendBytesField(allocator: std.mem.Allocator, out: *std.ArrayList(u8), field_num: u32, data: []const u8) !void {
    var tmp: [16]u8 = undefined;
    const tag_n = wire.putTag(&tmp, field_num, 2);
    try out.appendSlice(allocator, tmp[0..tag_n]);
    const len_n = wire.putVarint(&tmp, data.len);
    try out.appendSlice(allocator, tmp[0..len_n]);
    try out.appendSlice(allocator, data);
}

fn appendVarintField(allocator: std.mem.Allocator, out: *std.ArrayList(u8), field_num: u32, v: u64) !void {
    var tmp: [16]u8 = undefined;
    const tag_n = wire.putTag(&tmp, field_num, 0);
    try out.appendSlice(allocator, tmp[0..tag_n]);
    const n = wire.putVarint(&tmp, v);
    try out.appendSlice(allocator, tmp[0..n]);
}

test "request signing chain enforces origin/body rules" {
    const allocator = std.testing.allocator;

    var local = signer_mod.LocalSigner{ .secret = "k" };
    const first = try signRequestWithBuffer(allocator, local.asSigner(), .{
        .body = "body",
        .meta_chain = &[_][]const u8{"m1"},
    }, &[_]u8{});
    defer freeVerificationHeader(allocator, first);

    const second = try signRequestWithBuffer(allocator, local.asSigner(), .{
        .body = "body",
        .meta_chain = &[_][]const u8{"m2", "m1"},
        .verify_header = first,
    }, &[_]u8{});
    defer freeVerificationHeader(allocator, second);

    try std.testing.expect(second.body_signature == null);
    const ok = try verifyRequestWithBuffer("k", .{
        .body = "body",
        .meta_chain = &[_][]const u8{"m2", "m1"},
    }, second, &[_]u8{});
    try std.testing.expect(ok);
}

test "request signing fails on bad meta chain length" {
    const allocator = std.testing.allocator;
    var local = signer_mod.LocalSigner{ .secret = "k" };
    const first = try signRequestWithBuffer(allocator, local.asSigner(), .{
        .body = "body",
        .meta_chain = &[_][]const u8{"m1"},
    }, &[_]u8{});
    defer freeVerificationHeader(allocator, first);

    const second = try signRequestWithBuffer(allocator, local.asSigner(), .{
        .body = "body",
        .meta_chain = &[_][]const u8{"m2", "m1"},
        .verify_header = first,
    }, &[_]u8{});
    defer freeVerificationHeader(allocator, second);

    try std.testing.expectError(error.IncorrectNumberOfVerificationHeaders, verifyRequestWithBuffer("k", .{
        .body = "body",
        .meta_chain = &[_][]const u8{"m2"},
    }, second, &[_]u8{}));
}
