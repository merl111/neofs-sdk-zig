const std = @import("std");
const grpc = @import("../transport/grpc.zig");
const object_pb = @import("../proto/gen/object/types.pb.zig");
const session_pb = @import("../proto/gen/session/types.pb.zig");
const request = @import("request.zig");
const signer_mod = @import("../crypto/signer.zig");
const status = @import("status/errors.zig");

pub const PutInitParams = struct {
    init_request: object_pb.PutRequest,
};

pub const GetParams = struct {
    raw: bool = true,
    range: ?object_pb.Range = null,
    payload_only: bool = false,
};

pub const ObjectWriter = struct {
    allocator: std.mem.Allocator,
    grpc_client: *grpc.Client,
    path: []const u8 = "/neo.fs.v2.object.ObjectService/Put",
    chunks: std.ArrayList([]u8),
    init_request: ?object_pb.PutRequest = null,
    /// Optional inline LocalSigner; when set, `signer` points to this field so
    /// the writer's signer remains valid for the writer's lifetime.
    local_signer: ?signer_mod.LocalSigner = null,
    signer: ?signer_mod.Signer = null,
    session_token: ?session_pb.SessionToken = null,
    session_token_v2: ?session_pb.SessionTokenV2 = null,
    expected_object_id: [32]u8 = undefined,
    has_expected_object_id: bool = false,
    closed: bool = false,
    result_id: [32]u8 = undefined,
    has_result: bool = false,

    /// Returns the active Signer. If `local_signer` is set, derives a Signer
    /// whose ctx points into `self` (stable address), preventing dangling refs
    /// after the writer is moved by value from its constructor.
    fn currentSigner(self: *ObjectWriter) ?signer_mod.Signer {
        if (self.local_signer) |*ls| return ls.asSigner();
        return self.signer;
    }

    pub fn write(self: *ObjectWriter, chunk: []const u8) !void {
        const owned = try self.allocator.dupe(u8, chunk);
        try self.chunks.append(self.allocator, owned);
    }

    pub fn close(self: *ObjectWriter) !void {
        if (self.closed) return;
        self.closed = true;
        var encoded_chunks: std.ArrayList([]const u8) = .empty;
        defer encoded_chunks.deinit(self.allocator);
        if (self.init_request) |init_req| {
            var w: std.Io.Writer.Allocating = .init(self.allocator);
            defer w.deinit();
            try init_req.encode(&w.writer, self.allocator);
            const bytes = try self.allocator.dupe(u8, w.written());
            try encoded_chunks.append(self.allocator, bytes);
        } else if (self.chunks.items.len > 0) {
            return error.MissingPutInit;
        }
        for (self.chunks.items) |chunk| {
            const signer = self.currentSigner() orelse return error.MissingSigner;
            var meta = try request.defaultMetaHeader(self.allocator);
            if (self.session_token) |session_token| {
                meta.session_token = try session_token.dupe(self.allocator);
            }
            if (self.session_token_v2) |session_token_v2| {
                meta.session_token_v2 = try session_token_v2.dupe(self.allocator);
            }
            if (meta.session_token == null and meta.session_token_v2 == null) return error.MissingSessionToken;
            const req = object_pb.PutRequest{
                .body = .{
                    .object_part = .{ .chunk = chunk },
                },
                .meta_header = meta,
            };
            var signed = try request.signRequestMessageWithSigner(self.allocator, signer, req, meta);
            defer {
                if (signed.body) |*body| {
                    if (body.object_part) |*part| {
                        switch (part.*) {
                            .chunk => part.chunk = &[_]u8{},
                            else => {},
                        }
                    }
                }
                signed.deinit(self.allocator);
            }
            var w: std.Io.Writer.Allocating = .init(self.allocator);
            defer w.deinit();
            try signed.encode(&w.writer, self.allocator);
            const bytes = try self.allocator.dupe(u8, w.written());
            try encoded_chunks.append(self.allocator, bytes);
        }
        defer for (encoded_chunks.items) |b| self.allocator.free(b);
        const response_bytes = try self.grpc_client.clientStreamCall(self.path, encoded_chunks.items);
        defer self.allocator.free(response_bytes);
        var reader = std.Io.Reader.fixed(response_bytes);
        var resp = try object_pb.PutResponse.decode(&reader, self.allocator);
        defer resp.deinit(self.allocator);
        try validatePutStatus(resp.meta_header);
        if (resp.body) |body| {
            if (body.object_id) |oid| {
                if (oid.value.len >= 32) {
                    @memcpy(&self.result_id, oid.value[0..32]);
                    self.has_result = true;
                }
            }
        }
        if (!self.has_result and self.has_expected_object_id) {
            self.result_id = self.expected_object_id;
            self.has_result = true;
        }
    }

    pub fn storedObjectID(self: *ObjectWriter) ?[32]u8 {
        if (!self.has_result) return null;
        return self.result_id;
    }

    pub fn deinit(self: *ObjectWriter) void {
        if (self.init_request) |*req| req.deinit(self.allocator);
        if (self.session_token) |*token| token.deinit(self.allocator);
        for (self.chunks.items) |c| self.allocator.free(c);
        self.chunks.deinit(self.allocator);
    }
};

fn validatePutStatus(meta_header: ?session_pb.ResponseMetaHeader) !void {
    try validateResponseStatus(meta_header);
}

fn validateGetStatus(meta_header: ?session_pb.ResponseMetaHeader) !void {
    try validateResponseStatus(meta_header);
}

fn validateResponseStatus(meta_header: ?session_pb.ResponseMetaHeader) !void {
    const meta = meta_header orelse return;
    const st = meta.status orelse return;
    if (st.code != 0) {
        if (st.message.len > 0) {
            std.debug.print("NeoFS status {d}: {s}\n", .{ st.code, st.message });
        }
        return status.fromCode(@intCast(st.code));
    }
}

pub const PayloadReader = struct {
    allocator: std.mem.Allocator,
    stream: ?grpc.Client.ServerStream = null,
    tail: []u8 = "",
    stream_done: bool = false,
    chunks: std.ArrayList([]u8),
    index: usize = 0,
    offset: usize = 0,

    pub fn read(self: *PayloadReader, buf: []u8) !usize {
        if (buf.len == 0) return 0;
        if (self.stream != null) return self.readStream(buf);

        if (self.index >= self.chunks.items.len) return 0;
        var total: usize = 0;
        while (total < buf.len and self.index < self.chunks.items.len) {
            const cur = self.chunks.items[self.index];
            if (self.offset >= cur.len) {
                self.index += 1;
                self.offset = 0;
                continue;
            }
            const n = @min(buf.len - total, cur.len - self.offset);
            @memcpy(buf[total .. total + n], cur[self.offset .. self.offset + n]);
            self.offset += n;
            total += n;
        }
        return total;
    }

    fn readStream(self: *PayloadReader, buf: []u8) !usize {
        var total: usize = 0;
        if (self.tail.len > 0) {
            const n = @min(buf.len, self.tail.len);
            @memcpy(buf[0..n], self.tail[0..n]);
            if (n == self.tail.len) {
                self.allocator.free(self.tail);
                self.tail = "";
            } else {
                const remaining = try self.allocator.dupe(u8, self.tail[n..]);
                self.allocator.free(self.tail);
                self.tail = remaining;
            }
            total += n;
            if (total == buf.len) return total;
        }

        while (total < buf.len) {
            const chunk = try self.recvChunk() orelse {
                self.stream_done = true;
                return total;
            };
            if (chunk.len == 0) continue;

            const n = @min(buf.len - total, chunk.len);
            @memcpy(buf[total .. total + n], chunk[0..n]);
            total += n;
            if (n < chunk.len) {
                self.tail = try self.allocator.dupe(u8, chunk[n..]);
            }
            self.allocator.free(chunk);
            if (total == buf.len) return total;
        }
        return total;
    }

    fn recvChunk(self: *PayloadReader) !?[]u8 {
        const stream = &self.stream.?;
        while (true) {
            const msg_bytes = try stream.next() orelse return null;
            defer self.allocator.free(msg_bytes);
            var reader_io = std.Io.Reader.fixed(msg_bytes);
            var resp = try object_pb.GetResponse.decode(&reader_io, self.allocator);
            defer resp.deinit(self.allocator);
            const body = resp.body orelse continue;
            const part = body.object_part orelse continue;
            switch (part) {
                .chunk => |chunk| return try self.allocator.dupe(u8, chunk),
                else => return error.UnexpectedGetResponsePart,
            }
        }
    }

    pub fn deinit(self: *PayloadReader) void {
        if (self.stream) |*stream| stream.deinit();
        if (self.tail.len > 0) self.allocator.free(self.tail);
        for (self.chunks.items) |c| self.allocator.free(c);
        self.chunks.deinit(self.allocator);
    }
};

pub const ObjectRangeReader = PayloadReader;

pub fn objectPutInit(
    allocator: std.mem.Allocator,
    client: *grpc.Client,
    init_request: object_pb.PutRequest,
    signer_key: []const u8,
    expected_object_id: [32]u8,
) !ObjectWriter {
    // Build the writer first so the LocalSigner lives at a stable address inside
    // it (taking `&local_signer.asSigner()` on a stack value would dangle).
    const meta = init_request.meta_header orelse return error.MissingMetaHeader;
    const owned_token = if (meta.session_token) |session_token| try session_token.dupe(allocator) else null;
    const owned_token_v2 = if (meta.session_token_v2) |session_token_v2| try session_token_v2.dupe(allocator) else null;
    if (owned_token == null and owned_token_v2 == null) return error.MissingSessionToken;
    // Note: don't pre-build `.signer` here. The Signer's ctx pointer would
    // reference the local copy of `local_signer`, which dangles after this
    // function returns by value. `currentSigner()` rebinds it on use using a
    // pointer into the caller-owned writer.
    return .{
        .allocator = allocator,
        .grpc_client = client,
        .chunks = .empty,
        .init_request = init_request,
        .local_signer = .{ .secret = signer_key },
        .signer = null,
        .session_token = owned_token,
        .session_token_v2 = owned_token_v2,
        .expected_object_id = expected_object_id,
        .has_expected_object_id = true,
    };
}

pub fn objectPutInitWithSigner(
    allocator: std.mem.Allocator,
    client: *grpc.Client,
    init_request: object_pb.PutRequest,
    signer: signer_mod.Signer,
    expected_object_id: [32]u8,
) !ObjectWriter {
    const meta = init_request.meta_header orelse return error.MissingMetaHeader;
    const owned_token = if (meta.session_token) |session_token| try session_token.dupe(allocator) else null;
    const owned_token_v2 = if (meta.session_token_v2) |session_token_v2| try session_token_v2.dupe(allocator) else null;
    if (owned_token == null and owned_token_v2 == null) return error.MissingSessionToken;
    return .{
        .allocator = allocator,
        .grpc_client = client,
        .chunks = .empty,
        .init_request = init_request,
        .signer = signer,
        .session_token = owned_token,
        .session_token_v2 = owned_token_v2,
        .expected_object_id = expected_object_id,
        .has_expected_object_id = true,
    };
}

pub const GetInitResult = struct { header: object_pb.GetResponse, reader: PayloadReader };

pub fn objectGetInit(
    allocator: std.mem.Allocator,
    client: *grpc.Client,
    signer_key: []const u8,
    container_id: [32]u8,
    object_id: [32]u8,
    params: GetParams,
) !GetInitResult {
    var local_signer = signer_mod.LocalSigner{ .secret = signer_key };
    return objectGetInitWithSigner(allocator, client, local_signer.asSigner(), container_id, object_id, params, null);
}

pub fn objectGetInitWithSigner(
    allocator: std.mem.Allocator,
    client: *grpc.Client,
    signer: signer_mod.Signer,
    container_id: [32]u8,
    object_id: [32]u8,
    params: GetParams,
    session_token_v2: ?session_pb.SessionTokenV2,
) !GetInitResult {
    var req = object_pb.GetRequest{
        .body = .{
            .address = .{
                .container_id = .{ .value = try allocator.dupe(u8, &container_id) },
                .object_id = .{ .value = try allocator.dupe(u8, &object_id) },
            },
            .raw = params.raw,
            .payload_only = params.payload_only,
        },
        .meta_header = try request.defaultMetaHeader(allocator),
    };
    if (params.range) |rng| {
        req.body.?.range = .{
            .offset = rng.offset,
            .length = rng.length,
        };
    }
    if (session_token_v2) |tok| {
        req.meta_header.?.session_token_v2 = try tok.dupe(allocator);
    }
    var signed = try request.signRequestMessageWithSigner(allocator, signer, req, req.meta_header.?);
    defer signed.deinit(allocator);
    var w: std.Io.Writer.Allocating = .init(allocator);
    defer w.deinit();
    try signed.encode(&w.writer, allocator);

    var stream = try client.openServerStream("/neo.fs.v2.object.ObjectService/Get", w.written());
    if (params.payload_only) {
        return .{
            .header = .{},
            .reader = .{
                .allocator = allocator,
                .stream = stream,
                .chunks = .empty,
            },
        };
    }

    const first_bytes = try stream.next() orelse return error.EmptyStream;
    defer allocator.free(first_bytes);
    var reader_io = std.Io.Reader.fixed(first_bytes);
    const header = try object_pb.GetResponse.decode(&reader_io, allocator);
    try validateGetStatus(header.meta_header);

    return .{
        .header = header,
        .reader = .{
            .allocator = allocator,
            .stream = stream,
            .chunks = .empty,
        },
    };
}

pub fn objectRangeInit(
    allocator: std.mem.Allocator,
    client: *grpc.Client,
    signer_key: []const u8,
    container_id: [32]u8,
    object_id: [32]u8,
    offset: u64,
    length: u64,
) !ObjectRangeReader {
    var local_signer = signer_mod.LocalSigner{ .secret = signer_key };
    const result = try objectGetInitWithSigner(allocator, client, local_signer.asSigner(), container_id, object_id, .{
        .raw = true,
        .range = .{ .offset = offset, .length = length },
        .payload_only = true,
    }, null);
    return result.reader;
}

pub const SearchReader = struct {
    allocator: std.mem.Allocator,
    stream: grpc.Client.ServerStream,
    pending: std.ArrayList([32]u8),
    index: usize = 0,
    finished: bool = false,

    pub fn nextObjectID(self: *SearchReader) !?[32]u8 {
        while (self.index >= self.pending.items.len) {
            self.index = 0;
            self.pending.clearRetainingCapacity();
            if (self.finished) return null;
            const msg_bytes = try self.stream.next() orelse {
                self.finished = true;
                return null;
            };
            defer self.allocator.free(msg_bytes);
            var reader_io = std.Io.Reader.fixed(msg_bytes);
            var resp = try object_pb.SearchResponse.decode(&reader_io, self.allocator);
            defer resp.deinit(self.allocator);
            const body = resp.body orelse continue;
            for (body.id_list.items) |oid| {
                if (oid.value.len >= 32) {
                    var id: [32]u8 = undefined;
                    @memcpy(&id, oid.value[0..32]);
                    try self.pending.append(self.allocator, id);
                }
            }
            if (self.pending.items.len == 0) continue;
        }
        const id = self.pending.items[self.index];
        self.index += 1;
        return id;
    }

    pub fn deinit(self: *SearchReader) void {
        self.stream.deinit();
        self.pending.deinit(self.allocator);
    }
};

pub fn objectSearchInit(
    allocator: std.mem.Allocator,
    client: *grpc.Client,
    container_id: [32]u8,
) !SearchReader {
    var req = object_pb.SearchRequest{
        .body = .{
            .container_id = .{ .value = try allocator.dupe(u8, &container_id) },
        },
    };
    defer req.deinit(allocator);
    var w: std.Io.Writer.Allocating = .init(allocator);
    defer w.deinit();
    try req.encode(&w.writer, allocator);
    const stream = try client.openServerStream("/neo.fs.v2.object.ObjectService/Search", w.written());
    return .{ .allocator = allocator, .stream = stream };
}
