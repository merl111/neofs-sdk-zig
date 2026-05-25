const std = @import("std");
const openssl_tls = @import("openssl_tls.zig");
const hpack = @import("hpack.zig");

/// Minimal persistent HTTP/2 + gRPC client for NeoFS unary and streaming RPCs.
pub const Client = struct {
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    tls: ?*TlsConnection = null,
    scheme: []const u8 = "http",
    authority: []const u8,
    next_stream_id: u31 = 1,
    /// Peer-controlled flow-control windows for OUR sending direction.
    /// Both connection-level and per-stream windows start at 65535 per RFC 7540
    /// §6.9.2 and are updated by the peer via SETTINGS (INITIAL_WINDOW_SIZE=0x4)
    /// and WINDOW_UPDATE frames.
    peer_initial_window: i64 = 65535,
    conn_send_window: i64 = 65535,
    /// Per-stream send window for the currently active client-streaming send.
    /// Reset by clientStreamCall to peer_initial_window before sending DATA.
    stream_send_window: i64 = 65535,
    /// Current stream id we're sending DATA on (used to route WINDOW_UPDATE).
    sending_stream_id: u31 = 0,
    /// Set when the peer half-closes (END_STREAM trailers or RST_STREAM) while
    /// we are still in the send loop. Future DATA frames for that stream are
    /// suppressed so we stop fighting the server's flow control.
    peer_done_sending_stream: bool = false,
    /// Accumulated HPACK payload from response HEADERS frames received while
    /// we were still sending. Replayed by the read loop as if the frame came
    /// in normally.
    pending_response_hpack: std.ArrayList(u8) = .{},
    pending_response_hpack_end_stream: bool = false,
    /// DATA payloads received on the active stream while we were still
    /// sending. These must be replayed to the ServerStream once the send
    /// phase completes, otherwise the response body is silently dropped.
    pending_response_data: std.ArrayList(u8) = .{},
    /// HPACK decoder state, shared across all streams on this connection so
    /// dynamic-table indices (e.g. 0xbf/0xbe in compressed trailers) resolve
    /// back to entries inserted by earlier responses.
    hpack_decoder: hpack.Decoder = .{ .allocator = undefined },
    /// Last observed gRPC status header on this connection. -1 means "not seen
    /// yet for the current call".
    last_grpc_status: i32 = -1,
    last_grpc_message: ?[]u8 = null,
    last_http_status: u16 = 0,

    pub fn connect(allocator: std.mem.Allocator, host: []const u8, port: u16, tls: bool) !Client {
        const stream = try std.net.tcpConnectToHost(allocator, host, port);
        const authority = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        errdefer allocator.free(authority);
        var client = Client{
            .allocator = allocator,
            .stream = stream,
            .scheme = if (tls) "https" else "http",
            .authority = authority,
            .hpack_decoder = .{ .allocator = allocator },
        };
        errdefer client.deinit();
        if (tls) {
            client.tls = try TlsConnection.init(allocator, stream, host);
        }
        try client.handshake();
        return client;
    }

    pub fn deinit(self: *Client) void {
        if (self.last_grpc_message) |m| self.allocator.free(m);
        self.hpack_decoder.deinit();
        self.pending_response_hpack.deinit(self.allocator);
        self.pending_response_data.deinit(self.allocator);
        self.allocator.free(self.authority);
        if (self.tls) |tls| {
            tls.deinit(self.allocator);
            self.tls = null;
        }
        self.stream.close();
    }

    pub fn unaryCall(self: *Client, path: []const u8, request: []const u8) ![]u8 {
        var stream = try self.openServerStream(path, request);
        defer stream.deinit();
        const response = try stream.next() orelse return error.InvalidGrpcMessage;
        errdefer self.allocator.free(response);
        if (try stream.next()) |extra| {
            self.allocator.free(extra);
            self.allocator.free(response);
            return error.InvalidGrpcMessage;
        }
        return response;
    }

    pub fn clientStreamCall(self: *Client, path: []const u8, chunks: []const []const u8) ![]u8 {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 2;

        var headers_payload: std.ArrayList(u8) = .{};
        defer headers_payload.deinit(self.allocator);
        try writeRequestHeaders(self.allocator, &headers_payload, self.scheme, self.authority, path);
        try self.writeFrame(.headers, stream_id, .{ .end_stream = false, .end_headers = true }, headers_payload.items);

        // New stream: send window starts at peer's INITIAL_WINDOW_SIZE.
        self.stream_send_window = self.peer_initial_window;
        self.sending_stream_id = stream_id;
        self.peer_done_sending_stream = false;
        self.pending_response_hpack.clearRetainingCapacity();
        self.pending_response_hpack_end_stream = false;
        self.pending_response_data.clearRetainingCapacity();
        self.last_grpc_status = -1;
        self.last_http_status = 0;
        if (self.last_grpc_message) |m| {
            self.allocator.free(m);
            self.last_grpc_message = null;
        }
        defer self.sending_stream_id = 0;

        for (chunks, 0..) |chunk, i| {
            // Server may finish the response (trailers + RST_STREAM NO_ERROR)
            // before we finish streaming. After that, sending more DATA is
            // both pointless and may trigger a real protocol error.
            if (self.peer_done_sending_stream) break;
            var grpc_msg: std.ArrayList(u8) = .{};
            defer grpc_msg.deinit(self.allocator);
            try appendGrpcMessage(&grpc_msg, self.allocator, chunk);
            const last = i == chunks.len - 1;
            try self.writeFrame(.data, stream_id, .{ .end_stream = last, .end_headers = false }, grpc_msg.items);
        }

        var stream = ServerStream{
            .client = self,
            .stream_id = stream_id,
            .recv_buf = .{},
            .finished = self.peer_done_sending_stream and self.pending_response_hpack_end_stream,
        };
        defer stream.deinit();

        // Replay any DATA bytes the server sent during our send phase.
        if (self.pending_response_data.items.len > 0) {
            try stream.recv_buf.appendSlice(self.allocator, self.pending_response_data.items);
            self.pending_response_data.clearRetainingCapacity();
        }
        // Surface a non-OK gRPC status from trailers received during the
        // send phase before we attempt to decode a (possibly empty) body.
        if (self.peer_done_sending_stream) {
            try self.checkGrpcStatus();
        }
        const response = stream.next() catch |err| {
            self.checkGrpcStatus() catch |status_err| return status_err;
            return err;
        } orelse {
            try self.checkGrpcStatus();
            // No DATA body at all but grpc-status 0: return an empty buffer
            // so callers (e.g. ObjectWriter.close) can fall back to the
            // locally-computed object id.
            return try self.allocator.alloc(u8, 0);
        };
        errdefer self.allocator.free(response);
        if (try stream.next()) |extra| {
            self.allocator.free(extra);
            self.allocator.free(response);
            return error.InvalidGrpcMessage;
        }
        return response;
    }

    /// Translate last_grpc_status / last_http_status into a Zig error. Returns
    /// without error when the call appears to have succeeded (or we don't
    /// have enough info).
    fn checkGrpcStatus(self: *Client) !void {
        if (self.last_http_status != 0 and self.last_http_status != 200) {
            std.log.err("grpc: http status {d}", .{self.last_http_status});
            return error.HttpStatusNotOK;
        }
        const code = self.last_grpc_status;
        if (code <= 0) return;
        const msg = self.last_grpc_message orelse "";
        std.log.err("grpc: status {d} {s}", .{ code, msg });
        return error.GrpcStatusError;
    }

    pub fn openServerStream(self: *Client, path: []const u8, request: []const u8) !ServerStream {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 2;

        var headers_payload: std.ArrayList(u8) = .{};
        defer headers_payload.deinit(self.allocator);
        try writeRequestHeaders(self.allocator, &headers_payload, self.scheme, self.authority, path);
        try self.writeFrame(.headers, stream_id, .{ .end_stream = false, .end_headers = true }, headers_payload.items);

        var grpc_msg: std.ArrayList(u8) = .{};
        defer grpc_msg.deinit(self.allocator);
        try appendGrpcMessage(&grpc_msg, self.allocator, request);
        try self.writeFrame(.data, stream_id, .{ .end_stream = true, .end_headers = false }, grpc_msg.items);

        return .{
            .client = self,
            .stream_id = stream_id,
            .recv_buf = .{},
            .finished = false,
        };
    }

    pub const ServerStream = struct {
        client: *Client,
        stream_id: u31,
        recv_buf: std.ArrayList(u8),
        finished: bool,

        pub fn deinit(self: *ServerStream) void {
            self.recv_buf.deinit(self.client.allocator);
        }

        pub fn next(self: *ServerStream) !?[]u8 {
            while (true) {
                if (try takeGrpcMessage(&self.recv_buf, self.client.allocator)) |msg| {
                    return msg;
                }
                if (self.finished) return null;
                try self.readMore();
            }
        }

        fn readMore(self: *ServerStream) !void {
            const frame = try self.client.readFrame();
            defer self.client.allocator.free(frame.payload);
            // Handle connection-level control frames regardless of stream id.
            switch (frame.frame_type) {
                .window_update => {
                    if (frame.payload.len >= 4) {
                        const inc = std.mem.readInt(u32, frame.payload[0..4], .big) & 0x7fffffff;
                        if (frame.stream_id == 0) {
                            self.client.conn_send_window += @intCast(inc);
                        } else if (frame.stream_id == self.client.sending_stream_id) {
                            self.client.stream_send_window += @intCast(inc);
                        }
                    }
                    return;
                },
                .settings => {
                    if (!frame.flags.ack) {
                        applyPeerSettings(self.client, frame.payload);
                        try self.client.writeSingleFrame(.settings, 0, .{ .ack = true }, &.{});
                    }
                    return;
                },
                .ping => {
                    if (!frame.flags.ack) {
                        try self.client.writeSingleFrame(.ping, 0, .{ .ack = true }, frame.payload);
                    }
                    return;
                },
                .goaway => return error.PeerGoaway,
                else => {},
            }
            if (frame.stream_id != self.stream_id) return;
            switch (frame.frame_type) {
                .data => {
                    try self.recv_buf.appendSlice(self.client.allocator, frame.payload);
                    // Replenish peer's view of our receive window so it can
                    // keep streaming. We accept arbitrary inbound data so the
                    // simplest correct policy is to ACK exactly what we read.
                    if (frame.payload.len > 0) {
                        self.client.sendWindowUpdate(self.stream_id, @intCast(frame.payload.len)) catch {};
                        self.client.sendWindowUpdate(0, @intCast(frame.payload.len)) catch {};
                    }
                },
                .headers => {
                    if (frame.flags.end_stream) self.finished = true;
                    decodeAndLogHeaders(self.client, frame.payload, frame.stream_id, frame.flags.end_stream);
                },
                .rst_stream => {
                    const code: u32 = if (frame.payload.len >= 4)
                        std.mem.readInt(u32, frame.payload[0..4], .big)
                    else
                        0xffffffff;
                    std.log.err("grpc: RST_STREAM stream={d} error_code=0x{x}", .{ self.stream_id, code });
                    return error.StreamReset;
                },
                else => {},
            }
        }
    };

    fn handshake(self: *Client) !void {
        try self.writeAll("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        // Empty SETTINGS: do not advertise INITIAL_WINDOW_SIZE=0 (that deadlocks responses).
        try self.writeFrame(.settings, 0, .{}, &.{});
        const server_settings = try self.readFrame();
        defer self.allocator.free(server_settings.payload);
        if (server_settings.frame_type == .settings and !server_settings.flags.ack) {
            applyPeerSettings(self, server_settings.payload);
        }
        try self.writeFrame(.settings, 0, .{ .ack = true }, &.{});
    }

    /// Parse a SETTINGS frame payload (sequence of (id u16, value u32) entries)
    /// and apply the ones we care about. We only need INITIAL_WINDOW_SIZE (0x4)
    /// to size our per-stream send window; others (MAX_FRAME_SIZE, HEADER_TABLE_SIZE)
    /// are accepted-and-ignored.
    /// Feed an HPACK header block fragment into the client's decoder so the
    /// dynamic table stays in sync, and log each header for diagnostics. If a
    /// `grpc-status` header is observed, stash the numeric value on the client
    /// so callers can surface it as an error.
    fn decodeAndLogHeaders(self: *Client, payload: []const u8, stream_id: u31, end_stream: bool) void {
        const headers = self.hpack_decoder.decode(payload) catch |err| {
            std.log.warn("grpc: HPACK decode failed on stream {d}: {s}", .{ stream_id, @errorName(err) });
            return;
        };
        defer self.hpack_decoder.freeHeaders(headers);
        for (headers) |h| {
            std.log.info("grpc: stream {d} {s}: {s}{s}", .{
                stream_id,
                h.name,
                h.value,
                if (end_stream) " [end_stream]" else "",
            });
            if (std.mem.eql(u8, h.name, "grpc-status")) {
                const v = std.fmt.parseInt(i32, h.value, 10) catch -1;
                self.last_grpc_status = v;
            } else if (std.mem.eql(u8, h.name, "grpc-message")) {
                if (self.last_grpc_message) |old| self.allocator.free(old);
                self.last_grpc_message = self.allocator.dupe(u8, h.value) catch null;
            } else if (std.mem.eql(u8, h.name, ":status")) {
                const v = std.fmt.parseInt(u16, h.value, 10) catch 0;
                self.last_http_status = v;
            }
        }
    }

    /// Send a WINDOW_UPDATE frame for the given stream id (0 = connection-
    /// level). The increment is the number of additional bytes we are willing
    /// to receive. Per RFC 7540 §6.9, the value must be in [1, 2^31-1].
    fn sendWindowUpdate(self: *Client, stream_id: u31, increment: u32) !void {
        if (increment == 0) return;
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, increment & 0x7fffffff, .big);
        try self.writeSingleFrame(.window_update, stream_id, .{}, &payload);
    }

    fn applyPeerSettings(self: *Client, payload: []const u8) void {
        var i: usize = 0;
        while (i + 6 <= payload.len) : (i += 6) {
            const id = std.mem.readInt(u16, payload[i..][0..2], .big);
            const val = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
            if (id == 0x4) {
                // INITIAL_WINDOW_SIZE: applies to streams not yet opened. We
                // don't have any active streams during handshake, so it's safe
                // to just adopt this value.
                self.peer_initial_window = @intCast(val);
            }
        }
    }

    /// Block until our connection-level and per-stream send windows can both
    /// accommodate `need` bytes. We consume incoming non-DATA control frames
    /// (WINDOW_UPDATE, PING, SETTINGS) inline; any DATA frame from the peer
    /// during the send phase of a client-streaming RPC is unexpected per gRPC
    /// (server replies only after end_stream from client), so we just buffer
    /// the bytes on the stream — but since the server hasn't observed our end
    /// of stream yet, treat unexpected DATA as a protocol violation.
    fn awaitSendWindow(self: *Client, need: i64) !void {
        while (self.conn_send_window < need or self.stream_send_window < need) {
            const frame = try self.readFrame();
            defer self.allocator.free(frame.payload);
            switch (frame.frame_type) {
                .window_update => {
                    if (frame.payload.len < 4) return error.InvalidWindowUpdate;
                    const inc = std.mem.readInt(u32, frame.payload[0..4], .big) & 0x7fffffff;
                    if (frame.stream_id == 0) {
                        self.conn_send_window += @intCast(inc);
                    } else if (frame.stream_id == self.sending_stream_id) {
                        self.stream_send_window += @intCast(inc);
                    }
                },
                .settings => {
                    if (!frame.flags.ack) {
                        applyPeerSettings(self, frame.payload);
                        try self.writeSingleFrame(.settings, 0, .{ .ack = true }, &.{});
                    }
                },
                .ping => {
                    if (!frame.flags.ack) {
                        try self.writeSingleFrame(.ping, 0, .{ .ack = true }, frame.payload);
                    }
                },
                .goaway => {
                    const code: u32 = if (frame.payload.len >= 8)
                        std.mem.readInt(u32, frame.payload[4..8], .big)
                    else
                        0xffffffff;
                    std.log.err("grpc: GOAWAY error_code=0x{x} payload_len={d}", .{ code, frame.payload.len });
                    if (frame.payload.len > 8) {
                        std.log.err("grpc: GOAWAY debug_data='{s}'", .{frame.payload[8..]});
                    }
                    return error.PeerGoaway;
                },
                .rst_stream => {
                    const code: u32 = if (frame.payload.len >= 4)
                        std.mem.readInt(u32, frame.payload[0..4], .big)
                    else
                        0xffffffff;
                    // NO_ERROR after the peer has already produced trailers is
                    // benign: the server fully responded and is just closing
                    // its half of the stream. Stop trying to send more DATA
                    // and let the read loop process the buffered response.
                    if (code == 0 and self.pending_response_hpack_end_stream) {
                        self.peer_done_sending_stream = true;
                        return;
                    }
                    std.log.err("grpc: RST_STREAM (while sending) stream={d} error_code=0x{x}", .{ frame.stream_id, code });
                    return error.StreamReset;
                },
                .headers => {
                    if (frame.stream_id == self.sending_stream_id) {
                        try self.pending_response_hpack.appendSlice(self.allocator, frame.payload);
                        if (frame.flags.end_stream) {
                            self.pending_response_hpack_end_stream = true;
                            self.peer_done_sending_stream = true;
                        }
                    }
                    decodeAndLogHeaders(self, frame.payload, frame.stream_id, frame.flags.end_stream);
                    if (self.peer_done_sending_stream) return;
                },
                .data => {
                    // Server may stream response DATA before we finish
                    // sending (especially for short responses). Buffer it so
                    // the ServerStream that runs after the send loop can see
                    // it. Otherwise we'd silently drop the response body.
                    if (frame.stream_id == self.sending_stream_id) {
                        try self.pending_response_data.appendSlice(self.allocator, frame.payload);
                        if (frame.flags.end_stream) {
                            self.peer_done_sending_stream = true;
                            return;
                        }
                    }
                },
                else => {},
            }
        }
    }

    const FrameType = enum(u8) {
        data = 0,
        headers = 1,
        rst_stream = 3,
        settings = 4,
        ping = 6,
        goaway = 7,
        window_update = 8,
        _,
    };

    const Flags = struct {
        end_stream: bool = false,
        end_headers: bool = false,
        ack: bool = false,
    };

    const Frame = struct {
        frame_type: FrameType,
        stream_id: u31,
        flags: Flags,
        payload: []u8,
    };

    /// HTTP/2 default SETTINGS_MAX_FRAME_SIZE per RFC 7540 §6.5.2. We never
    /// advertise a higher value in our SETTINGS frame, so peers may apply this
    /// limit to inbound frames.
    const default_max_frame_size: usize = 16384;

    fn writeFrame(self: *Client, frame_type: FrameType, stream_id: u31, flags: Flags, payload: []const u8) !void {
        // DATA frames may legally be larger than SETTINGS_MAX_FRAME_SIZE only
        // if the peer advertises a higher value. Split DATA payloads into
        // chunks of at most `default_max_frame_size`, propagating end_stream
        // only on the final piece. Other frame types (HEADERS, SETTINGS, ...)
        // we produce are always small enough to fit in one frame.
        if (frame_type == .data) {
            var off: usize = 0;
            while (off < payload.len) {
                const remaining = payload.len - off;
                const take = @min(remaining, default_max_frame_size);
                if (take > 0) try self.awaitSendWindow(@intCast(take));
                // If the peer finished the stream (sent trailers) while we
                // were draining for window, stop pushing more DATA frames.
                if (self.peer_done_sending_stream and stream_id == self.sending_stream_id) return;
                const last = off + take == payload.len;
                try self.writeSingleFrame(
                    .data,
                    stream_id,
                    .{ .end_stream = last and flags.end_stream, .end_headers = false },
                    payload[off .. off + take],
                );
                self.conn_send_window -= @intCast(take);
                if (stream_id != 0 and stream_id == self.sending_stream_id) {
                    self.stream_send_window -= @intCast(take);
                }
                off += take;
            }
            // Handle the corner case of an explicitly empty DATA frame to set
            // end_stream when no payload bytes exist.
            if (payload.len == 0 and flags.end_stream) {
                try self.writeSingleFrame(.data, stream_id, .{ .end_stream = true }, &.{});
            }
            return;
        }
        try self.writeSingleFrame(frame_type, stream_id, flags, payload);
    }

    fn writeSingleFrame(self: *Client, frame_type: FrameType, stream_id: u31, flags: Flags, payload: []const u8) !void {
        var header: [9]u8 = undefined;
        header[0] = @intCast((payload.len >> 16) & 0xff);
        header[1] = @intCast((payload.len >> 8) & 0xff);
        header[2] = @intCast(payload.len & 0xff);
        header[3] = @intFromEnum(frame_type);
        var f: u8 = 0;
        // For SETTINGS and PING, bit 0x01 is ACK; for DATA/HEADERS, it is
        // END_STREAM. Different frame types share the same flag bit.
        if (frame_type == .settings or frame_type == .ping) {
            if (flags.ack) f |= 0x01;
        } else if (flags.end_stream) {
            f |= 0x01;
        }
        if (flags.end_headers) f |= 0x04;
        header[4] = f;
        std.mem.writeInt(u32, header[5..9], stream_id, .big);
        try self.writeAll(&header);
        if (payload.len > 0) try self.writeAll(payload);
    }

    fn readExact(self: *Client, buf: []u8) !void {
        if (self.tls) |tls| {
            try tls.conn.readAll(buf);
            return;
        }
        var off: usize = 0;
        while (off < buf.len) {
            const n = try self.stream.readAtLeast(buf[off..], buf.len - off);
            off += n;
        }
    }

    fn writeAll(self: *Client, data: []const u8) !void {
        if (self.tls) |tls| {
            try tls.conn.writeAll(data);
            return;
        }
        try self.stream.writeAll(data);
    }

    fn readFrame(self: *Client) !Frame {
        var header: [9]u8 = undefined;
        try self.readExact(&header);
        const len = (@as(usize, header[0]) << 16) | (@as(usize, header[1]) << 8) | header[2];
        const frame_type: FrameType = @enumFromInt(header[3]);
        const ack_bit = (frame_type == .settings or frame_type == .ping) and header[4] & 0x01 != 0;
        const flags = Flags{
            .end_stream = !(frame_type == .settings or frame_type == .ping) and header[4] & 0x01 != 0,
            .end_headers = header[4] & 0x04 != 0,
            .ack = ack_bit,
        };
        const stream_id: u31 = @truncate(std.mem.readInt(u32, header[5..9], .big) & 0x7fffffff);
        const payload = try self.allocator.alloc(u8, len);
        errdefer self.allocator.free(payload);
        if (len > 0) try self.readExact(payload);
        return .{ .frame_type = frame_type, .stream_id = stream_id, .flags = flags, .payload = payload };
    }
};

const TlsConnection = struct {
    conn: openssl_tls.Connection,

    fn init(allocator: std.mem.Allocator, stream: std.net.Stream, host: []const u8) !*TlsConnection {
        const host_z = try allocator.allocSentinel(u8, host.len, 0);
        errdefer allocator.free(host_z);
        @memcpy(host_z, host);

        const tls = try allocator.create(TlsConnection);
        errdefer allocator.destroy(tls);
        tls.* = .{
            .conn = try openssl_tls.Connection.init(host_z, stream),
        };
        allocator.free(host_z);
        return tls;
    }

    fn deinit(self: *TlsConnection, allocator: std.mem.Allocator) void {
        self.conn.deinit();
        allocator.destroy(self);
    }
};

fn writeRequestHeaders(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    scheme: []const u8,
    authority: []const u8,
    path: []const u8,
) !void {
    try hpackLiteral(allocator, out, ":method", "POST");
    try hpackLiteral(allocator, out, ":scheme", scheme);
    try hpackLiteral(allocator, out, ":authority", authority);
    try hpackLiteral(allocator, out, ":path", path);
    try hpackLiteral(allocator, out, "content-type", "application/grpc");
    try hpackLiteral(allocator, out, "te", "trailers");
}

fn appendGrpcMessage(list: *std.ArrayList(u8), allocator: std.mem.Allocator, payload: []const u8) !void {
    try list.append(allocator, 0);
    try writeU32Be(list, allocator, @intCast(payload.len));
    try list.appendSlice(allocator, payload);
}

fn writeU32Be(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    try list.appendSlice(allocator, &buf);
}

fn hpackLiteral(allocator: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    try out.append(allocator, 0x00);
    try out.append(allocator, @intCast(name.len));
    try out.appendSlice(allocator, name);
    try out.append(allocator, @intCast(value.len));
    try out.appendSlice(allocator, value);
}

fn takeGrpcMessage(buf: *std.ArrayList(u8), allocator: std.mem.Allocator) !?[]u8 {
    if (buf.items.len < 5) return null;
    const msg_len = std.mem.readInt(u32, buf.items[1..5], .big);
    const total = 5 + msg_len;
    if (buf.items.len < total) return null;
    const msg = try allocator.dupe(u8, buf.items[5..total]);
    _ = try buf.replaceRange(allocator, 0, total, &.{});
    return msg;
}

fn extractGrpcMessage(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len < 5) return error.InvalidGrpcMessage;
    const msg_len = std.mem.readInt(u32, data[1..5], .big);
    if (data.len < 5 + msg_len) return error.InvalidGrpcMessage;
    return try allocator.dupe(u8, data[5 .. 5 + msg_len]);
}

test "take multiple grpc messages from buffer" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(allocator);
    try appendGrpcMessage(&buf, allocator, "first");
    try appendGrpcMessage(&buf, allocator, "second");

    const first = (try takeGrpcMessage(&buf, allocator)).?;
    defer allocator.free(first);
    try std.testing.expectEqualStrings("first", first);

    const second = (try takeGrpcMessage(&buf, allocator)).?;
    defer allocator.free(second);
    try std.testing.expectEqualStrings("second", second);

    try std.testing.expect((try takeGrpcMessage(&buf, allocator)) == null);
}

test "extract single grpc message" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(allocator);
    try appendGrpcMessage(&buf, allocator, "payload");

    const msg = try extractGrpcMessage(allocator, buf.items);
    defer allocator.free(msg);
    try std.testing.expectEqualStrings("payload", msg);
}
