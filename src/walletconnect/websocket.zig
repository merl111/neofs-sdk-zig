const std = @import("std");
const csprng = @import("../crypto/csprng.zig");

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: []u8,
    connected: bool = false,
    host: []u8 = &.{},
    path_query: []u8 = &.{},
    auth_bearer: ?[]u8 = null,
    stream: ?std.Io.net.Stream = null,
    ssl: ?*c.SSL = null,
    ssl_ctx: ?*c.SSL_CTX = null,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, endpoint: []const u8, auth_bearer: ?[]u8) !Client {
        const ep = try allocator.dupe(u8, endpoint);
        const parsed = try std.Uri.parse(ep);
        const host = parsed.host orelse return error.InvalidEndpoint;
        const host_bytes = try allocator.dupe(u8, host.percent_encoded);
        const path = if (parsed.path.percent_encoded.len == 0) "/" else parsed.path.percent_encoded;
        const path_query = if (parsed.query) |q|
            try std.fmt.allocPrint(allocator, "{s}?{s}", .{ path, q.percent_encoded })
        else
            try allocator.dupe(u8, path);
        const bearer = auth_bearer;
        return .{
            .allocator = allocator,
            .io = io,
            .endpoint = ep,
            .connected = false,
            .host = host_bytes,
            .path_query = path_query,
            .auth_bearer = bearer,
        };
    }

    pub fn deinit(self: *Client) void {
        if (self.ssl) |ssl| {
            _ = c.SSL_shutdown(ssl);
            _ = c.SSL_free(ssl);
        }
        if (self.ssl_ctx) |ctx| _ = c.SSL_CTX_free(ctx);
        if (self.stream) |s| s.close(self.io);
        self.allocator.free(self.endpoint);
        self.allocator.free(self.host);
        self.allocator.free(self.path_query);
        if (self.auth_bearer) |auth| self.allocator.free(auth);
        self.* = undefined;
    }

    pub fn connect(self: *Client) !void {
        if (self.connected) return;
        if (!std.mem.startsWith(u8, self.endpoint, "wss://")) return error.UnsupportedScheme;

        const host_name = try std.Io.net.HostName.init(self.host);
        self.stream = try std.Io.net.HostName.connect(host_name, self.io, 443, .{ .mode = .stream });
        errdefer if (self.stream) |s| {
            s.close(self.io);
            self.stream = null;
        };

        _ = c.OPENSSL_init_ssl(c.OPENSSL_INIT_LOAD_SSL_STRINGS | c.OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);
        const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.TlsInitializationFailed;
        errdefer _ = c.SSL_CTX_free(ctx);
        if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) return error.TlsInitializationFailed;
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);

        const ssl = c.SSL_new(ctx) orelse return error.TlsInitializationFailed;
        errdefer _ = c.SSL_free(ssl);
        if (c.SSL_set_fd(ssl, @intCast(self.stream.?.socket.handle)) != 1) return error.TlsInitializationFailed;

        const host_z = try self.allocator.dupeZ(u8, self.host);
        defer self.allocator.free(host_z);
        if (c.SSL_set_tlsext_host_name(ssl, host_z.ptr) != 1) return error.TlsInitializationFailed;
        if (c.SSL_connect(ssl) != 1) return error.TlsInitializationFailed;

        try self.handshakeWith(ssl);
        self.ssl_ctx = ctx;
        self.ssl = ssl;
        self.connected = true;
    }

    pub fn sendText(self: *Client, payload: []const u8) !void {
        if (!self.connected) return error.NotConnected;
        try self.sendFrame(0x1, payload);
    }

    pub fn recvText(self: *Client, allocator: std.mem.Allocator) ![]u8 {
        if (!self.connected) return error.NotConnected;
        return self.recvFrame(allocator);
    }

    pub fn recvTextWithTimeout(self: *Client, allocator: std.mem.Allocator, timeout_ms: u64) !?[]u8 {
        if (!self.connected) return error.NotConnected;
        const fd = c.SSL_get_fd(self.ssl.?);
        if (fd < 0) return error.NotConnected;

        var pollfds = [_]std.posix.pollfd{.{
            .fd = fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&pollfds, @intCast(timeout_ms)) catch return null;
        if (ready == 0) return null;
        const msg = try self.recvText(allocator);
        return msg;
    }

    fn handshakeWith(self: *Client, ssl: *c.SSL) !void {
        var key_raw: [16]u8 = undefined;
        csprng.randomBytes(&key_raw);
        const key_size = std.base64.standard.Encoder.calcSize(key_raw.len);
        var key_b64: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(key_b64[0..key_size], &key_raw);

        const req = if (self.auth_bearer) |auth|
            try std.fmt.allocPrint(self.allocator,
                "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: neofs-sdk-zig-walletconnect/0.1\r\nOrigin: https://neon.coz.io\r\nAuthorization: Bearer {s}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: irn\r\n\r\n",
                .{ self.path_query, self.host, auth, key_b64[0..key_size] })
        else
            try std.fmt.allocPrint(self.allocator,
                "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: neofs-sdk-zig-walletconnect/0.1\r\nOrigin: https://neon.coz.io\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: irn\r\n\r\n",
                .{ self.path_query, self.host, key_b64[0..key_size] });
        defer self.allocator.free(req);
        try writeAllSsl(ssl, req);

        const response = try readHttpResponseSsl(ssl, self.allocator);
        defer self.allocator.free(response);
        if (std.mem.indexOf(u8, response, " 101 ") == null) {
            const end = @min(response.len, 512);
            std.log.err("websocket handshake failed: {s}", .{response[0..end]});
            return error.WebSocketHandshakeFailed;
        }
        const accept = try expectedAccept(self.allocator, key_b64[0..key_size]);
        defer self.allocator.free(accept);
        if (std.mem.indexOf(u8, response, accept) == null) return error.WebSocketHandshakeFailed;
    }

    fn sendFrame(self: *Client, opcode: u8, payload: []const u8) !void {
        if (payload.len > 0xFFFF) return error.MessageTooLarge;
        var header: [14]u8 = undefined;
        var off: usize = 0;
        header[off] = 0x80 | (opcode & 0x0F);
        off += 1;

        if (payload.len < 126) {
            header[off] = 0x80 | @as(u8, @intCast(payload.len));
            off += 1;
        } else {
            header[off] = 0x80 | 126;
            off += 1;
            const plen: u16 = @intCast(payload.len);
            header[off] = @intCast(plen >> 8);
            header[off + 1] = @intCast(plen & 0xff);
            off += 2;
        }

        var mask: [4]u8 = undefined;
        csprng.randomBytes(&mask);
        @memcpy(header[off .. off + 4], &mask);
        off += 4;
        try self.writeAll(header[0..off]);

        var masked = try self.allocator.alloc(u8, payload.len);
        defer self.allocator.free(masked);
        for (payload, 0..) |b, i| masked[i] = b ^ mask[i % 4];
        try self.writeAll(masked);
    }

    fn recvFrame(self: *Client, allocator: std.mem.Allocator) ![]u8 {
        var message: std.ArrayList(u8) = .empty;
        defer message.deinit(allocator);

        while (true) {
            var h: [2]u8 = undefined;
            try self.readAll(&h);
            const fin = (h[0] & 0x80) != 0;
            const opcode = h[0] & 0x0F;

            var len: usize = h[1] & 0x7F;
            const masked = (h[1] & 0x80) != 0;
            if (len == 126) {
                var b: [2]u8 = undefined;
                try self.readAll(&b);
                len = std.mem.readInt(u16, &b, .big);
            } else if (len == 127) {
                var b: [8]u8 = undefined;
                try self.readAll(&b);
                len = @intCast(std.mem.readInt(u64, &b, .big));
            }

            var mask: [4]u8 = .{ 0, 0, 0, 0 };
            if (masked) try self.readAll(&mask);

            const payload = try allocator.alloc(u8, len);
            errdefer allocator.free(payload);
            try self.readAll(payload);
            if (masked) {
                for (payload, 0..) |*b, i| b.* ^= mask[i % 4];
            }

            switch (opcode) {
                0x8 => {
                    allocator.free(payload);
                    return error.ConnectionClosed;
                },
                0x9 => {
                    // Reply to relay pings and keep waiting for text data.
                    try self.sendFrame(0xA, payload);
                    allocator.free(payload);
                    continue;
                },
                0xA => {
                    allocator.free(payload);
                    continue;
                },
                0x1, 0x0 => {
                    try message.appendSlice(allocator, payload);
                    allocator.free(payload);
                    if (fin) return message.toOwnedSlice(allocator);
                    continue;
                },
                else => {
                    // Ignore binary/unknown frames rather than failing the session.
                    allocator.free(payload);
                    continue;
                },
            }
        }
    }

    fn readHttpResponseSsl(ssl: *c.SSL, allocator: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(allocator);
        while (true) {
            var byte: [1]u8 = undefined;
            try readAllSsl(ssl, &byte);
            try out.append(allocator, byte[0]);
            if (out.items.len >= 4 and std.mem.eql(u8, out.items[out.items.len - 4 ..], "\r\n\r\n")) break;
            if (out.items.len > 16 * 1024) return error.HeaderTooLarge;
        }

        const header_end = out.items.len;
        const headers = out.items[0..header_end];
        const content_length = parseContentLength(headers) orelse return out.toOwnedSlice(allocator);
        if (content_length == 0) return out.toOwnedSlice(allocator);

        try out.resize(allocator, header_end + content_length);
        try readAllSsl(ssl, out.items[header_end..]);
        return out.toOwnedSlice(allocator);
    }

    fn readAll(self: *Client, out: []u8) !void {
        return readAllSsl(self.ssl.?, out);
    }

    fn writeAll(self: *Client, data: []const u8) !void {
        return writeAllSsl(self.ssl.?, data);
    }
};

fn parseContentLength(headers: []const u8) ?usize {
    var it = std.mem.splitSequence(u8, headers, "\r\n");
    while (it.next()) |line| {
        if (line.len == 0) break;
        if (line.len >= 15 and std.ascii.eqlIgnoreCase(line[0..15], "content-length:")) {
            const value = std.mem.trim(u8, line[15..], " \t");
            return std.fmt.parseInt(usize, value, 10) catch null;
        }
    }
    return null;
}

fn readAllSsl(ssl: *c.SSL, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = c.SSL_read(ssl, out.ptr + off, @intCast(out.len - off));
        if (n <= 0) return error.EndOfStream;
        off += @intCast(n);
    }
}

fn writeAllSsl(ssl: *c.SSL, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const n = c.SSL_write(ssl, data.ptr + off, @intCast(data.len - off));
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }
}

fn expectedAccept(allocator: std.mem.Allocator, key: []const u8) ![]u8 {
    const concat = try std.fmt.allocPrint(allocator, "{s}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", .{key});
    defer allocator.free(concat);
    var sha1: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(concat, &sha1, .{});
    const out_len = std.base64.standard.Encoder.calcSize(sha1.len);
    const out = try allocator.alloc(u8, out_len);
    _ = std.base64.standard.Encoder.encode(out, &sha1);
    return out;
}

