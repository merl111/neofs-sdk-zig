const std = @import("std");
const ws = @import("websocket.zig");
const base58 = @import("../crypto/base58.zig");
const wc_crypto = @import("crypto.zig");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const Relay = struct {
    const Ed25519 = std.crypto.sign.Ed25519;

    allocator: std.mem.Allocator,
    endpoint: []u8,
    project_id: []u8,
    ws_client: ?ws.Client = null,
    rpc_id: u64 = 10_000_000_000,
    auth_key: Ed25519.KeyPair,
    client_id: []u8,
    topic_keys: std.StringHashMap([]u8),

    pub fn init(allocator: std.mem.Allocator, endpoint: []const u8, project_id: []const u8) !Relay {
        const kp = Ed25519.KeyPair.generate();
        const did = try makeDidKey(allocator, kp);
        const now_ms: u64 = @intCast(std.time.milliTimestamp());
        return .{
            .allocator = allocator,
            .endpoint = try allocator.dupe(u8, endpoint),
            .project_id = try allocator.dupe(u8, project_id),
            .auth_key = kp,
            .client_id = did,
            .topic_keys = std.StringHashMap([]u8).init(allocator),
            .rpc_id = now_ms * 1000,
        };
    }

    pub fn deinit(self: *Relay) void {
        if (self.ws_client) |*client| client.deinit();
        var it = self.topic_keys.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.topic_keys.deinit();
        self.allocator.free(self.endpoint);
        self.allocator.free(self.project_id);
        self.allocator.free(self.client_id);
        self.* = undefined;
    }

    pub fn connect(self: *Relay) !void {
        var attempt: u8 = 0;
        while (attempt < 3) : (attempt += 1) {
            if (attempt > 0) {
                if (self.ws_client) |*client| {
                    client.deinit();
                    self.ws_client = null;
                }
                std.Thread.sleep(@as(u64, attempt) * 500_000_000);
            }

            if (self.ws_client == null) {
                const auth_owned = try self.makeAuthToken();
                errdefer self.allocator.free(auth_owned);
                const auth_enc = try queryEncodeValue(self.allocator, auth_owned);
                defer self.allocator.free(auth_enc);
                const pid_enc = try queryEncodeValue(self.allocator, self.project_id);
                defer self.allocator.free(pid_enc);
                const ua = "irn-1/zig-0.1/linux-unknown/node";
                const ua_enc = try queryEncodeValue(self.allocator, ua);
                defer self.allocator.free(ua_enc);
                const full = if (std.mem.endsWith(u8, self.endpoint, "/"))
                    try std.fmt.allocPrint(self.allocator, "{s}?auth={s}&projectId={s}&ua={s}", .{ self.endpoint, auth_enc, pid_enc, ua_enc })
                else
                    try std.fmt.allocPrint(self.allocator, "{s}/?auth={s}&projectId={s}&ua={s}", .{ self.endpoint, auth_enc, pid_enc, ua_enc });
                defer self.allocator.free(full);
                self.ws_client = try ws.Client.init(self.allocator, full, auth_owned);
            }

            self.ws_client.?.connect() catch |err| {
                if (self.ws_client) |*client| {
                    client.deinit();
                    self.ws_client = null;
                }
                if (attempt + 1 < 3 and err == error.WebSocketHandshakeFailed) continue;
                return err;
            };
            return;
        }
    }

    pub fn subscribe(self: *Relay, topic: []const u8) !u64 {
        const id = self.nextID();
        std.log.info("wc: relay subscribe topic={s} rpc_id={d}", .{ topic, id });
        const payload = try stringifyAlloc(self.allocator, .{
            .id = id,
            .jsonrpc = "2.0",
            .method = "irn_subscribe",
            .params = .{ .topic = topic },
        });
        defer self.allocator.free(payload);
        try self.ws_client.?.sendText(payload);
        return id;
    }

    pub fn waitForRpcAck(self: *Relay, allocator: std.mem.Allocator, request_id: u64, timeout_ms: u64) !void {
        const start_ms: u64 = @intCast(std.time.milliTimestamp());
        while (true) {
            const now_ms: u64 = @intCast(std.time.milliTimestamp());
            if (now_ms >= start_ms + timeout_ms) return error.RpcAckTimeout;
            const raw = try self.recv(allocator);
            defer allocator.free(raw);
            if (rpcResponseMatches(allocator, raw, request_id)) return;
        }
    }

    pub fn fetchMessages(self: *Relay, allocator: std.mem.Allocator, topic: []const u8) !usize {
        const id = self.nextID();
        std.log.info("wc: relay fetchMessages topic={s}", .{topic});
        const payload = try stringifyAlloc(self.allocator, .{
            .id = id,
            .jsonrpc = "2.0",
            .method = "irn_fetchMessages",
            .params = .{ .topic = topic },
        });
        defer self.allocator.free(payload);
        try self.ws_client.?.sendText(payload);
        const start_ms: u64 = @intCast(std.time.milliTimestamp());
        while (true) {
            const now_ms: u64 = @intCast(std.time.milliTimestamp());
            if (now_ms >= start_ms + 5000) return error.RpcAckTimeout;
            const raw = try self.recv(allocator);
            defer allocator.free(raw);
            if (!rpcResponseMatches(allocator, raw, id)) continue;
            const count = try countFetchedMessages(allocator, raw) orelse 0;
            std.log.info("wc: relay fetchMessages cached={d}", .{count});
            return count;
        }
    }

    pub fn tryRecv(self: *Relay, allocator: std.mem.Allocator, timeout_ms: u64) !?[]u8 {
        const raw = try self.ws_client.?.recvTextWithTimeout(allocator, timeout_ms) orelse return null;
        errdefer allocator.free(raw);
        try self.ackSubscriptionIfNeeded(raw);
        if (try decodeSubscriptionMessage(self, allocator, raw)) |decoded| {
            allocator.free(raw);
            return decoded;
        }
        return raw;
    }

    pub fn registerTopicKey(self: *Relay, topic: []const u8, sym_key_hex: []const u8) !void {
        const topic_copy = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(topic_copy);
        const key_copy = try self.allocator.dupe(u8, sym_key_hex);
        errdefer self.allocator.free(key_copy);
        if (self.topic_keys.fetchRemove(topic)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }
        try self.topic_keys.putNoClobber(topic_copy, key_copy);
    }

    pub fn publish(self: *Relay, topic: []const u8, payload: []const u8, tag: u32, ttl: u64) !void {
        const prompt = tag == 1100 or tag == 1108;
        std.log.info("wc: relay publish topic={s} tag={d} ttl={d} prompt={} payload_len={d}", .{ topic, tag, ttl, prompt, payload.len });
        const encrypted_payload = if (self.topic_keys.get(topic)) |sym_key_hex|
            try encryptEnvelopeType0(self.allocator, sym_key_hex, payload)
        else
            try self.allocator.dupe(u8, payload);
        defer self.allocator.free(encrypted_payload);
        const req = if (prompt)
            try stringifyAlloc(self.allocator, .{
                .id = self.nextID(),
                .jsonrpc = "2.0",
                .method = "irn_publish",
                .params = .{
                    .topic = topic,
                    .message = encrypted_payload,
                    .tag = tag,
                    .ttl = ttl,
                    .prompt = true,
                },
            })
        else
            try stringifyAlloc(self.allocator, .{
                .id = self.nextID(),
                .jsonrpc = "2.0",
                .method = "irn_publish",
                .params = .{
                    .topic = topic,
                    .message = encrypted_payload,
                    .tag = tag,
                    .ttl = ttl,
                },
            });
        defer self.allocator.free(req);
        try self.ws_client.?.sendText(req);
    }

    pub fn recv(self: *Relay, allocator: std.mem.Allocator) ![]u8 {
        const raw = try self.ws_client.?.recvText(allocator);
        errdefer allocator.free(raw);
        std.log.info("wc: relay raw recv bytes={d}", .{raw.len});
        if (raw.len > 0) {
            const n = @min(raw.len, 220);
            std.log.info("wc: relay raw recv head={s}", .{raw[0..n]});
        }
        try self.ackSubscriptionIfNeeded(raw);
        if (try decodeSubscriptionMessage(self, allocator, raw)) |decoded| {
            allocator.free(raw);
            std.log.info("wc: relay decoded subscription bytes={d}", .{decoded.len});
            if (decoded.len > 0) {
                const n = @min(decoded.len, 320);
                std.log.info("wc: relay decoded head={s}", .{decoded[0..n]});
            }
            return decoded;
        }
        return raw;
    }

    fn ackSubscriptionIfNeeded(self: *Relay, raw: []const u8) !void {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{}) catch return;
        defer parsed.deinit();
        const root = parsed.value;
        if (root != .object) return;
        const method = root.object.get("method") orelse return;
        if (method != .string or !std.mem.eql(u8, method.string, "irn_subscription")) return;
        const idv = root.object.get("id") orelse return;
        const ack_id: u64 = switch (idv) {
            .integer => @intCast(idv.integer),
            else => return,
        };
        if (root.object.get("params")) |params| {
            if (params == .object) {
                if (params.object.get("data")) |data| {
                    if (data == .object) {
                        if (data.object.get("topic")) |topic_v| {
                            if (topic_v == .string) {
                                const tag_v = data.object.get("tag");
                                const tag: u64 = if (tag_v) |tv| switch (tv) {
                                    .integer => @intCast(tv.integer),
                                    else => 0,
                                } else 0;
                                std.log.info("wc: irn_subscription topic={s} tag={d}", .{ topic_v.string, tag });
                            }
                        }
                    }
                }
            }
        }
        const ack = try stringifyAlloc(self.allocator, .{
            .id = ack_id,
            .jsonrpc = "2.0",
            .result = true,
        });
        defer self.allocator.free(ack);
        std.log.info("wc: ack irn_subscription id={d}", .{ack_id});
        try self.ws_client.?.sendText(ack);
    }

    fn nextID(self: *Relay) u64 {
        const id = self.rpc_id;
        self.rpc_id += 1;
        return id;
    }

    fn makeAuthToken(self: *Relay) ![]u8 {
        const now: u64 = @intCast(std.time.timestamp());
        const sub = try wc_crypto.randomHex(self.allocator, 16);
        defer self.allocator.free(sub);
        const header = try wc_crypto.base64UrlNoPad(self.allocator, "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
        defer self.allocator.free(header);
        const payload_json = try stringifyAlloc(self.allocator, .{
            .iat = now,
            .exp = now + 3600,
            .iss = self.client_id,
            .aud = self.endpoint,
            .sub = sub,
            .act = "client_auth",
        });
        defer self.allocator.free(payload_json);
        const payload = try wc_crypto.base64UrlNoPad(self.allocator, payload_json);
        defer self.allocator.free(payload);
        const signing_input = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ header, payload });
        defer self.allocator.free(signing_input);

        const sig_obj = try self.auth_key.sign(signing_input, null);
        const sig_b64 = try wc_crypto.base64UrlNoPad(self.allocator, &sig_obj.toBytes());
        defer self.allocator.free(sig_b64);
        return std.fmt.allocPrint(self.allocator, "{s}.{s}.{s}", .{ header, payload, sig_b64 });
    }
};

fn rpcResponseMatches(allocator: std.mem.Allocator, raw: []const u8, request_id: u64) bool {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return false;
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return false;
    const idv = root.object.get("id") orelse return false;
    if (idv != .integer or @as(u64, @intCast(idv.integer)) != request_id) return false;
    return root.object.get("result") != null;
}

fn countFetchedMessages(allocator: std.mem.Allocator, raw: []const u8) !?usize {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return null;
    const result = root.object.get("result") orelse return null;
    if (result != .object) return null;
    const messages = result.object.get("messages") orelse return null;
    if (messages != .array) return null;
    return messages.array.items.len;
}

fn decodeSubscriptionMessage(self: *Relay, allocator: std.mem.Allocator, raw: []const u8) !?[]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return null;
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return null;
    const method = root.object.get("method") orelse return null;
    if (method != .string or !std.mem.eql(u8, method.string, "irn_subscription")) return null;
    const params = root.object.get("params") orelse return null;
    if (params != .object) return null;
    const data = params.object.get("data") orelse return null;
    if (data != .object) return null;
    const topic = data.object.get("topic") orelse return null;
    const message = data.object.get("message") orelse return null;
    if (topic != .string or message != .string) return null;

    if (self.topic_keys.get(topic.string)) |sym_key_hex| {
        return decryptEnvelopeType0(allocator, sym_key_hex, message.string) catch |err| {
            std.log.warn("wc: subscription decrypt failed topic={s} err={s}", .{ topic.string, @errorName(err) });
            return null;
        };
    }
    std.log.warn("wc: no topic key registered for subscription topic={s}", .{topic.string});
    return try allocator.dupe(u8, message.string);
}

fn encryptEnvelopeType0(allocator: std.mem.Allocator, sym_key_hex: []const u8, payload: []const u8) ![]u8 {
    const key_raw = try wc_crypto.decodeHex(allocator, sym_key_hex);
    defer allocator.free(key_raw);
    if (key_raw.len != ChaCha20Poly1305.key_length) return error.InvalidSymmetricKey;
    var key: [ChaCha20Poly1305.key_length]u8 = undefined;
    @memcpy(&key, key_raw);

    var nonce: [ChaCha20Poly1305.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    const cipher = try allocator.alloc(u8, payload.len);
    defer allocator.free(cipher);
    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
    ChaCha20Poly1305.encrypt(
        cipher,
        &tag,
        payload,
        "",
        nonce,
        key,
    );

    const framed = try allocator.alloc(u8, 1 + nonce.len + cipher.len + tag.len);
    defer allocator.free(framed);
    framed[0] = 0;
    @memcpy(framed[1 .. 1 + nonce.len], &nonce);
    @memcpy(framed[1 + nonce.len .. 1 + nonce.len + cipher.len], cipher);
    @memcpy(framed[1 + nonce.len + cipher.len ..], &tag);

    const encoded_len = std.base64.standard.Encoder.calcSize(framed.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, framed);
    return encoded;
}

fn decryptEnvelopeType0(allocator: std.mem.Allocator, sym_key_hex: []const u8, encoded: []const u8) ![]u8 {
    const key_raw = try wc_crypto.decodeHex(allocator, sym_key_hex);
    defer allocator.free(key_raw);
    if (key_raw.len != ChaCha20Poly1305.key_length) return error.InvalidSymmetricKey;
    var key: [ChaCha20Poly1305.key_length]u8 = undefined;
    @memcpy(&key, key_raw);

    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, encoded);
    if (decoded.len < 1 + ChaCha20Poly1305.nonce_length + ChaCha20Poly1305.tag_length) return error.InvalidEnvelope;
    if (decoded[0] != 0) return error.UnsupportedEnvelopeType;

    var nonce: [ChaCha20Poly1305.nonce_length]u8 = undefined;
    @memcpy(&nonce, decoded[1 .. 1 + ChaCha20Poly1305.nonce_length]);
    const sealed = decoded[1 + ChaCha20Poly1305.nonce_length ..];
    if (sealed.len < ChaCha20Poly1305.tag_length) return error.InvalidEnvelope;
    const cipher = sealed[0 .. sealed.len - ChaCha20Poly1305.tag_length];
    const tag = sealed[sealed.len - ChaCha20Poly1305.tag_length ..];

    var tag_arr: [ChaCha20Poly1305.tag_length]u8 = undefined;
    @memcpy(&tag_arr, tag);
    const out = try allocator.alloc(u8, cipher.len);
    errdefer allocator.free(out);
    try ChaCha20Poly1305.decrypt(out, cipher, tag_arr, "", nonce, key);
    return out;
}

fn stringifyAlloc(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var w: std.Io.Writer.Allocating = .init(allocator);
    try w.writer.print("{f}", .{std.json.fmt(value, .{})});
    return try w.toOwnedSlice();
}

fn queryEncodeValue(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .{};
    errdefer out.deinit(allocator);
    const hex = "0123456789ABCDEF";
    for (input) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try out.append(allocator, c);
        } else {
            try out.append(allocator, '%');
            try out.append(allocator, hex[(c >> 4) & 0x0f]);
            try out.append(allocator, hex[c & 0x0f]);
        }
    }
    return out.toOwnedSlice(allocator);
}

fn makeDidKey(allocator: std.mem.Allocator, kp: std.crypto.sign.Ed25519.KeyPair) ![]u8 {
    const pub_key = kp.public_key.toBytes();
    var codec: [34]u8 = undefined;
    codec[0] = 0xed;
    codec[1] = 0x01;
    @memcpy(codec[2..], &pub_key);
    const b58 = try base58.encode(allocator, &codec);
    defer allocator.free(b58);
    return std.fmt.allocPrint(allocator, "did:key:z{s}", .{b58});
}

