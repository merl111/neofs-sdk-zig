const std = @import("std");
const pairing = @import("pairing.zig");
const relay_mod = @import("relay.zig");
const session_mod = @import("session.zig");
const neon = @import("neon.zig");
const wc_crypto = @import("crypto.zig");
const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const default_relay = "wss://relay.walletconnect.com";
pub const default_project_id = "d6101aae216a0aceffa616159a5eb35e";

/// Minimum methods Neon expects (CityOfZion wallet-connect-sdk defaults).
pub const neon_default_methods = [_][]const u8{
    "invokeFunction",
    "testInvoke",
    "signMessage",
    "verifyMessage",
};

pub const SignClient = struct {
    allocator: std.mem.Allocator,
    relay: relay_mod.Relay,
    chain: []u8,
    session: ?session_mod.Session = null,
    pairing_uri: ?[]u8 = null,
    request_id: u64 = 10_000,
    propose_request_id: ?u64 = null,
    proposer_secret_key: ?[X25519.secret_length]u8 = null,
    session_topic: ?[]u8 = null,
    session_sym_key_hex: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator, project_id: []const u8, chain: []const u8) !SignClient {
        const pid = if (project_id.len == 0) default_project_id else project_id;
        const now_ms: u64 = @intCast(std.time.milliTimestamp());
        return .{
            .allocator = allocator,
            .relay = try relay_mod.Relay.init(allocator, default_relay, pid),
            .chain = try allocator.dupe(u8, chain),
            .request_id = now_ms * 1000,
        };
    }

    pub fn deinit(self: *SignClient) void {
        if (self.session) |*s| s.deinit(self.allocator);
        if (self.pairing_uri) |v| self.allocator.free(v);
        if (self.session_topic) |v| self.allocator.free(v);
        if (self.session_sym_key_hex) |v| self.allocator.free(v);
        self.relay.deinit();
        self.allocator.free(self.chain);
        self.* = undefined;
    }

    pub fn takePairingUri(self: *SignClient) ?[]u8 {
        const uri = self.pairing_uri;
        self.pairing_uri = null;
        return uri;
    }

    pub fn connect(self: *SignClient) !void {
        const now: u64 = @intCast(std.time.timestamp());
        const pair = try pairing.newPairing(self.allocator, now, 300);
        defer {
            var p = pair;
            p.deinit(self.allocator);
        }
        if (self.pairing_uri) |v| self.allocator.free(v);
        self.pairing_uri = try pairing.buildUri(self.allocator, pair, &.{ "wc_sessionPropose", "wc_sessionRequest" });
    }

    pub fn beginPairing(self: *SignClient, pairing_topic: []const u8, sym_key_hex: []const u8) !void {
        try self.relay.connect();
        try self.relay.registerTopicKey(pairing_topic, sym_key_hex);
        const sub_id = try self.relay.subscribe(pairing_topic);
        try self.relay.waitForRpcAck(self.allocator, sub_id, 10_000);
        _ = self.relay.fetchMessages(self.allocator, pairing_topic) catch |err| {
            std.log.warn("wc: fetchMessages failed err={s}", .{@errorName(err)});
        };
    }

    pub fn awaitSessionSettle(
        self: *SignClient,
        pairing_topic: []const u8,
        account_hint: ?[]const u8,
        timeout_secs: u64,
    ) !void {
        std.log.info("wc: waiting for session settle on pairing topic {s}", .{pairing_topic});
        const start: u64 = @intCast(std.time.timestamp());
        var last_republished: u64 = start;
        while (true) {
            const now: u64 = @intCast(std.time.timestamp());
            if (now >= start + timeout_secs) return error.SessionSettleTimeout;

            if (self.session == null and now >= last_republished + 30) {
                try self.sendSessionPropose(pairing_topic);
                last_republished = now;
                std.log.info("wc: re-published wc_sessionPropose", .{});
            }

            const raw = try self.relay.recv(self.allocator);
            defer self.allocator.free(raw);
            if (extractRpcMethod(self.allocator, raw)) |method| {
                defer self.allocator.free(method);
                std.log.info("wc: relay message method={s}", .{method});
            } else |_| {}
            if (extractRpcError(self.allocator, raw)) |err_msg| {
                defer self.allocator.free(err_msg);
                std.log.warn("wc: relay/json-rpc error={s}", .{err_msg});
            } else |_| {}
            if (try self.handleSessionProposeResponse(raw)) |session_topic| {
                if (self.session_topic) |old| self.allocator.free(old);
                self.session_topic = session_topic;
                std.log.info("wc: derived session topic {s}, subscribed for settle", .{session_topic});
            }
            const settle_topic = self.session_topic orelse pairing_topic;
            if (try parseSessionSettle(self.allocator, raw, settle_topic, self.chain, account_hint)) |parsed| {
                try self.sendSessionSettleAck(settle_topic, parsed.request_id);
                if (self.session) |*old| old.deinit(self.allocator);
                var session = parsed.session;
                if (session.sym_key_hex == null and self.session_sym_key_hex != null) {
                    session.sym_key_hex = try self.allocator.dupe(u8, self.session_sym_key_hex.?);
                }
                self.session = session;
                std.log.info("wc: session settled topic={s} account={s}", .{ self.session.?.topic, self.session.?.account });
                return;
            }
            std.Thread.sleep(250 * std.time.ns_per_ms);
        }
    }

    pub fn proposePairing(self: *SignClient, pairing_topic: []const u8) !void {
        try self.sendSessionPropose(pairing_topic);
    }

    pub fn settleSession(
        self: *SignClient,
        topic: []const u8,
        account: []const u8,
        methods: []const []const u8,
        expiry: u64,
    ) !void {
        if (self.session) |*old| old.deinit(self.allocator);
        var session = session_mod.Session{
            .topic = try self.allocator.dupe(u8, topic),
            .chain_id = try self.allocator.dupe(u8, self.chain),
            .account = try self.allocator.dupe(u8, account),
            .methods = .{},
            .expiry = expiry,
        };
        errdefer session.deinit(self.allocator);
        for (methods) |m| try session.methods.append(self.allocator, try self.allocator.dupe(u8, m));
        self.session = session;
    }

    pub fn save(self: *SignClient, path: []const u8) !void {
        if (self.session) |*session| {
            if (session.sym_key_hex == null and self.session_sym_key_hex != null) {
                session.sym_key_hex = try self.allocator.dupe(u8, self.session_sym_key_hex.?);
            }
            if (self.session_topic) |topic| {
                if (!std.mem.eql(u8, session.topic, topic)) {
                    self.allocator.free(session.topic);
                    session.topic = try self.allocator.dupe(u8, topic);
                }
            }
        }
        const session = self.session orelse return error.MissingSession;
        try session_mod.saveSession(path, session, self.allocator);
    }

    /// Re-derive session encryption keys and wait for Neon to settle the session.
    pub fn recoverSessionEncryption(
        self: *SignClient,
        pairing_topic: []const u8,
        account_hint: ?[]const u8,
        timeout_secs: u64,
    ) !void {
        try self.sendSessionPropose(pairing_topic);
        const start: i64 = @intCast(std.time.timestamp());
        while (true) {
            const now: i64 = @intCast(std.time.timestamp());
            if (now >= start + @as(i64, @intCast(timeout_secs))) return error.SessionKeyRecoveryTimeout;
            const raw = try self.relay.recv(self.allocator);
            defer self.allocator.free(raw);
            if (try self.handleSessionProposeResponse(raw)) |session_topic| {
                if (self.session_topic) |old| self.allocator.free(old);
                self.session_topic = session_topic;
                std.log.info("wc: derived session topic {s}", .{session_topic});
            }
            if (try self.tryAckSessionSettle(raw, account_hint)) {
                std.log.info("wc: recovered session encryption keys", .{});
                return;
            }
        }
    }

    /// Pull cached relay messages and acknowledge any pending session settle.
    pub fn prepareSessionChannel(self: *SignClient, account_hint: ?[]const u8) !void {
        const session = self.session orelse return error.MissingSession;
        const cached = self.relay.fetchMessages(self.allocator, session.topic) catch |err| {
            std.log.warn("wc: fetchMessages failed err={s}", .{@errorName(err)});
            return;
        };
        if (cached == 0) return;

        var drained: usize = 0;
        while (drained < 12) : (drained += 1) {
            const raw = try self.relay.tryRecv(self.allocator, 500);
            const msg = raw orelse break;
            defer self.allocator.free(msg);
            _ = try self.tryAckSessionSettle(msg, account_hint);
        }
    }

    fn tryAckSessionSettle(self: *SignClient, raw: []const u8, account_hint: ?[]const u8) !bool {
        const session = self.session orelse return false;
        const settle_topic = self.session_topic orelse session.topic;
        const parsed = try parseSessionSettle(self.allocator, raw, settle_topic, self.chain, account_hint) orelse return false;
        defer {
            var s = parsed.session;
            s.deinit(self.allocator);
        }
        try self.sendSessionSettleAck(settle_topic, parsed.request_id);
        std.log.info("wc: acknowledged wc_sessionSettle id={d}", .{parsed.request_id});
        return true;
    }

    pub const InvokeResult = struct {
        txid: ?[]u8 = null,
        raw: []u8,

        pub fn deinit(self: *InvokeResult, allocator: std.mem.Allocator) void {
            if (self.txid) |v| allocator.free(v);
            allocator.free(self.raw);
            self.* = undefined;
        }
    };

    pub fn invokeFunction(
        self: *SignClient,
        invoke_params: anytype,
        timeout_secs: u64,
    ) !InvokeResult {
        const session = self.session orelse return error.MissingSession;
        try self.prepareSessionChannel(session.account);

        const request_id = self.nextRequestID();
        const req_payload = try stringifyAlloc(self.allocator, .{
            .id = request_id,
            .jsonrpc = "2.0",
            .method = "wc_sessionRequest",
            .params = .{
                .request = .{
                    .method = "invokeFunction",
                    .params = invoke_params,
                },
                .chainId = session.chain_id,
            },
        });
        defer self.allocator.free(req_payload);

        var republished = false;
        std.log.info("wc: publishing invokeFunction to Neon", .{});
        try self.relay.publish(session.topic, req_payload, 1108, 300);

        const max_attempts = @max(timeout_secs * 4, 1);
        var attempts: usize = 0;
        while (attempts < max_attempts) : (attempts += 1) {
            const raw = try self.relay.tryRecv(self.allocator, 500);
            if (raw == null) continue;
            defer self.allocator.free(raw.?);
            const msg = raw.?;
            if (try self.tryAckSessionSettle(msg, session.account)) {
                if (!republished) {
                    std.log.info("wc: re-publishing invokeFunction after session settle ack", .{});
                    try self.relay.publish(session.topic, req_payload, 1108, 300);
                    republished = true;
                }
                continue;
            }
            if (try parseInvokeFunctionResponse(self.allocator, msg, request_id)) |result| {
                return result;
            }
        }
        return error.InvokeRequestTimeout;
    }

    /// Default deadline for `signMessage` calls. Generous enough for a human to
    /// review and approve a NeoFS request in Neon while still bounding the wait.
    pub const default_sign_timeout_secs: u64 = 300;

    pub fn signMessage(self: *SignClient, message_hex: []const u8, version: u8) !neon.SignedMessage {
        return self.signMessageWithTimeout(message_hex, version, default_sign_timeout_secs);
    }

    pub fn signMessageWithTimeout(
        self: *SignClient,
        message_hex: []const u8,
        version: u8,
        timeout_secs: u64,
    ) !neon.SignedMessage {
        const session = self.session orelse return error.MissingSession;
        try self.prepareSessionChannel(session.account);

        const request_id = self.nextRequestID();
        const req_payload = try stringifyAlloc(self.allocator, .{
            .id = request_id,
            .jsonrpc = "2.0",
            .method = "wc_sessionRequest",
            .params = .{
                .request = .{
                    .method = "signMessage",
                    .params = .{
                        .message = message_hex,
                        .version = version,
                    },
                },
                .chainId = session.chain_id,
            },
        });
        defer self.allocator.free(req_payload);
        try self.relay.publish(session.topic, req_payload, 1108, 300);

        const max_attempts = @max(timeout_secs * 2, 1);
        var attempts: usize = 0;
        while (attempts < max_attempts) : (attempts += 1) {
            const raw = try self.relay.tryRecv(self.allocator, 500);
            if (raw == null) continue;
            defer self.allocator.free(raw.?);
            const msg = raw.?;
            _ = try self.tryAckSessionSettle(msg, session.account);
            if (try parseSignMessageResponse(self.allocator, msg, request_id)) |signed| {
                return signed;
            }
        }
        return error.SignRequestTimeout;
    }

    fn nextRequestID(self: *SignClient) u64 {
        const id = self.request_id;
        self.request_id += 1;
        return id;
    }

    fn sendSessionPropose(self: *SignClient, pairing_topic: []const u8) !void {
        const proposer_pub = blk: {
            if (self.proposer_secret_key) |sk| {
                const pk = X25519.recoverPublicKey(sk) catch return error.InvalidProposerKey;
                break :blk try hexEncodeAlloc(self.allocator, &pk);
            }
            const kp = X25519.KeyPair.generate();
            self.proposer_secret_key = kp.secret_key;
            break :blk try hexEncodeAlloc(self.allocator, &kp.public_key);
        };
        defer self.allocator.free(proposer_pub);

        const request_id = self.propose_request_id orelse blk: {
            const id = self.nextRequestID();
            self.propose_request_id = id;
            break :blk id;
        };
        const chain = resolveProposalChain(self.chain);
        const expiry: u64 = @as(u64, @intCast(std.time.timestamp())) + 300;
        const payload = try stringifyAlloc(self.allocator, .{
            .id = request_id,
            .jsonrpc = "2.0",
            .method = "wc_sessionPropose",
            .params = .{
                .id = request_id,
                .expiryTimestamp = expiry,
                .requiredNamespaces = .{
                    .neo3 = .{
                        .chains = &.{chain},
                        .methods = &neon_default_methods,
                        .events = &.{},
                    },
                },
                .relays = &.{.{ .protocol = "irn" }},
                .proposer = .{
                    .publicKey = proposer_pub,
                    .metadata = .{
                        .name = "neofs-sdk-zig",
                        .description = "NeoFS Zig SDK",
                        .url = "https://github.com/nspcc-dev/neofs-sdk-zig",
                        .icons = &.{"https://walletconnect.com/walletconnect-logo.png"},
                    },
                },
                .pairingTopic = pairing_topic,
            },
        });
        defer self.allocator.free(payload);
        const preview_len = @min(payload.len, 200);
        std.log.info("wc: propose payload head={s}", .{payload[0..preview_len]});
        std.log.info("wc: publishing wc_sessionPropose id={d} topic={s} chain={s} prompt=true", .{ request_id, pairing_topic, chain });
        try self.relay.publish(pairing_topic, payload, 1100, 300);
    }

    fn sendSessionSettleAck(self: *SignClient, session_topic: []const u8, request_id: u64) !void {
        const payload = try stringifyAlloc(self.allocator, .{
            .id = request_id,
            .jsonrpc = "2.0",
            .result = true,
        });
        defer self.allocator.free(payload);
        std.log.info("wc: sending wc_sessionSettle ack on topic {s}", .{session_topic});
        try self.relay.publish(session_topic, payload, 1103, 300);
    }

    fn handleSessionProposeResponse(self: *SignClient, raw: []const u8) !?[]u8 {
        const request_id = self.propose_request_id orelse return null;
        const secret = self.proposer_secret_key orelse return null;
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{}) catch return null;
        defer parsed.deinit();
        const root = parsed.value;
        if (root != .object) return null;
        const idv = root.object.get("id") orelse return null;
        if (idv != .integer or @as(u64, @intCast(idv.integer)) != request_id) return null;
        if (root.object.get("error")) |err_v| {
            if (err_v == .object) {
                if (err_v.object.get("message")) |msg| {
                    if (msg == .string) std.log.warn("wc: session proposal rejected: {s}", .{msg.string});
                }
            }
            return null;
        }
        const result = root.object.get("result") orelse return null;
        if (result != .object) return null;
        const responder = result.object.get("responderPublicKey") orelse return null;
        if (responder != .string) return null;

        const responder_bytes = try wc_crypto.decodeHex(self.allocator, responder.string);
        defer self.allocator.free(responder_bytes);
        if (responder_bytes.len != X25519.public_length) return error.InvalidResponderPublicKey;
        var responder_raw: [X25519.public_length]u8 = undefined;
        @memcpy(&responder_raw, responder_bytes);
        const shared = try X25519.scalarmult(secret, responder_raw);

        const prk = HkdfSha256.extract("", &shared);
        var sym_key_raw: [32]u8 = undefined;
        HkdfSha256.expand(&sym_key_raw, "", prk);
        const sym_key_hex = try hexEncodeAlloc(self.allocator, &sym_key_raw);
        defer self.allocator.free(sym_key_hex);
        if (self.session_sym_key_hex) |old| self.allocator.free(old);
        self.session_sym_key_hex = try self.allocator.dupe(u8, sym_key_hex);

        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&sym_key_raw, &digest, .{});
        const session_topic = try hexEncodeAlloc(self.allocator, &digest);
        errdefer self.allocator.free(session_topic);

        try self.relay.registerTopicKey(session_topic, sym_key_hex);
        _ = try self.relay.subscribe(session_topic);
        self.propose_request_id = null;
        return session_topic;
    }
};

fn resolveProposalChain(chain: []const u8) []const u8 {
    if (chain.len == 0 or std.mem.eql(u8, chain, "neo3:auto")) return "neo3:mainnet";
    return chain;
}

fn stringifyAlloc(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var w: std.Io.Writer.Allocating = .init(allocator);
    try w.writer.print("{f}", .{std.json.fmt(value, .{})});
    return try w.toOwnedSlice();
}

fn extractRpcMethod(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return error.NoMethod;
    const method = root.object.get("method") orelse return error.NoMethod;
    if (method != .string) return error.NoMethod;
    return allocator.dupe(u8, method.string);
}

fn extractRpcError(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return error.NoError;
    const err_v = root.object.get("error") orelse return error.NoError;
    if (err_v != .object) return error.NoError;
    const msg = err_v.object.get("message") orelse return error.NoError;
    if (msg != .string) return error.NoError;
    return allocator.dupe(u8, msg.string);
}

fn hexEncodeAlloc(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const alphabet = "0123456789abcdef";
    const out = try allocator.alloc(u8, data.len * 2);
    for (data, 0..) |b, i| {
        out[i * 2] = alphabet[(b >> 4) & 0x0f];
        out[i * 2 + 1] = alphabet[b & 0x0f];
    }
    return out;
}

fn isAutoChain(chain_id: []const u8) bool {
    return chain_id.len == 0 or std.mem.eql(u8, chain_id, "neo3:auto");
}

fn chainMatches(chain_id: []const u8, account: []const u8) bool {
    if (isAutoChain(chain_id)) return std.mem.startsWith(u8, account, "neo3:");
    return std.mem.startsWith(u8, account, chain_id);
}

fn chainIdFromAccount(allocator: std.mem.Allocator, account: []const u8) ![]u8 {
    var it = std.mem.splitScalar(u8, account, ':');
    const ns = it.next() orelse return error.InvalidAccount;
    const net = it.next() orelse return error.InvalidAccount;
    return std.fmt.allocPrint(allocator, "{s}:{s}", .{ ns, net });
}

fn parseInvokeFunctionResponse(allocator: std.mem.Allocator, raw: []const u8, request_id: u64) !?SignClient.InvokeResult {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return null;
    const idv = root.object.get("id") orelse return null;
    if (idv != .integer or @as(u64, @intCast(idv.integer)) != request_id) return null;
    if (root.object.get("error")) |err_v| {
        if (err_v == .object) {
            if (err_v.object.get("message")) |msg| {
                if (msg == .string) std.log.warn("wc: invokeFunction rejected: {s}", .{msg.string});
            }
        }
        return error.InvokeRequestRejected;
    }
    const result = root.object.get("result") orelse return null;
    const raw_copy = try allocator.dupe(u8, raw);
    errdefer allocator.free(raw_copy);
    const txid = try extractTxId(allocator, result);
    return .{ .txid = txid, .raw = raw_copy };
}

fn extractTxId(allocator: std.mem.Allocator, result: std.json.Value) !?[]u8 {
    switch (result) {
        .string => |s| return try allocator.dupe(u8, s),
        .object => |obj| {
            inline for (.{ "txid", "transactionId", "hash", "txHash" }) |key| {
                if (obj.get(key)) |v| {
                    switch (v) {
                        .string => |s| return try allocator.dupe(u8, s),
                        else => {},
                    }
                }
            }
            if (obj.get("result")) |inner| return try extractTxId(allocator, inner);
            return null;
        },
        else => return null,
    }
}

fn parseSignMessageResponse(allocator: std.mem.Allocator, raw: []const u8, request_id: u64) !?neon.SignedMessage {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return null;
    const idv = root.object.get("id") orelse return null;
    if (idv != .integer or @as(u64, @intCast(idv.integer)) != request_id) return null;
    const result = root.object.get("result") orelse return null;
    if (result == .string) {
        return parseSignResultString(allocator, result.string);
    }
    if (result != .object) return null;

    const data = result.object.get("data") orelse return null;
    const salt_v = result.object.get("salt");
    const public_key = result.object.get("publicKey") orelse return null;
    const message_hex = result.object.get("messageHex") orelse return null;
    if (data != .string or public_key != .string or message_hex != .string) return null;
    const salt_str: []const u8 = if (salt_v) |sv| switch (sv) {
        .string => sv.string,
        else => return null,
    } else "";
    return .{
        .data = try allocator.dupe(u8, data.string),
        .salt = try allocator.dupe(u8, salt_str),
        .public_key = try allocator.dupe(u8, public_key.string),
        .message_hex = try allocator.dupe(u8, message_hex.string),
    };
}

fn parseSignResultString(allocator: std.mem.Allocator, result: []const u8) !?neon.SignedMessage {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, result, .{}) catch return null;
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return null;
    const data = root.object.get("data") orelse return null;
    const salt_v = root.object.get("salt");
    const public_key = root.object.get("publicKey") orelse return null;
    const message_hex = root.object.get("messageHex") orelse return null;
    if (data != .string or public_key != .string or message_hex != .string) return null;
    const salt_str: []const u8 = if (salt_v) |sv| switch (sv) {
        .string => sv.string,
        else => return null,
    } else "";
    return .{
        .data = try allocator.dupe(u8, data.string),
        .salt = try allocator.dupe(u8, salt_str),
        .public_key = try allocator.dupe(u8, public_key.string),
        .message_hex = try allocator.dupe(u8, message_hex.string),
    };
}

fn parseSessionSettle(
    allocator: std.mem.Allocator,
    raw: []const u8,
    topic: []const u8,
    chain_id: []const u8,
    account_hint: ?[]const u8,
) !?struct { session: session_mod.Session, request_id: u64 } {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return null;
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return null;
    const method = root.object.get("method") orelse return null;
    if (method != .string or !std.mem.eql(u8, method.string, "wc_sessionSettle")) return null;
    const idv = root.object.get("id") orelse return null;
    if (idv != .integer) return null;
    const request_id: u64 = @intCast(idv.integer);
    const params = root.object.get("params") orelse return null;
    if (params != .object) return null;

    const settle = if (params.object.get("session")) |session_obj| session_obj else params;
    if (settle != .object) return null;

    const namespaces = settle.object.get("namespaces") orelse return null;
    if (namespaces != .object) return null;
    const topic_v = settle.object.get("topic") orelse settle.object.get("sessionTopic");
    const session_topic = if (topic_v) |tv|
        switch (tv) {
            .string => tv.string,
            else => topic,
        }
    else
        topic;
    const expiry_v = settle.object.get("expiry");
    const expiry: u64 = if (expiry_v) |e| switch (e) {
        .integer => @intCast(e.integer),
        else => 0,
    } else 0;

    const account = try extractAccount(allocator, namespaces, chain_id, account_hint) orelse return null;
    errdefer allocator.free(account);
    const resolved_chain = try chainIdFromAccount(allocator, account);
    errdefer allocator.free(resolved_chain);
    var methods = try extractMethods(allocator, namespaces, chain_id);
    errdefer {
        for (methods.items) |m| allocator.free(m);
        methods.deinit(allocator);
    }

    var session = session_mod.Session{
        .topic = try allocator.dupe(u8, session_topic),
        .chain_id = resolved_chain,
        .account = account,
        .methods = .empty,
        .expiry = expiry,
    };
    errdefer session.deinit(allocator);
    for (methods.items) |m| {
        try session.methods.append(allocator, m);
    }
    methods.deinit(allocator);
    return .{ .session = session, .request_id = request_id };
}

fn extractAccount(
    allocator: std.mem.Allocator,
    namespaces: std.json.Value,
    chain_id: []const u8,
    account_hint: ?[]const u8,
) !?[]u8 {
    var it = namespaces.object.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* != .object) continue;
        const accounts = entry.value_ptr.object.get("accounts") orelse continue;
        if (accounts != .array) continue;
        for (accounts.array.items) |item| {
            if (item != .string) continue;
            if (!chainMatches(chain_id, item.string)) continue;
            if (account_hint) |hint| {
                if (std.mem.eql(u8, hint, item.string)) return try allocator.dupe(u8, item.string);
                continue;
            }
            return try allocator.dupe(u8, item.string);
        }
    }
    return null;
}

fn extractMethods(
    allocator: std.mem.Allocator,
    namespaces: std.json.Value,
    chain_id: []const u8,
) !std.ArrayListUnmanaged([]u8) {
    var out: std.ArrayListUnmanaged([]u8) = .empty;
    var it = namespaces.object.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* != .object) continue;
        const accounts = entry.value_ptr.object.get("accounts") orelse continue;
        if (accounts != .array) continue;
        var chain_match = false;
        for (accounts.array.items) |item| {
            if (item == .string and chainMatches(chain_id, item.string)) {
                chain_match = true;
                break;
            }
        }
        if (!chain_match) continue;
        const methods = entry.value_ptr.object.get("methods") orelse continue;
        if (methods != .array) continue;
        for (methods.array.items) |m| {
            if (m != .string) continue;
            try out.append(allocator, try allocator.dupe(u8, m.string));
        }
    }
    return out;
}

