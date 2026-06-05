const std = @import("std");
const wc_crypto = @import("crypto.zig");

/// In-memory WalletConnect relay for unit tests (no WebSocket).
pub const MockRelay = struct {
    allocator: std.mem.Allocator,
    topic_keys: std.StringHashMap([]u8),
    messages: std.StringHashMap(std.ArrayList([]u8)),

    pub fn init(allocator: std.mem.Allocator) MockRelay {
        return .{
            .allocator = allocator,
            .topic_keys = std.StringHashMap([]u8).init(allocator),
            .messages = std.StringHashMap(std.ArrayList([]u8)).init(allocator),
        };
    }

    pub fn deinit(self: *MockRelay) void {
        var key_it = self.topic_keys.iterator();
        while (key_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.topic_keys.deinit();

        var msg_it = self.messages.iterator();
        while (msg_it.next()) |entry| {
            for (entry.value_ptr.items) |payload| self.allocator.free(payload);
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.messages.deinit();
    }

    pub fn registerTopicKey(self: *MockRelay, topic: []const u8, sym_key_hex: []const u8) !void {
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

    pub fn publish(self: *MockRelay, topic: []const u8, payload: []const u8) !void {
        const gop = try self.messages.getOrPut(topic);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.allocator.dupe(u8, topic);
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.append(self.allocator, try self.allocator.dupe(u8, payload));
    }

    pub fn messageCount(self: *MockRelay, topic: []const u8) usize {
        const bucket = self.messages.get(topic) orelse return 0;
        return bucket.items.len;
    }

    pub fn lastMessage(self: *MockRelay, topic: []const u8) ?[]const u8 {
        const bucket = self.messages.get(topic) orelse return null;
        if (bucket.items.len == 0) return null;
        return bucket.items[bucket.items.len - 1];
    }
};

test "mock relay stores published payloads per topic" {
    const allocator = std.testing.allocator;

    var relay = MockRelay.init(allocator);
    defer relay.deinit();

    const sym_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const sym_key_raw = try wc_crypto.decodeHex(allocator, sym_key);
    defer allocator.free(sym_key_raw);
    const topic = try wc_crypto.sha256Hex(allocator, sym_key_raw);
    defer allocator.free(topic);
    try relay.registerTopicKey(topic, sym_key);

    try relay.publish(topic, "{\"method\":\"wc_sessionPropose\"}");
    try relay.publish(topic, "{\"method\":\"wc_sessionSettle\"}");
    try std.testing.expectEqual(@as(usize, 2), relay.messageCount(topic));
    try std.testing.expectEqualStrings("{\"method\":\"wc_sessionSettle\"}", relay.lastMessage(topic).?);
}
