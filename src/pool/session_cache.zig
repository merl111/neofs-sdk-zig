const std = @import("std");
const clock = @import("../util/clock.zig");
const session_mod = @import("../session/token.zig");
const session_v2 = @import("../session/v2/token.zig");

pub const SessionCache = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(Entry),
    max_size: usize,
    current_epoch: u64 = 0,

    const Entry = struct {
        version: u8,
        token_v1: session_mod.Token,
        token_v2: session_v2.Token,
    };

    pub fn init(allocator: std.mem.Allocator, max_size: usize) SessionCache {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(Entry).init(allocator),
            .max_size = max_size,
        };
    }

    pub fn deinit(self: *SessionCache) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();
    }

    pub fn getV1(self: *SessionCache, key: []const u8) ?session_mod.Token {
        const entry = self.entries.get(key) orelse return null;
        if (entry.version != 1) return null;
        if (entry.token_v1.exp_epoch <= self.current_epoch + 1) {
            const removed = self.entries.fetchRemove(key) orelse return null;
            self.allocator.free(removed.key);
            return null;
        }
        return entry.token_v1;
    }

    pub fn getV2(self: *SessionCache, key: []const u8) ?session_v2.Token {
        const entry = self.entries.get(key) orelse return null;
        if (entry.version != 2) return null;
        const now = @as(u64, @intCast(clock.timestamp()));
        if (entry.token_v2.exp <= now) {
            const removed = self.entries.fetchRemove(key) orelse return null;
            self.allocator.free(removed.key);
            return null;
        }
        return entry.token_v2;
    }

    pub fn putV1(self: *SessionCache, owned_key: []u8, token: session_mod.Token) !void {
        try self.putOwned(owned_key, .{ .version = 1, .token_v1 = token, .token_v2 = undefined });
    }

    pub fn putV2(self: *SessionCache, owned_key: []u8, token: session_v2.Token) !void {
        try self.putOwned(owned_key, .{ .version = 2, .token_v1 = undefined, .token_v2 = token });
    }

    fn putOwned(self: *SessionCache, owned_key: []u8, entry: Entry) !void {
        if (self.entries.fetchRemove(owned_key)) |kv| {
            self.allocator.free(kv.key);
        } else if (self.entries.count() >= self.max_size) {
            var it = self.entries.iterator();
            if (it.next()) |old| {
                self.allocator.free(old.key_ptr.*);
                _ = self.entries.remove(old.key_ptr.*);
            }
        }
        try self.entries.put(owned_key, entry);
    }

    fn put(self: *SessionCache, key: []const u8, entry: Entry) !void {
        const owned = try self.allocator.dupe(u8, key);
        try self.putOwned(owned, entry);
    }

    pub fn deleteByPrefix(self: *SessionCache, prefix: []const u8) void {
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer {
            for (to_remove.items) |k| self.allocator.free(k);
            to_remove.deinit(self.allocator);
        }
        var it = self.entries.keyIterator();
        while (it.next()) |key| {
            if (std.mem.startsWith(u8, key.*, prefix)) {
                to_remove.append(self.allocator, key.*) catch continue;
            }
        }
        for (to_remove.items) |k| _ = self.entries.remove(k);
    }

    pub fn purge(self: *SessionCache) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.entries.clearRetainingCapacity();
    }

    pub fn updateEpoch(self: *SessionCache, epoch: u64) void {
        if (epoch > self.current_epoch) self.current_epoch = epoch;
    }
};

test {
    _ = @import("session_cache_test.zig");
}
