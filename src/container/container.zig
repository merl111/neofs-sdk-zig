const std = @import("std");
const user = @import("../user/id.zig");
const base58 = @import("../crypto/base58.zig");

pub const Container = struct {
    allocator: std.mem.Allocator,
    owner: []u8,
    nonce: []u8,
    attributes: std.StringHashMap([]u8),

    /// Copies `owner` and `nonce` so the returned container owns its memory.
    pub fn init(allocator: std.mem.Allocator, owner: []const u8, nonce: []const u8) !Container {
        const owner_copy = try allocator.dupe(u8, owner);
        errdefer allocator.free(owner_copy);
        const nonce_copy = try allocator.dupe(u8, nonce);
        return .{
            .allocator = allocator,
            .owner = owner_copy,
            .nonce = nonce_copy,
            .attributes = std.StringHashMap([]u8).init(allocator),
        };
    }

    /// Insert an attribute. The Container takes ownership of both `key` and `value`.
    pub fn putAttributeOwned(self: *Container, key: []u8, value: []u8) !void {
        try self.attributes.put(key, value);
    }

    /// Copy `key` and `value` into the Container's allocator.
    pub fn putAttribute(self: *Container, key: []const u8, value: []const u8) !void {
        const k = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(k);
        const v = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(v);
        try self.attributes.put(k, v);
    }

    pub fn deinit(self: *Container) void {
        var it = self.attributes.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.attributes.deinit();
        self.allocator.free(self.owner);
        self.allocator.free(self.nonce);
    }

    /// Encode `owner` (raw user.ID bytes) as a Neo N3 base58check address
    /// (e.g. `Nfoo...`). Caller frees.
    pub fn ownerAddress(self: Container, allocator: std.mem.Allocator) ![]u8 {
        if (self.owner.len != user.IDSize) return error.InvalidOwnerLength;
        return base58.encode(allocator, self.owner);
    }
};
