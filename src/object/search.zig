const std = @import("std");

test {
    _ = @import("search_test.zig");
}

pub const Match = enum {
    eq,
    ne,
    prefix,
};

pub const Filter = struct {
    key: []const u8,
    value: []const u8,
    match: Match,
};

pub const Filters = struct {
    allocator: std.mem.Allocator,
    list: std.ArrayList(Filter),

    pub fn init(allocator: std.mem.Allocator) Filters {
        return .{
            .allocator = allocator,
            .list = .{},
        };
    }

    pub fn deinit(self: *Filters) void {
        self.list.deinit(self.allocator);
    }

    pub fn add(self: *Filters, key: []const u8, value: []const u8, m: Match) !void {
        try self.list.append(self.allocator, .{ .key = key, .value = value, .match = m });
    }
};
