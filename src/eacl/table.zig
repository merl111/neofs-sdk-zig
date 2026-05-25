const std = @import("std");
const user = @import("../user/id.zig");

pub const Action = enum(u8) {
    unspecified = 0,
    allow = 1,
    deny = 2,
};

pub const Operation = enum(u8) {
    unspecified = 0,
    get = 1,
    head = 2,
    put = 3,
    delete = 4,
    search = 5,
    range = 6,
    range_hash = 7,
};

pub const Role = enum(u8) {
    unspecified = 0,
    user = 1,
    system = 2,
    others = 3,
};

pub const FilterHeaderType = enum(u8) {
    unspecified = 0,
    request = 1,
    object = 2,
    service = 3,
};

pub const Match = enum(u8) {
    unspecified = 0,
    string_equal = 1,
    string_not_equal = 2,
    not_present = 3,
    num_gt = 4,
    num_ge = 5,
    num_lt = 6,
    num_le = 7,
};

pub const Filter = struct {
    header_type: FilterHeaderType = .object,
    key: []const u8,
    value: []const u8,
    match: Match = .string_equal,
};

pub const Target = struct {
    role: Role = .others,
    keys: []const []const u8 = &.{},
    accounts: []const [user.IDSize]u8 = &.{},
};

pub const Record = struct {
    action: Action,
    operation: Operation,
    targets: []const Target = &.{},
    filters: []const Filter = &.{},
};

pub const Header = struct {
    key: []const u8,
    value: []const u8,
};

pub const HeaderSource = struct {
    object: []const Header = &.{},
    request: []const Header = &.{},

    pub fn headersOfType(self: HeaderSource, ht: FilterHeaderType) struct { headers: []const Header, ok: bool } {
        return switch (ht) {
            .object => .{ .headers = self.object, .ok = true },
            .request => .{ .headers = self.request, .ok = true },
            else => .{ .headers = &.{}, .ok = false },
        };
    }
};

pub const ValidationUnit = struct {
    role: Role = .others,
    operation: Operation = .unspecified,
    hdr_src: HeaderSource = .{},
    sender_key: ?[]const u8 = null,
    account: ?[user.IDSize]u8 = null,
    table: *const Table,
};

pub const Table = struct {
    allocator: std.mem.Allocator,
    container_id: [32]u8 = [_]u8{0} ** 32,
    records: std.ArrayList(Record),

    pub fn init(allocator: std.mem.Allocator) Table {
        return .{
            .allocator = allocator,
            .records = .{},
        };
    }

    pub fn deinit(self: *Table) void {
        self.records.deinit(self.allocator);
    }

    pub fn setRecords(self: *Table, records: []const Record) !void {
        try self.records.appendSlice(self.allocator, records);
    }
};

test "record supports targets and filters" {
    const rec: Record = .{
        .action = .allow,
        .operation = .get,
        .targets = &.{.{ .role = .user, .keys = &.{"pub"} }},
        .filters = &.{.{ .key = "Name", .value = "img", .match = .string_equal }},
    };
    try std.testing.expectEqual(@as(usize, 1), rec.filters.len);
    try std.testing.expectEqual(Role.user, rec.targets[0].role);
}

test {
    _ = @import("validator_test.zig");
}
