const std = @import("std");
const tz = @import("../tzhash/root.zig");

pub const Type = enum(u32) {
    unknown = 0,
    tillich_zemor = 1,
    sha256 = 2,
};

pub const Checksum = struct {
    typ: Type,
    value: []const u8,

    pub fn init(typ: Type, value: []const u8) Checksum {
        return .{ .typ = typ, .value = value };
    }
};

pub fn newFromData(allocator: std.mem.Allocator, typ: Type, data: []const u8) !Checksum {
    return switch (typ) {
        .sha256 => blk: {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
            break :blk .{ .typ = .sha256, .value = try allocator.dupe(u8, &digest) };
        },
        .tillich_zemor => blk: {
            const digest = tz.sum(data);
            break :blk .{ .typ = .tillich_zemor, .value = try allocator.dupe(u8, &digest) };
        },
        else => error.UnsupportedChecksumType,
    };
}

test "checksum sha256" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const c = try newFromData(allocator, .sha256, "abc");
    defer allocator.free(c.value);
    try std.testing.expectEqual(Type.sha256, c.typ);
}
