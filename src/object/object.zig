const std = @import("std");
const checksum = @import("../checksum/checksum.zig");

pub const Type = enum(u8) {
    regular = 0,
    tombstone = 1,
    storage_group = 2,
    lock = 3,
    link = 4,
};

pub const Attribute = struct {
    key: []const u8,
    value: []const u8,
};

pub const Object = struct {
    container_id: [32]u8 = [_]u8{0} ** 32,
    owner: []const u8 = "",
    payload: []const u8 = "",
    object_type: Type = .regular,
    attributes: []const Attribute = &.{},
    payload_checksum: ?checksum.Checksum = null,
};

pub const attr_name = "Name";
pub const attr_filename = "FileName";
pub const attr_path = "FilePath";
pub const attr_timestamp = "Timestamp";
pub const attr_content_type = "Content-Type";

pub fn calcID(obj: Object) [32]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(obj.payload, &hash, .{});
    return hash;
}

test "object id is stable for same payload" {
    const a = calcID(.{ .payload = "x" });
    const b = calcID(.{ .payload = "x" });
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "well-known object attributes remain stable" {
    try std.testing.expectEqualStrings("Name", attr_name);
    try std.testing.expectEqualStrings("FileName", attr_filename);
}
