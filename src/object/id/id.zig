const std = @import("std");

pub const ID = [32]u8;

pub fn fromMarshaledHeader(data: []const u8) ID {
    var out: ID = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

pub const Address = struct {
    container_id: [32]u8,
    object_id: [32]u8,
};
