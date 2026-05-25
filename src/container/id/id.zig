const std = @import("std");

pub const ID = [32]u8;

pub fn fromMarshaledContainer(data: []const u8) ID {
    var out: ID = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

test {
    _ = @import("id_test.zig");
}
