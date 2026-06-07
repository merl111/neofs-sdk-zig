const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/tombstone/types.pb.zig");

test "tombstone marshal stable round-trip" {
    const allocator = std.testing.allocator;

    const msg: pb.Tombstone = .{ .expiration_epoch = 1 };
    try marshal_stable.testRoundTrip(pb.Tombstone, allocator, msg);
}
