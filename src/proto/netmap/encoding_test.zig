const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/netmap/types.pb.zig");

test "replica marshal stable round-trip" {
    const allocator = std.testing.allocator;

    const msg: pb.Replica = .{ .count = 1, .selector = "s" };
    try marshal_stable.testRoundTrip(pb.Replica, allocator, msg);
}
