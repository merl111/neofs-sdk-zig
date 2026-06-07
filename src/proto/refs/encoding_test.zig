const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/refs/types.pb.zig");

test "version marshal stable round-trip" {
    const allocator = std.testing.allocator;

    const msg: pb.Version = .{ .major = 1, .minor = 2 };
    try marshal_stable.testRoundTrip(pb.Version, allocator, msg);
}
