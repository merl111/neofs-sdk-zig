const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/link/types.pb.zig");

test "measured object marshal stable round-trip" {
    const allocator = std.testing.allocator;

    const msg: pb.Link.MeasuredObject = .{ .size = 1 };
    try marshal_stable.testRoundTrip(pb.Link.MeasuredObject, allocator, msg);
}
