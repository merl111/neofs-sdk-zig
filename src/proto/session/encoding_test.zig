const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/session/types.pb.zig");

test "xheader marshal stable round-trip" {
    const allocator = std.testing.allocator;

    const msg: pb.XHeader = .{ .key = "k", .value = "v" };
    try marshal_stable.testRoundTrip(pb.XHeader, allocator, msg);
}
