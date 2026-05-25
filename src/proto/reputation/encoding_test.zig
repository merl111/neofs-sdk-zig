const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/reputation/types.pb.zig");

test "peer id marshal stable round-trip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const msg: pb.PeerID = .{ .public_key = &[_]u8{1} };
    try marshal_stable.testRoundTrip(pb.PeerID, allocator, msg);
}
