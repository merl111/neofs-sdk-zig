const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/subnet/types.pb.zig");

test "subnet info marshal stable round-trip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const msg: pb.SubnetInfo = .{ .owner = .{ .value = &[_]u8{1} } };
    try marshal_stable.testRoundTrip(pb.SubnetInfo, allocator, msg);
}
