const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/object/types.pb.zig");

test "range marshal stable round-trip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const msg: pb.Range = .{ .offset = 1, .length = 2 };
    try marshal_stable.testRoundTrip(pb.Range, allocator, msg);
}
