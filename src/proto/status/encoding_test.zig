const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/status/types.pb.zig");

test "status marshal stable round-trip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const msg: pb.Status = .{ .code = 1, .message = "ok" };
    try marshal_stable.testRoundTrip(pb.Status, allocator, msg);
}
