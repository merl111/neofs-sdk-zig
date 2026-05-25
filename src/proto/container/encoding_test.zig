const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/container/types.pb.zig");

test "attribute marshal stable round-trip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const msg: pb.Container.Attribute = .{ .key = "k", .value = "v" };
    try marshal_stable.testRoundTrip(pb.Container.Attribute, allocator, msg);
}
