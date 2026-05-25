const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/storagegroup/types.pb.zig");

test "storage group marshal stable round-trip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const msg: pb.StorageGroup = .{ .validation_data_size = 1 };
    try marshal_stable.testRoundTrip(pb.StorageGroup, allocator, msg);
}
