const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/lock/types.pb.zig");

test "lock marshal stable round-trip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const oid_val = try allocator.dupe(u8, &[_]u8{1});
    var msg: pb.Lock = .{};
    try msg.members.append(allocator, .{ .value = oid_val });
    defer msg.deinit(allocator);

    try marshal_stable.testRoundTrip(pb.Lock, allocator, msg);
}
