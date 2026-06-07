const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/audit/types.pb.zig");

test "data audit result marshal stable round-trip" {
    const allocator = std.testing.allocator;

    const msg: pb.DataAuditResult = .{ .audit_epoch = 1 };
    try marshal_stable.testRoundTrip(pb.DataAuditResult, allocator, msg);
}
