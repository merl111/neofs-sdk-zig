const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/accounting/types.pb.zig");

test "decimal marshal stable round-trip" {
    const allocator = std.testing.allocator;

    const msg: pb.Decimal = .{ .value = 1, .precision = 1 };
    try marshal_stable.testRoundTrip(pb.Decimal, allocator, msg);
}
