const std = @import("std");
const marshal_stable = @import("../../testutil/marshal_stable.zig");
const pb = @import("../gen/acl/types.pb.zig");

test "token lifetime marshal stable round-trip" {
    const allocator = std.testing.allocator;

    const msg: pb.BearerToken.Body.TokenLifetime = .{ .exp = 1, .nbf = 2, .iat = 3 };
    try marshal_stable.testRoundTrip(pb.BearerToken.Body.TokenLifetime, allocator, msg);
}
