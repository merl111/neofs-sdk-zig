const std = @import("std");
const basic = @import("basic.zig");

const OpsExpected = struct {
    owner: bool = false,
    container: bool = false,
    inner_ring: bool = false,
    others: bool = false,
    bearer: bool = false,
};

fn testOp(v: basic.Basic, op: basic.Op, exp: OpsExpected) !void {
    try std.testing.expectEqual(exp.owner, v.isOpAllowed(op, .owner));
    try std.testing.expectEqual(exp.container, v.isOpAllowed(op, .container));
    try std.testing.expectEqual(exp.inner_ring, v.isOpAllowed(op, .inner_ring));
    try std.testing.expectEqual(exp.others, v.isOpAllowed(op, .others));
    try std.testing.expectEqual(exp.bearer, v.allowedBearerRules(op));
}

test "disable extension and sticky bits" {
    var val: basic.Basic = .{ .value = 0 };
    try std.testing.expect(val.extendable());

    var val2 = val;
    val.disableExtension();
    try std.testing.expect(!val.extendable());
    val2 = basic.Basic.fromBits(val.value);
    try std.testing.expect(!val2.extendable());

    try std.testing.expect(!val.sticky());
    val.makeSticky();
    try std.testing.expect(val.sticky());
}

test "allow bearer rules per operation" {
    var val: basic.Basic = .{ .value = 0 };
    val.allowBearerRules(.object_get);
    try std.testing.expect(val.allowedBearerRules(.object_get));
    try std.testing.expect(!val.allowedBearerRules(.object_put));
}

test "allow op for role" {
    var val: basic.Basic = .{ .value = 0 };
    try std.testing.expect(!val.isOpAllowed(.object_get, .others));
    val.allowOp(.object_get, .others);
    try std.testing.expect(val.isOpAllowed(.object_get, .others));
}

test "public read write preset permissions" {
    const val = basic.Basic.fromBits(basic.public_rw_acl);
    try std.testing.expect(!val.extendable());
    try testOp(val, .object_get, .{
        .owner = true,
        .container = true,
        .inner_ring = true,
        .others = true,
        .bearer = true,
    });
    try testOp(val, .object_put, .{
        .owner = true,
        .container = true,
        .others = true,
        .bearer = true,
    });
    try testOp(val, .object_delete, .{
        .owner = true,
        .others = true,
        .bearer = true,
    });
}

test "private preset denies others" {
    const val = basic.Basic.fromBits(basic.private_acl);
    try testOp(val, .object_get, .{
        .owner = true,
        .container = true,
        .inner_ring = true,
    });
    try testOp(val, .object_put, .{ .owner = true, .container = true });
}
