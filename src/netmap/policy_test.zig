const std = @import("std");
const policy = @import("policy_parser.zig");

const valid_cases = [_][]const u8{
    \\REP 1 IN X
    \\CBF 1
    \\SELECT 2 IN SAME Location FROM * AS X
    ,
    \\REP 1
    \\SELECT 2 IN City FROM Good
    \\FILTER Country EQ RU AS FromRU
    \\FILTER @FromRU AND Rating GT 7 AS Good
    ,
    \\REP 7 IN SPB
    \\SELECT 1 IN City FROM SPBSSD AS SPB
    \\FILTER City EQ SPB AND SSD EQ true OR City EQ SPB AND Rating GE 5 AS SPBSSD
    ,
};

const invalid_cases = [_][]const u8{
    "?REP 1",
    "REP 1 trailing garbage",
};

test "decode multi-line policy string round-trip" {
    const allocator = std.testing.allocator;
    for (valid_cases) |input| {
        var p = try policy.decodeString(allocator, input);
        defer policy.deinitPolicy(&p, allocator);
        const encoded = try policy.encodeString(allocator, p);
        defer allocator.free(encoded);
        try std.testing.expectEqualStrings(input, encoded);
    }
}

test "reject invalid policy syntax" {
    const allocator = std.testing.allocator;
    for (invalid_cases) |input| {
        try std.testing.expectError(policy.ParseError.SyntaxError, policy.decodeString(allocator, input));
    }
}

fn makeValidPolicy(allocator: std.mem.Allocator) !policy.PlacementPolicy {
    var p: policy.PlacementPolicy = .{};
    try p.replicas.append(allocator, .{ .count = 7, .selector = try allocator.dupe(u8, "SEL1") });
    try p.replicas.append(allocator, .{ .count = 8, .selector = try allocator.dupe(u8, "SEL2") });
    try p.selectors.append(allocator, .{
        .name = try allocator.dupe(u8, "SEL1"),
        .count = 2,
        .filter = try allocator.dupe(u8, policy.mainFilterName),
    });
    try p.selectors.append(allocator, .{
        .name = try allocator.dupe(u8, "SEL2"),
        .count = 2,
        .filter = try allocator.dupe(u8, policy.mainFilterName),
    });
    return p;
}

test "verify constraints" {
    const allocator = std.testing.allocator;

    const empty: policy.PlacementPolicy = .{};
    try std.testing.expect(try policy.verifyPolicyErrmsg(allocator, empty) == null);

    var valid_policy = try makeValidPolicy(allocator);
    defer policy.deinitPolicy(&valid_policy, allocator);
    try std.testing.expect(try policy.verifyPolicyErrmsg(allocator, valid_policy) == null);

    var too_many_rep: policy.PlacementPolicy = .{};
    defer too_many_rep.deinit(allocator);
    for (0..257) |_| try too_many_rep.replicas.append(allocator, .{ .count = 1 });
    const rep_err = try policy.verifyPolicyErrmsg(allocator, too_many_rep);
    defer if (rep_err) |m| allocator.free(m);
    try std.testing.expect(rep_err != null);
    try std.testing.expectEqualStrings("more than 256 REP rules", rep_err.?);

    var too_many_objects = try makeValidPolicy(allocator);
    defer policy.deinitPolicy(&too_many_objects, allocator);
    too_many_objects.replicas.items[1].count = 9;
    const obj_err = try policy.verifyPolicyErrmsg(allocator, too_many_objects);
    defer if (obj_err) |m| allocator.free(m);
    try std.testing.expect(obj_err != null);
    try std.testing.expectEqualStrings("invalid REP rule #1: more than 8 object replicas", obj_err.?);

    var missing_sel = try makeValidPolicy(allocator);
    defer policy.deinitPolicy(&missing_sel, allocator);
    allocator.free(missing_sel.selectors.items[1].name);
    missing_sel.selectors.items[1].name = try allocator.dupe(u8, "SEL3");
    const sel_err = try policy.verifyPolicyErrmsg(allocator, missing_sel);
    defer if (sel_err) |m| allocator.free(m);
    try std.testing.expect(sel_err != null);
    try std.testing.expectEqualStrings("invalid REP rule #1: missing selector \"SEL2\"", sel_err.?);

    var too_many_nodes = try makeValidPolicy(allocator);
    defer policy.deinitPolicy(&too_many_nodes, allocator);
    too_many_nodes.selectors.items[1].count = 22;
    const node_err = try policy.verifyPolicyErrmsg(allocator, too_many_nodes);
    defer if (node_err) |m| allocator.free(m);
    try std.testing.expect(node_err != null);
    try std.testing.expectEqualStrings("invalid REP rule #1: more than 64 nodes", node_err.?);
}
