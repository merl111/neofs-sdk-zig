const std = @import("std");
const table = @import("table.zig");
const validator = @import("validator.zig");

fn checkAction(expected: table.Action, matched: bool, got: struct { action: table.Action, matched: bool }) !void {
    try std.testing.expect(matched);
    try std.testing.expect(got.matched);
    try std.testing.expectEqual(expected, got.action);
}

fn checkDefault(got: struct { action: table.Action, matched: bool }) !void {
    try std.testing.expect(!got.matched);
    try std.testing.expectEqual(table.Action.allow, got.action);
}

fn checkIgnored(expected: table.Action, got: struct { action: table.Action, matched: bool }) !void {
    try std.testing.expect(!got.matched);
    try std.testing.expectEqual(expected, got.action);
}

test "filter match simple headers" {
    const tgt = table.Target{ .role = .others };
    const records = [_]table.Record{
        .{ .action = .deny, .operation = .unspecified, .targets = &.{tgt}, .filters = &.{
            .{ .header_type = .object, .key = "a", .value = "xxx", .match = .string_equal },
        }},
        .{ .action = .deny, .operation = .unspecified, .targets = &.{tgt}, .filters = &.{
            .{ .header_type = .request, .key = "b", .value = "yyy", .match = .string_not_equal },
        }},
        .{ .action = .allow, .operation = .unspecified, .targets = &.{tgt} },
    };

    var tb = table.Table.init(std.testing.allocator);
    defer tb.deinit();
    try tb.setRecords(&records);

    const v: validator.Validator = .{};
    var hs: table.HeaderSource = .{};
    var unit = table.ValidationUnit{ .role = .others, .table = &tb, .hdr_src = hs };

    try checkAction(.allow, true, try validator.calculateAction(v, unit));

    hs.object = &[_]table.Header{.{ .key = "b", .value = "yyy" }};
    unit.hdr_src = hs;
    try checkAction(.allow, true, try validator.calculateAction(v, unit));

    hs.object = &[_]table.Header{.{ .key = "a", .value = "xxx" }};
    unit.hdr_src = hs;
    try checkAction(.deny, true, try validator.calculateAction(v, unit));

    hs.object = &.{};
    hs.request = &[_]table.Header{.{ .key = "b", .value = "yyy" }};
    unit.hdr_src = hs;
    try checkAction(.allow, true, try validator.calculateAction(v, unit));

    hs.request = &[_]table.Header{.{ .key = "b", .value = "abc" }};
    unit.hdr_src = hs;
    try checkAction(.deny, true, try validator.calculateAction(v, unit));
}

test "all filters must match" {
    const tgt = table.Target{ .role = .others };
    const records = [_]table.Record{
        .{ .action = .deny, .operation = .unspecified, .targets = &.{tgt}, .filters = &.{
            .{ .header_type = .object, .key = "a", .value = "xxx", .match = .string_equal },
            .{ .header_type = .request, .key = "b", .value = "yyy", .match = .string_equal },
        }},
        .{ .action = .allow, .operation = .unspecified, .targets = &.{tgt} },
    };

    var tb = table.Table.init(std.testing.allocator);
    defer tb.deinit();
    try tb.setRecords(&records);

    const v: validator.Validator = .{};
    var hs: table.HeaderSource = .{};
    var unit = table.ValidationUnit{ .role = .others, .table = &tb, .hdr_src = hs };

    hs.object = &[_]table.Header{.{ .key = "a", .value = "xxx" }};
    unit.hdr_src = hs;
    try checkDefault(try validator.calculateAction(v, unit));

    hs.request = &[_]table.Header{.{ .key = "b", .value = "yyy" }};
    unit.hdr_src = hs;
    try checkAction(.deny, true, try validator.calculateAction(v, unit));

    hs.object = &.{};
    unit.hdr_src = hs;
    try checkDefault(try validator.calculateAction(v, unit));
}

test "operation match and deny allow ordering" {
    const tgt = table.Target{ .role = .others };
    const records = [_]table.Record{
        .{ .action = .deny, .operation = .put, .targets = &.{tgt} },
        .{ .action = .allow, .operation = .get, .targets = &.{tgt} },
    };

    var tb = table.Table.init(std.testing.allocator);
    defer tb.deinit();
    try tb.setRecords(&records);

    const v: validator.Validator = .{};
    var unit = table.ValidationUnit{ .role = .others, .table = &tb };

    unit.operation = .put;
    try checkAction(.deny, true, try validator.calculateAction(v, unit));

    unit.operation = .get;
    try checkAction(.allow, true, try validator.calculateAction(v, unit));

    unit.operation = .delete;
    try checkDefault(try validator.calculateAction(v, unit));
}

test "target matches keys and role" {
    const keys = [_][]const u8{ "key0", "key1", "key2" };
    const tgt1 = table.Target{ .role = .user, .keys = keys[0..2] };
    const tgt2 = table.Target{ .role = .others };
    const record = table.Record{ .action = .allow, .operation = .get, .targets = &.{ tgt1, tgt2 } };

    var unit = table.ValidationUnit{ .role = .user, .sender_key = "key0", .table = undefined };
    try std.testing.expect(validator.targetMatches(unit, record));

    unit.sender_key = "key2";
    try std.testing.expect(!validator.targetMatches(unit, record));

    unit = .{ .role = .unspecified, .sender_key = "key1", .table = undefined };
    try std.testing.expect(validator.targetMatches(unit, record));

    unit = .{ .role = .others, .sender_key = "key2", .table = undefined };
    try std.testing.expect(validator.targetMatches(unit, record));

    unit = .{ .role = .system, .sender_key = "key2", .table = undefined };
    try std.testing.expect(!validator.targetMatches(unit, record));
}

test "system role targets are ignored" {
    const tgt = table.Target{ .role = .system };
    const records = [_]table.Record{
        .{ .action = .deny, .operation = .put, .targets = &.{tgt} },
        .{ .action = .deny, .operation = .get, .targets = &.{tgt} },
    };

    var tb = table.Table.init(std.testing.allocator);
    defer tb.deinit();
    try tb.setRecords(&records);

    const v: validator.Validator = .{};
    const unit = table.ValidationUnit{ .role = .system, .operation = .put, .table = &tb };
    try checkIgnored(.allow, try validator.calculateAction(v, unit));
}

test "numeric filter rules" {
    const cases = [_]struct {
        m: table.Match,
        h: []const u8,
        f: []const u8,
        exp_match: bool,
    }{
        .{ .m = .num_gt, .h = "1", .f = "0", .exp_match = true },
        .{ .m = .num_gt, .h = "0", .f = "0", .exp_match = false },
        .{ .m = .num_ge, .h = "0", .f = "0", .exp_match = true },
        .{ .m = .num_lt, .h = "-2", .f = "-1", .exp_match = true },
        .{ .m = .num_le, .h = "0", .f = "1", .exp_match = true },
        .{ .m = .num_gt, .h = "non-decimal", .f = "0", .exp_match = false },
    };

    for (cases) |tc| {
        const filters = [_]table.Filter{
            .{ .header_type = .object, .key = "any_key", .value = tc.f, .match = tc.m },
        };
        const hs = table.HeaderSource{ .object = &[_]table.Header{.{ .key = "any_key", .value = tc.h }} };
        const result = try validator.matchFilters(hs, &filters);
        if (tc.exp_match) {
            try std.testing.expectEqual(@as(@TypeOf(result), .all_matched), result);
        } else {
            try std.testing.expectEqual(@as(@TypeOf(result), .not_matched), result);
        }
    }
}
