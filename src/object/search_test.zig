const std = @import("std");
const search = @import("search.zig");
const object_pb = @import("../proto/gen/object/types.pb.zig");
const marshal_stable = @import("../testutil/marshal_stable.zig");

fn toProtoMatch(m: search.Match) object_pb.MatchType {
    return switch (m) {
        .eq => .STRING_EQUAL,
        .ne => .STRING_NOT_EQUAL,
        .prefix => .COMMON_PREFIX,
    };
}

test "search filter encoding preserves key value and match" {
    const allocator = std.testing.allocator;

    const sf = object_pb.SearchFilter{
        .match_type = toProtoMatch(.eq),
        .key = "k1",
        .value = "v1",
    };

    const encoded = try marshal_stable.encodeMessage(object_pb.SearchFilter, allocator, sf);
    defer allocator.free(encoded);

    var decoded = try marshal_stable.decodeMessage(object_pb.SearchFilter, allocator, encoded);
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(object_pb.MatchType.STRING_EQUAL, decoded.match_type);
    try std.testing.expectEqualStrings("k1", decoded.key);
    try std.testing.expectEqualStrings("v1", decoded.value);

    const reencoded = try marshal_stable.encodeMessage(object_pb.SearchFilter, allocator, decoded);
    defer allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, encoded, reencoded);
}

test "search filters list accepts multiple matchers" {
    const allocator = std.testing.allocator;

    var filters = search.Filters.init(allocator);
    defer filters.deinit();
    try filters.add("k1", "v1", .eq);
    try filters.add("k2", "v2", .ne);
    try std.testing.expectEqual(@as(usize, 2), filters.list.items.len);
    try std.testing.expectEqual(search.Match.ne, filters.list.items[1].match);
}
