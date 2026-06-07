const std = @import("std");
const hrw = @import("hrw/root.zig");

test "hrw reference vectors" {
    const allocator = std.testing.allocator;

    const data = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "test/vectors/hrw/reference.json", allocator, std.Io.Limit.limited(1 << 20));
    defer allocator.free(data);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();

    const root = parsed.value.object;
    const pivot = root.get("key").?.string;
    const nodes_arr = root.get("nodes").?.array;
    const expect_arr = root.get("expectedOrder").?.array;

    const Node = struct {
        value: u64,
        fn h(v: @This()) u64 {
            return v.value;
        }
    };

    var nodes = try allocator.alloc(Node, nodes_arr.items.len);
    defer allocator.free(nodes);
    for (nodes_arr.items, 0..) |n, i| {
        nodes[i] = .{ .value = @intCast(n.integer) };
    }

    const object = hrw.wrapBytes(pivot);
    hrw.sort(Node, nodes, object.hash(), Node.h);

    for (expect_arr.items, nodes) |exp, node| {
        try std.testing.expectEqual(@as(u64, @intCast(exp.integer)), node.value);
    }
}

test "tzhash reference vector file present" {
    try std.Io.Dir.cwd().access(std.testing.io, "test/vectors/tzhash/reference.json", .{});
}
