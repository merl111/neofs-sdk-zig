const std = @import("std");
const hrw = @import("hrw/root.zig");

test "hrw reference vectors" {
    const allocator = std.heap.page_allocator;

    const data = try std.fs.cwd().readFileAlloc(allocator, "test/vectors/hrw/reference.json", 1 << 20);
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
    try std.fs.cwd().access("test/vectors/tzhash/reference.json", .{});
}
