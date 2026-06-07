const std = @import("std");
const json_vectors = @import("../testutil/json_vectors.zig");
const engine = @import("engine.zig");
const node_info = @import("node_info.zig");

test "netmap json vector files exist" {
    const cwd = std.Io.Dir.cwd();
    var dir = try cwd.openDir(std.testing.io, "test/vectors/netmap", .{ .iterate = true });
    defer dir.close(std.testing.io);
    var it = dir.iterate();
    var count: usize = 0;
    while (try it.next(std.testing.io)) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".json")) count += 1;
    }
    try std.testing.expectEqual(@as(usize, 14), count);
}

test "netmap json vectors placement interop" {
    const allocator = std.heap.page_allocator;

    var dir = try std.Io.Dir.cwd().openDir(std.testing.io, "test/vectors/netmap", .{ .iterate = true });
    defer dir.close(std.testing.io);
    var it = dir.iterate();

    while (try it.next(std.testing.io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json")) continue;
        if (std.mem.eql(u8, entry.name, "hrw_sort.json")) continue; // TODO: HRW pivot parity with Go weights
        const path = try std.fmt.allocPrint(allocator, "test/vectors/netmap/{s}", .{entry.name});
        defer allocator.free(path);

        var vc = try json_vectors.loadNetmapVector(allocator, path);
        defer json_vectors.freeVectorCase(allocator, &vc);

        var nodes = try allocator.alloc(node_info.NodeInfo, vc.nodes.len);
        for (vc.nodes, 0..) |vn, i| {
            nodes[i] = try node_info.NodeInfo.fromVectorNode(allocator, i, vn.publicKey);
            for (vn.attributes) |a| {
                try nodes[i].setAttribute(allocator, a.key, a.value);
            }
        }

        var nm = engine.NetMap.init(allocator, nodes);
        defer nm.deinit();

        var test_it = vc.tests.iterator();
        while (test_it.next()) |te| {
            const pivot_slice = te.value_ptr.pivot[0..];

            const result = nm.containerNodes(te.value_ptr.policy, pivot_slice);
            if (te.value_ptr.err_expected) |msg| {
                const expected_err: anyerror = if (std.mem.indexOf(u8, msg, "filter not found") != null)
                    error.FilterNotFound
                else if (std.mem.indexOf(u8, msg, "invalid number") != null)
                    error.InvalidNumber
                else
                    error.NotEnoughNodes;
                try std.testing.expectError(expected_err, result);
                continue;
            }

            const vectors = try result;
            defer nm.freeContainerNodes(vectors);

            const expected = te.value_ptr.result orelse continue;
            try std.testing.expectEqual(expected.len, vectors.len);
            for (expected, vectors) |exp_row, act_row| {
                try std.testing.expect(try engine.compareResultsIgnoreOrder(allocator, exp_row, nodes, act_row));
            }

        }
    }
}
