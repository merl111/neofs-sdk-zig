const std = @import("std");
const hrw = @import("../hrw/root.zig");

pub const policy = @import("policy_parser.zig");
pub const engine = @import("engine.zig");
pub const node_info = @import("node_info.zig");
pub const placement_context = @import("placement_context.zig");

pub const NodeInfo = struct {
    public_key: []const u8,
    weight: f64 = 1.0,

    pub fn hash(self: NodeInfo) u64 {
        return hrw.hash(self.public_key);
    }
};

pub fn sortNodesByPivot(nodes: []NodeInfo, pivot: []const u8) void {
    const p = hrw.wrapBytes(pivot);
    hrw.sort(NodeInfo, nodes, p.hash(), NodeInfo.hash);
}

pub fn sortNodesByPivotWeighted(nodes: []NodeInfo, weights: []const f64, pivot: []const u8) void {
    const p = hrw.wrapBytes(pivot);
    hrw.sortWeighted(NodeInfo, nodes, weights, p.hash(), NodeInfo.hash);
}

pub fn selectReplicas(nodes: []NodeInfo, count: usize, pivot: []const u8) []NodeInfo {
    sortNodesByPivot(nodes, pivot);
    return nodes[0..@min(count, nodes.len)];
}

test "netmap sorting keeps size" {
    var nodes = [_]NodeInfo{
        .{ .public_key = "a" },
        .{ .public_key = "b" },
    };
    sortNodesByPivot(nodes[0..], "pivot");
    try std.testing.expectEqual(@as(usize, 2), nodes.len);
}

test "select replicas returns requested amount" {
    var nodes = [_]NodeInfo{
        .{ .public_key = "a" },
        .{ .public_key = "b" },
        .{ .public_key = "c" },
    };
    const selected = selectReplicas(nodes[0..], 2, "pivot");
    try std.testing.expectEqual(@as(usize, 2), selected.len);
}

test {
    _ = @import("policy_test.zig");
}
