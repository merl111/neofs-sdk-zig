const std = @import("std");
const hrw = @import("../hrw/root.zig");
const netmap_pb = @import("../proto/gen/netmap/types.pb.zig");
const node_info = @import("node_info.zig");
const placement_context = @import("placement_context.zig");

pub const NetMap = struct {
    nodes: []node_info.NodeInfo,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, nodes: []node_info.NodeInfo) NetMap {
        return .{ .nodes = nodes, .allocator = allocator };
    }

    pub fn deinit(self: *NetMap) void {
        for (self.nodes) |*n| n.deinit(self.allocator);
        self.allocator.free(self.nodes);
    }

    pub fn containerNodes(
        self: NetMap,
        policy: netmap_pb.PlacementPolicy,
        pivot: []const u8,
    ) ![][]node_info.NodeInfo {
        var ctx = placement_context.PlacementContext.init(self.allocator, self.nodes);
        defer ctx.deinit();
        ctx.setCBF(policy.container_backup_factor);
        ctx.setPivot(pivot);

        try ctx.processFilters(policy);
        try ctx.processSelectors(policy);

        const rep_count = policy.replicas.items.len;
        const ec_count = policy.ec_rules.items.len;
        var result = try self.allocator.alloc([]node_info.NodeInfo, rep_count + ec_count);
        for (result) |*slot| slot.* = &.{};
        errdefer {
            for (result) |r| {
                if (r.len > 0) {
                    for (r) |*n| n.deinit(self.allocator);
                    self.allocator.free(r);
                }
            }
            self.allocator.free(result);
        }

        for (policy.replicas.items, 0..) |rep, i| {
            const s_name = rep.selector;
            if (s_name.len == 0) {
                if (policy.selectors.items.len == 0) {
                    var implicit = netmap_pb.Selector{
                        .count = rep.count,
                        .filter = placement_context.main_filter_name,
                    };
                    const groups = try ctx.getSelection(policy, &implicit);
                    result[i] = try placement_context.flattenNodeGroups(self.allocator, groups);
                } else {
                    result[i] = try flattenAllSelectors(self.allocator, &ctx, policy);
                }
            } else {
                const groups = ctx.selections.get(s_name) orelse return error.SelectorNotFound;
                result[i] = try placement_context.flattenNodeGroups(self.allocator, groups);
            }
        }

        for (policy.ec_rules.items, 0..) |rule, j| {
            const i = rep_count + j;
            const s_name = rule.selector;
            if (s_name.len == 0) {
                if (policy.selectors.items.len == 0) {
                    var implicit = netmap_pb.Selector{
                        .count = rule.data_part_num + rule.parity_part_num,
                        .filter = placement_context.main_filter_name,
                    };
                    const groups = try ctx.getSelection(policy, &implicit);
                    result[i] = try placement_context.flattenNodeGroups(self.allocator, groups);
                } else {
                    result[i] = try flattenAllSelectors(self.allocator, &ctx, policy);
                }
            } else {
                const groups = ctx.selections.get(s_name) orelse return error.SelectorNotFound;
                result[i] = try placement_context.flattenNodeGroups(self.allocator, groups);
            }
        }

        return result;
    }

    pub fn freeContainerNodes(self: NetMap, vectors: [][]node_info.NodeInfo) void {
        for (vectors) |vec| {
            for (vec) |*n| n.deinit(self.allocator);
            self.allocator.free(vec);
        }
        self.allocator.free(vectors);
    }

    pub fn placementVectors(
        self: NetMap,
        vectors: [][]node_info.NodeInfo,
        object_pivot: []const u8,
    ) ![][]node_info.NodeInfo {
        const pivot_hash = hrw.wrapBytes(object_pivot);
        const wf = node_info.WeightFunc.init(self.nodes);
        var result = try self.allocator.alloc([]node_info.NodeInfo, vectors.len);
        errdefer {
            for (result) |r| self.allocator.free(r);
            self.allocator.free(result);
        }
        for (vectors, 0..) |vec, i| {
            const copy = try self.allocator.alloc(node_info.NodeInfo, vec.len);
            @memcpy(copy, vec);
            const weights = try self.allocator.alloc(f64, copy.len);
            defer self.allocator.free(weights);
            for (copy, weights) |n, *w| {
                w.* = wf.call(n);
            }
            hrw.sortWeighted(node_info.NodeInfo, copy, weights, pivot_hash.hash(), node_info.nodeHash);
            result[i] = copy;
        }
        return result;
    }
};

fn flattenAllSelectors(
    allocator: std.mem.Allocator,
    ctx: *placement_context.PlacementContext,
    policy: netmap_pb.PlacementPolicy,
) ![]node_info.NodeInfo {
    var total_len: usize = 0;
    for (policy.selectors.items) |s| {
        const g = ctx.selections.get(s.name) orelse return error.SelectorNotFound;
        for (g) |grp| total_len += grp.len;
    }
    var flat = try allocator.alloc(node_info.NodeInfo, total_len);
    errdefer {
        for (flat) |*n| n.deinit(allocator);
        allocator.free(flat);
    }
    var off: usize = 0;
    for (policy.selectors.items) |s| {
        const g = ctx.selections.get(s.name) orelse return error.SelectorNotFound;
        for (g) |grp| {
            for (grp) |n| {
                flat[off] = try n.clone(allocator);
                off += 1;
            }
        }
    }
    return flat;
}

pub fn nodesEqual(a: node_info.NodeInfo, b: node_info.NodeInfo) bool {
    if (!std.mem.eql(u8, a.public_key, b.public_key)) return false;
    if (a.attributes.count() != b.attributes.count()) return false;
    var it = a.attributes.iterator();
    while (it.next()) |e| {
        const bv = b.attribute(e.key_ptr.*);
        if (!std.mem.eql(u8, e.value_ptr.*, bv)) return false;
    }
    return true;
}

pub fn compareResults(
    expected_indices: []const usize,
    all_nodes: []node_info.NodeInfo,
    actual: []node_info.NodeInfo,
) bool {
    if (expected_indices.len != actual.len) return false;
    for (expected_indices, actual) |idx, act| {
        if (idx >= all_nodes.len) return false;
        if (!nodesEqual(all_nodes[idx], act)) return false;
    }
    return true;
}

pub fn compareResultsIgnoreOrder(
    allocator: std.mem.Allocator,
    expected_indices: []const usize,
    all_nodes: []node_info.NodeInfo,
    actual: []node_info.NodeInfo,
) !bool {
    if (expected_indices.len != actual.len) return false;
    const matched = try allocator.alloc(bool, actual.len);
    defer allocator.free(matched);
    @memset(matched, false);
    for (expected_indices) |idx| {
        if (idx >= all_nodes.len) return false;
        const exp = all_nodes[idx];
        var found = false;
        for (actual, matched) |act, *m| {
            if (m.*) continue;
            if (nodesEqual(exp, act)) {
                m.* = true;
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}
