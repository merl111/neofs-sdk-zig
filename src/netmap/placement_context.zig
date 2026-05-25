const std = @import("std");
const hrw = @import("../hrw/root.zig");
const netmap_pb = @import("../proto/gen/netmap/types.pb.zig");
const node_info = @import("node_info.zig");

pub const main_filter_name = "*";
pub const default_container_backup_factor: u32 = 3;

pub const ErrNotEnoughNodes = error.NotEnoughNodes;

pub const FilterOp = netmap_pb.Operation;

pub const PlacementContext = struct {
    nodes: []node_info.NodeInfo,
    processed_filters: std.StringHashMapUnmanaged(usize),
    selections: std.StringArrayHashMapUnmanaged([]node_groups),
    num_cache: std.StringHashMapUnmanaged(u64),
    hrw_seed: []const u8 = "",
    weight_func: node_info.WeightFunc,
    cbf: u32 = default_container_backup_factor,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PlacementContext) void {
        var fit = self.processed_filters.iterator();
        while (fit.next()) |e| self.allocator.free(e.key_ptr.*);
        self.processed_filters.deinit(self.allocator);
    var sit = self.selections.iterator();
    while (sit.next()) |e| {
        self.allocator.free(e.key_ptr.*);
        for (e.value_ptr.*) |g| {
            for (g) |*n| n.deinit(self.allocator);
            self.allocator.free(g);
        }
        self.allocator.free(e.value_ptr.*);
    }
        self.selections.deinit(self.allocator);
        self.num_cache.deinit(self.allocator);
    }

    pub fn init(allocator: std.mem.Allocator, nodes: []node_info.NodeInfo) PlacementContext {
        return .{
            .nodes = nodes,
            .processed_filters = .{},
            .selections = .{},
            .num_cache = .{},
            .weight_func = node_info.WeightFunc.init(nodes),
            .allocator = allocator,
        };
    }

    pub fn setPivot(self: *PlacementContext, pivot: []const u8) void {
        self.hrw_seed = pivot;
    }

    pub fn setCBF(self: *PlacementContext, cbf: u32) void {
        self.cbf = if (cbf == 0) default_container_backup_factor else cbf;
    }

    fn nodeIndex(nodes: []node_info.NodeInfo, n: node_info.NodeInfo) usize {
        for (nodes, 0..) |node, i| {
            if (std.mem.eql(u8, node.public_key, n.public_key) and
                node.attributes.count() == n.attributes.count())
            {
                var it = node.attributes.iterator();
                var same = true;
                while (it.next()) |e| {
                    if (!std.mem.eql(u8, e.value_ptr.*, n.attribute(e.key_ptr.*))) {
                        same = false;
                        break;
                    }
                }
                if (same) return i;
            }
        }
        return 0;
    }

    pub fn processFilters(self: *PlacementContext, policy: netmap_pb.PlacementPolicy) !void {
        for (policy.filters.items, 0..) |*f, i| {
            try self.processFilter(policy, f, true, i);
        }
    }

    fn processFilter(self: *PlacementContext, policy: netmap_pb.PlacementPolicy, f: *const netmap_pb.Filter, top: bool, idx: usize) !void {
        if (std.mem.eql(u8, f.name, main_filter_name)) {
            return error.InvalidFilterName;
        }
        if (top and f.name.len == 0) return error.UnnamedTopFilter;
        if (!top and f.name.len > 0 and self.processed_filters.get(f.name) == null) {
            return error.FilterNotFound;
        }
        const op = f.op;
        if (op == .AND or op == .OR) {
            for (f.filters.items) |*inner| {
                try self.processFilter(policy, inner, false, 0);
            }
        } else {
            if (f.filters.items.len != 0) return error.NonEmptyFilters;
            if (!top and f.name.len > 0) return;
            switch (op) {
                .EQ, .NE => {},
                .GT, .GE, .LT, .LE => {
                    const n = std.fmt.parseInt(u64, f.value, 10) catch return error.InvalidNumber;
                    try self.num_cache.put(self.allocator, try self.allocator.dupe(u8, f.value), n);
                },
                else => return error.InvalidFilterOp,
            }
        }
        if (top) {
            const fname = try self.allocator.dupe(u8, f.name);
            try self.processed_filters.put(self.allocator, fname, idx);
        }
    }

    fn filterByName(self: *PlacementContext, policy: netmap_pb.PlacementPolicy, name: []const u8) ?*const netmap_pb.Filter {
        const fi = self.processed_filters.get(name) orelse return null;
        return &policy.filters.items[fi];
    }

    pub fn processSelectors(self: *PlacementContext, policy: netmap_pb.PlacementPolicy) !void {
        for (policy.selectors.items) |*s| {
            const f_name = s.filter;
            if (!std.mem.eql(u8, f_name, main_filter_name) and self.processed_filters.get(f_name) == null) {
                return error.FilterNotFound;
            }
            const result = try self.getSelection(policy, s);
            const name = try self.allocator.dupe(u8, s.name);
            try self.selections.put(self.allocator, name, result);
        }
    }

    fn match(self: *PlacementContext, policy: netmap_pb.PlacementPolicy, f: *const netmap_pb.Filter, n: node_info.NodeInfo) bool {
        switch (f.op) {
            .AND, .OR => {
                for (f.filters.items) |*inner| {
                    const sub: *const netmap_pb.Filter = if (inner.name.len > 0)
                        self.filterByName(policy, inner.name) orelse return false
                    else
                        inner;
                    const ok = self.match(policy, sub, n);
                    if (ok == (f.op == .OR)) return ok;
                }
                return f.op == .AND;
            },
            else => return self.matchKeyValue(f, n),
        }
    }

    fn matchKeyValue(self: *PlacementContext, f: *const netmap_pb.Filter, n: node_info.NodeInfo) bool {
        switch (f.op) {
            .EQ => return std.mem.eql(u8, n.attribute(f.key), f.value),
            .NE => return !std.mem.eql(u8, n.attribute(f.key), f.value),
            else => {
                var attr: u64 = 0;
                if (std.mem.eql(u8, f.key, node_info.attr_price)) {
                    attr = n.price();
                } else if (std.mem.eql(u8, f.key, node_info.attr_capacity)) {
                    attr = n.capacity();
                } else {
                    attr = std.fmt.parseInt(u64, n.attribute(f.key), 10) catch return false;
                }
                const cached = self.num_cache.get(f.value) orelse return false;
                return switch (f.op) {
                    .GT => attr > cached,
                    .GE => attr >= cached,
                    .LT => attr < cached,
                    .LE => attr <= cached,
                    else => false,
                };
            },
        }
    }

    const NodeAttrPair = struct {
        attr: []const u8,
        nodes: []node_info.NodeInfo,
    };

    fn getSelectionBase(self: *PlacementContext, policy: netmap_pb.PlacementPolicy, s: *const netmap_pb.Selector) ![]NodeAttrPair {
        const f_name = s.filter;
        const f: ?*const netmap_pb.Filter = if (std.mem.eql(u8, f_name, main_filter_name))
            null
        else
            self.filterByName(policy, f_name);
        const is_main = std.mem.eql(u8, f_name, main_filter_name);
        var result: std.ArrayListUnmanaged(NodeAttrPair) = .empty;
        errdefer result.deinit(self.allocator);
        var node_map: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(node_info.NodeInfo)) = .empty;
        errdefer {
            var it = node_map.iterator();
            while (it.next()) |e| {
                e.value_ptr.deinit(self.allocator);
            }
            node_map.deinit(self.allocator);
        }
        const attr_key = s.attribute;

        for (self.nodes) |n| {
            if (is_main or (f != null and self.match(policy, f.?, n))) {
                if (attr_key.len == 0) {
                    const one = try self.allocator.alloc(node_info.NodeInfo, 1);
                    one[0] = n;
                    try result.append(self.allocator, .{ .attr = "", .nodes = one });
                } else {
                    const v = n.attribute(attr_key);
                    const gop = try node_map.getOrPut(self.allocator, v);
                    if (!gop.found_existing) {
                        gop.value_ptr.* = .{};
                    }
                    try gop.value_ptr.append(self.allocator, n);
                }
            }
        }

        if (attr_key.len > 0) {
            var it = node_map.iterator();
            while (it.next()) |e| {
                const nodes_slice = try e.value_ptr.toOwnedSlice(self.allocator);
                try result.append(self.allocator, .{ .attr = e.key_ptr.*, .nodes = nodes_slice });
            }
            node_map.deinit(self.allocator);
        }

        if (self.hrw_seed.len > 0) {
            const pivot_hash = hrw.wrapBytes(self.hrw_seed);
            for (result.items) |*pair| {
                const nodes_copy = try self.allocator.alloc(node_info.NodeInfo, pair.nodes.len);
                @memcpy(nodes_copy, pair.nodes);
                const weights = self.allocator.alloc(f64, nodes_copy.len) catch continue;
                defer self.allocator.free(weights);
                for (nodes_copy, weights) |nn, *w| {
                    w.* = self.weight_func.call(nn);
                }
                hrw.sortWeighted(node_info.NodeInfo, nodes_copy, weights, pivot_hash.hash(), node_info.nodeHash);
                self.allocator.free(pair.nodes);
                pair.nodes = nodes_copy;
            }
        }

        return result.toOwnedSlice(self.allocator);
    }

    fn calcNodesCount(s: *const netmap_pb.Selector) struct { bucket_count: usize, nodes_in_bucket: usize } {
        const n: usize = @intCast(s.count);
        if (s.clause == .SAME) return .{ .bucket_count = 1, .nodes_in_bucket = n };
        return .{ .bucket_count = n, .nodes_in_bucket = 1 };
    }

    pub fn getSelection(self: *PlacementContext, policy: netmap_pb.PlacementPolicy, s: *const netmap_pb.Selector) ![]node_groups {
        const counts = calcNodesCount(s);
        if (counts.bucket_count == 0 or counts.nodes_in_bucket == 0) {
            return ErrNotEnoughNodes;
        }
        const buckets = try self.getSelectionBase(policy, s);
        defer {
            for (buckets) |b| self.allocator.free(b.nodes);
            self.allocator.free(buckets);
        }

        if (buckets.len < counts.bucket_count) {
            return ErrNotEnoughNodes;
        }

        if (self.hrw_seed.len == 0) {
            if (s.attribute.len == 0) {
                std.mem.sort(NodeAttrPair, buckets, self.nodes, struct {
                    fn less(nodes: []node_info.NodeInfo, a: NodeAttrPair, b: NodeAttrPair) bool {
                        const ha = node_info.nodeHash(a.nodes[0]);
                        const hb = node_info.nodeHash(b.nodes[0]);
                        if (ha != hb) return ha < hb;
                        return nodeIndex(nodes, a.nodes[0]) < nodeIndex(nodes, b.nodes[0]);
                    }
                }.less);
            } else {
                std.mem.sort(NodeAttrPair, buckets, self.nodes, struct {
                    fn less(nodes: []node_info.NodeInfo, a: NodeAttrPair, b: NodeAttrPair) bool {
                        const ord = std.mem.order(u8, a.attr, b.attr);
                        if (ord != .eq) return ord == .lt;
                        return nodeIndex(nodes, a.nodes[0]) < nodeIndex(nodes, b.nodes[0]);
                    }
                }.less);
            }
        }

        const max_nodes_in_bucket = std.math.mul(
            usize,
            counts.nodes_in_bucket,
            @as(usize, self.cbf),
        ) catch return ErrNotEnoughNodes;
        var res: std.ArrayListUnmanaged([]node_info.NodeInfo) = .empty;
        errdefer {
            for (res.items) |g| self.allocator.free(g);
            res.deinit(self.allocator);
        }
        var fallback: std.ArrayListUnmanaged([]node_info.NodeInfo) = .empty;
        errdefer {
            for (fallback.items) |g| self.allocator.free(g);
            fallback.deinit(self.allocator);
        }

        for (buckets) |b| {
            if (b.nodes.len >= max_nodes_in_bucket) {
                const slice = try self.allocator.alloc(node_info.NodeInfo, max_nodes_in_bucket);
                @memcpy(slice, b.nodes[0..max_nodes_in_bucket]);
                try res.append(self.allocator, slice);
            } else if (b.nodes.len >= counts.nodes_in_bucket) {
                const slice = try self.allocator.alloc(node_info.NodeInfo, b.nodes.len);
                @memcpy(slice, b.nodes);
                try fallback.append(self.allocator, slice);
            }
        }

        if (res.items.len < counts.bucket_count) {
            try res.appendSlice(self.allocator, fallback.items);
            fallback.clearRetainingCapacity();
            if (res.items.len < counts.bucket_count) return ErrNotEnoughNodes;
        }

        if (self.hrw_seed.len > 0) {
            const pivot_hash = hrw.wrapBytes(self.hrw_seed);
            const weights = try self.allocator.alloc(f64, res.items.len);
            defer self.allocator.free(weights);
            for (res.items, weights) |*group, *w| {
                w.* = node_info.calcBucketWeight(group.*, self.weight_func, self.allocator);
            }
            hrw.sortWeighted([]node_info.NodeInfo, res.items, weights, pivot_hash.hash(), groupHash);
        }

        if (s.attribute.len == 0) {
            const primary = try self.allocator.alloc([]node_info.NodeInfo, counts.bucket_count);
            @memcpy(primary, res.items[0..counts.bucket_count]);
            const extra = res.items[counts.bucket_count..];
            for (extra, 0..) |fb, i| {
                const index = i % counts.bucket_count; // bucket_count > 0 checked above
                if (primary[index].len >= max_nodes_in_bucket) break;
                const new_len = primary[index].len + fb.len;
                const merged = try self.allocator.alloc(node_info.NodeInfo, new_len);
                @memcpy(merged[0..primary[index].len], primary[index]);
                @memcpy(merged[primary[index].len..], fb);
                self.allocator.free(primary[index]);
                primary[index] = merged;
            }
            const out = try dupNodeGroups(self.allocator, primary);
            self.allocator.free(primary);
            if (res.items.len > counts.bucket_count) {
                for (res.items[counts.bucket_count..]) |g| self.allocator.free(g);
            }
            res.deinit(self.allocator);
            for (fallback.items) |g| self.allocator.free(g);
            fallback.deinit(self.allocator);
            return out;
        }

        const out = try dupNodeGroups(self.allocator, res.items[0..counts.bucket_count]);
        for (res.items) |g| self.allocator.free(g);
        res.deinit(self.allocator);
        for (fallback.items) |g| self.allocator.free(g);
        fallback.deinit(self.allocator);
        return out;
    }
};

pub const node_groups = []node_info.NodeInfo;

fn groupHash(g: []node_info.NodeInfo) u64 {
    if (g.len > 0) return g[0].hash();
    return 0;
}

fn dupNodeGroups(allocator: std.mem.Allocator, groups: []node_groups) ![]node_groups {
    const out = try allocator.alloc(node_groups, groups.len);
    errdefer allocator.free(out);
    for (groups, out) |g, *dst| {
        const ng = try allocator.alloc(node_info.NodeInfo, g.len);
        errdefer allocator.free(ng);
        for (g, ng) |n, *slot| {
            slot.* = try n.clone(allocator);
        }
        dst.* = ng;
    }
    return out;
}

pub fn flattenNodeGroups(allocator: std.mem.Allocator, groups: []node_groups) ![]node_info.NodeInfo {
    var total: usize = 0;
    for (groups) |g| total += g.len;
    const out = try allocator.alloc(node_info.NodeInfo, total);
    var off: usize = 0;
    for (groups) |g| {
        for (g) |n| {
            out[off] = try n.clone(allocator);
            off += 1;
        }
    }
    return out;
}
