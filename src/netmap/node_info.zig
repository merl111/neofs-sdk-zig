const std = @import("std");
const hrw = @import("../hrw/root.zig");

pub const attr_price = "Price";
pub const attr_capacity = "Capacity";

pub const NodeInfo = struct {
    public_key: []const u8,
    attributes: std.StringArrayHashMapUnmanaged([]const u8),

    pub fn init(_: std.mem.Allocator) NodeInfo {
        return .{
            .public_key = "",
            .attributes = .{},
        };
    }

    pub fn deinit(self: *NodeInfo, allocator: std.mem.Allocator) void {
        var it = self.attributes.iterator();
        while (it.next()) |e| {
            allocator.free(e.key_ptr.*);
            allocator.free(e.value_ptr.*);
        }
        self.attributes.deinit(allocator);
        if (self.public_key.len > 0) allocator.free(self.public_key);
    }

    pub fn setAttribute(self: *NodeInfo, allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
        const k = try allocator.dupe(u8, key);
        errdefer allocator.free(k);
        const v = try allocator.dupe(u8, value);
        errdefer allocator.free(v);
        const gop = try self.attributes.getOrPut(allocator, k);
        if (gop.found_existing) {
            allocator.free(v);
            allocator.free(k);
            allocator.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = v;
    }

    pub fn attribute(self: NodeInfo, key: []const u8) []const u8 {
        return self.attributes.get(key) orelse "";
    }

    pub fn price(self: NodeInfo) u64 {
        return std.fmt.parseInt(u64, self.attribute(attr_price), 10) catch 0;
    }

    pub fn capacity(self: NodeInfo) u64 {
        return std.fmt.parseInt(u64, self.attribute(attr_capacity), 10) catch 0;
    }

    pub fn hash(self: NodeInfo) u64 {
        return hrw.hash(self.public_key);
    }

    pub fn clone(self: NodeInfo, allocator: std.mem.Allocator) !NodeInfo {
        var out = NodeInfo.init(allocator);
        if (self.public_key.len > 0) {
            out.public_key = try allocator.dupe(u8, self.public_key);
        }
        var it = self.attributes.iterator();
        while (it.next()) |e| {
            try out.setAttribute(allocator, e.key_ptr.*, e.value_ptr.*);
        }
        return out;
    }

    pub fn fromVectorNode(allocator: std.mem.Allocator, _: usize, public_key: []const u8) !NodeInfo {
        var n = NodeInfo.init(allocator);
        if (public_key.len > 0) {
            n.public_key = try allocator.dupe(u8, public_key);
        }
        return n;
    }
};

pub const nodes = []NodeInfo;

pub fn nodeHash(n: NodeInfo) u64 {
    return n.hash();
}

pub fn nodeWeights(ns: []const NodeInfo, wf: *const WeightFunc) []f64 {
    var w = std.ArrayListUnmanaged(f64){};
    w.ensureTotalCapacityPrecise(std.heap.page_allocator, ns.len) catch return &.{};
    for (ns) |n| {
        w.append(std.heap.page_allocator, wf.call(n)) catch return &.{};
    }
    return w.items;
}

pub const WeightFunc = struct {
    cap_norm: SigmoidNorm,
    price_norm: ReverseMinNorm,

    pub fn init(ns: []const NodeInfo) WeightFunc {
        var mean_cap = MeanAgg.init();
        var min_price = MinAgg.init();
        for (ns) |n| {
            mean_cap.add(@floatFromInt(n.capacity()));
            min_price.add(@floatFromInt(n.price()));
        }
        return .{
            .cap_norm = .{ .scale = mean_cap.compute() },
            .price_norm = .{ .min = min_price.compute() },
        };
    }

    pub fn call(self: WeightFunc, n: NodeInfo) f64 {
        const cap = self.cap_norm.normalize(@floatFromInt(n.capacity()));
        const price = self.price_norm.normalize(@floatFromInt(n.price()));
        return cap * price;
    }
};

const MeanAgg = struct {
    mean: f64 = 0,
    count: usize = 0,
    fn init() MeanAgg {
        return .{};
    }
    fn add(self: *MeanAgg, n: f64) void {
        const c = self.count + 1;
        self.mean = self.mean * (@as(f64, @floatFromInt(self.count)) / @as(f64, @floatFromInt(c))) + n / @as(f64, @floatFromInt(c));
        self.count = c;
    }
    fn compute(self: MeanAgg) f64 {
        return self.mean;
    }
};

const MinAgg = struct {
    min: ?f64 = null,
    fn init() MinAgg {
        return .{};
    }
    fn add(self: *MinAgg, n: f64) void {
        if (self.min == null or n < self.min.?) self.min = n;
    }
    fn compute(self: MinAgg) f64 {
        return self.min orelse 0;
    }
};

const SigmoidNorm = struct {
    scale: f64 = 0,
    fn normalize(self: SigmoidNorm, w: f64) f64 {
        if (self.scale == 0) return 0;
        const x = w / self.scale;
        return x / (1 + x);
    }
};

const ReverseMinNorm = struct {
    min: f64 = 0,
    fn normalize(self: ReverseMinNorm, w: f64) f64 {
        if (w == 0) return 0;
        return self.min / w;
    }
};

const MeanIQRAgg = struct {
    arr: std.ArrayListUnmanaged(f64) = .{},
    k: f64 = 1.5,

    fn init(allocator: std.mem.Allocator) MeanIQRAgg {
        _ = allocator;
        return .{};
    }

    fn deinit(self: *MeanIQRAgg, allocator: std.mem.Allocator) void {
        self.arr.deinit(allocator);
    }

    fn add(self: *MeanIQRAgg, allocator: std.mem.Allocator, n: f64) !void {
        try self.arr.append(allocator, n);
    }

    fn compute(self: *MeanIQRAgg, allocator: std.mem.Allocator) f64 {
        if (self.arr.items.len == 0) return 0;
        const sorted = allocator.alloc(f64, self.arr.items.len) catch return 0;
        defer allocator.free(sorted);
        @memcpy(sorted, self.arr.items);
        std.mem.sort(f64, sorted, {}, std.sort.asc(f64));

        const l = sorted.len;
        const min_ln: usize = 4;
        var min_v: f64 = undefined;
        var max_v: f64 = undefined;
        if (l < min_ln) {
            min_v = sorted[0];
            max_v = sorted[l - 1];
        } else {
            const start = l / min_ln;
            const end = l * 3 / min_ln - 1;
            const iqr = self.k * (sorted[end] - sorted[start]);
            min_v = sorted[start] - iqr;
            max_v = sorted[end] + iqr;
        }
        var sum: f64 = 0;
        var count: usize = 0;
        for (sorted) |e| {
            if (e >= min_v and e <= max_v) {
                sum += e;
                count += 1;
            }
        }
        if (count == 0) return 0;
        return sum / @as(f64, @floatFromInt(count));
    }
};

pub fn calcBucketWeight(ns: []const NodeInfo, wf: WeightFunc, allocator: std.mem.Allocator) f64 {
    var agg = MeanIQRAgg.init(allocator);
    defer agg.deinit(allocator);
    for (ns) |n| {
        agg.add(allocator, wf.call(n)) catch return 0;
    }
    return agg.compute(allocator);
}
