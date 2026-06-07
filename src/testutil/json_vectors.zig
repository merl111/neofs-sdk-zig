const std = @import("std");
const netmap_pb = @import("../proto/gen/netmap/types.pb.zig");

pub const VectorNode = struct {
    publicKey: []const u8 = "",
    addresses: []const []const u8 = &.{},
    attributes: []const VectorAttribute = &.{},
    state: []const u8 = "UNSPECIFIED",
};

pub const VectorAttribute = struct {
    key: []const u8,
    value: []const u8,
};

pub const VectorPlacement = struct {
    pivot: [32]u8 = [_]u8{0} ** 32,
    result: ?[][]usize = null,
};

pub const VectorTest = struct {
    policy: netmap_pb.PlacementPolicy,
    pivot: [32]u8 = [_]u8{0} ** 32,
    result: ?[][]usize = null,
    err_expected: ?[]const u8 = null,
    placement: ?VectorPlacement = null,
};

pub const VectorCase = struct {
    name: []const u8,
    nodes: []VectorNode,
    tests: std.StringArrayHashMapUnmanaged(VectorTest),
};

pub fn loadNetmapVector(allocator: std.mem.Allocator, path: []const u8) !VectorCase {
    const data = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, std.Io.Limit.limited(16 << 20));
    defer allocator.free(data);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const root = parsed.value.object;
    const name = root.get("name") orelse return error.InvalidVector;
    const nodes_val = root.get("nodes") orelse return error.InvalidVector;
    const tests_val = root.get("tests") orelse return error.InvalidVector;

    var nodes_list: std.ArrayListUnmanaged(VectorNode) = .empty;
    errdefer nodes_list.deinit(allocator);
    for (nodes_val.array.items) |item| {
        const obj = item.object;
        const pk_str: []const u8 = blk: {
            if (obj.get("publicKey")) |pk| break :blk pk.string;
            if (obj.get("public_key")) |pk| break :blk pk.string;
            break :blk "";
        };
        var attrs_list: std.ArrayListUnmanaged(VectorAttribute) = .empty;
        errdefer attrs_list.deinit(allocator);
        if (obj.get("attributes")) |attrs| {
            for (attrs.array.items) |a| {
                const ao = a.object;
                const key_v = ao.get("key") orelse return error.InvalidVector;
                const val_v = ao.get("value") orelse return error.InvalidVector;
                try attrs_list.append(allocator, .{
                    .key = try allocator.dupe(u8, key_v.string),
                    .value = try allocator.dupe(u8, val_v.string),
                });
            }
        }
        const attrs_slice = try attrs_list.toOwnedSlice(allocator);
        try nodes_list.append(allocator, .{
            .publicKey = try allocator.dupe(u8, pk_str),
            .addresses = &.{},
            .attributes = attrs_slice,
            .state = if (obj.get("state")) |s| try allocator.dupe(u8, s.string) else try allocator.dupe(u8, "UNSPECIFIED"),
        });
    }

    var tests_map: std.StringArrayHashMapUnmanaged(VectorTest) = .empty;
    errdefer {
        var it = tests_map.iterator();
        while (it.next()) |e| {
            freeVectorTest(allocator, e.value_ptr.*);
        }
        tests_map.deinit(allocator);
    }

    var test_it = tests_val.object.iterator();
    while (test_it.next()) |entry| {
        const test_obj = entry.value_ptr.object;
        var policy: netmap_pb.PlacementPolicy = .{};
        if (test_obj.get("policy")) |pol| {
            var policy_w: std.Io.Writer.Allocating = .init(allocator);
            defer policy_w.deinit();
            try policy_w.writer.print("{f}", .{std.json.fmt(pol, .{})});
            const policy_json = policy_w.written();
            var parsed_policy = try netmap_pb.PlacementPolicy.jsonDecode(
                policy_json,
                .{ .ignore_unknown_fields = true },
                allocator,
            );
            defer parsed_policy.deinit();
            policy = try parsed_policy.value.dupe(allocator);
        }
        var result: ?[][]usize = null;
        if (test_obj.get("result")) |res| {
            result = try parseIndexMatrix(allocator, res);
        }
        const err_str: ?[]const u8 = if (test_obj.get("error")) |e| e.string else null;
        const pivot = try parsePivot(allocator, test_obj.get("pivot"));

        var placement: ?VectorPlacement = null;
        if (test_obj.get("placement")) |pl| {
            const pl_obj = pl.object;
            var pl_result: ?[][]usize = null;
            if (pl_obj.get("result")) |pr| {
                pl_result = try parseIndexMatrix(allocator, pr);
            }
            placement = .{
                .pivot = try parsePivot(allocator, pl_obj.get("pivot")),
                .result = pl_result,
            };
        }

        const test_name = try allocator.dupe(u8, entry.key_ptr.*);
        try tests_map.put(allocator, test_name, .{
            .policy = policy,
            .pivot = pivot,
            .result = result,
            .err_expected = if (err_str) |s| try allocator.dupe(u8, s) else null,
            .placement = placement,
        });
    }

    const name_owned = try allocator.dupe(u8, name.string);
    return .{
        .name = name_owned,
        .nodes = try nodes_list.toOwnedSlice(allocator),
        .tests = tests_map,
    };
}

fn parseIndexMatrix(allocator: std.mem.Allocator, res: std.json.Value) ![][]usize {
    var outer: std.ArrayListUnmanaged([]usize) = .empty;
    errdefer {
        for (outer.items) |inner| allocator.free(inner);
        outer.deinit(allocator);
    }
    for (res.array.items) |row| {
        var inner: std.ArrayListUnmanaged(usize) = .empty;
        errdefer inner.deinit(allocator);
        for (row.array.items) |idx| {
            try inner.append(allocator, @intCast(idx.integer));
        }
        try outer.append(allocator, try inner.toOwnedSlice(allocator));
    }
    return outer.toOwnedSlice(allocator);
}

fn parsePivot(allocator: std.mem.Allocator, val: ?std.json.Value) ![32]u8 {
    var pivot: [32]u8 = [_]u8{0} ** 32;
    const v = val orelse return pivot;
    const s = v.string;
    const size = std.base64.standard.Decoder.calcSizeForSlice(s) catch {
        @memcpy(pivot[0..@min(32, s.len)], s[0..@min(32, s.len)]);
        return pivot;
    };
    const decoded = allocator.alloc(u8, size) catch return pivot;
    defer allocator.free(decoded);
    std.base64.standard.Decoder.decode(decoded, s) catch {
        @memcpy(pivot[0..@min(32, s.len)], s[0..@min(32, s.len)]);
        return pivot;
    };
    @memcpy(pivot[0..@min(32, size)], decoded[0..@min(32, size)]);
    return pivot;
}

pub fn freeVectorCase(allocator: std.mem.Allocator, vc: *VectorCase) void {
    allocator.free(vc.name);
    for (vc.nodes) |*n| {
        allocator.free(n.publicKey);
        allocator.free(n.state);
        for (n.attributes) |a| {
            allocator.free(a.key);
            allocator.free(a.value);
        }
        allocator.free(n.attributes);
    }
    allocator.free(vc.nodes);
    var it = vc.tests.iterator();
    while (it.next()) |e| {
        allocator.free(e.key_ptr.*);
        freeVectorTest(allocator, e.value_ptr.*);
    }
    vc.tests.deinit(allocator);
}

fn freeVectorTest(allocator: std.mem.Allocator, vt: VectorTest) void {
    var policy = vt.policy;
    policy.deinit(allocator);
    if (vt.result) |r| {
        for (r) |row| allocator.free(row);
        allocator.free(r);
    }
    if (vt.err_expected) |e| allocator.free(e);
    if (vt.placement) |pl| {
        if (pl.result) |r| {
            for (r) |row| allocator.free(row);
            allocator.free(r);
        }
    }
}
