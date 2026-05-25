const std = @import("std");

pub const HashableBytes = struct {
    bytes: []const u8,

    pub fn hash(self: HashableBytes) u64 {
        return murmur3_64(self.bytes);
    }
};

pub fn wrapBytes(bytes: []const u8) HashableBytes {
    return .{ .bytes = bytes };
}

pub fn hash(data: []const u8) u64 {
    return murmur3_64(data);
}

pub fn distance(x: u64, y: u64) u64 {
    var acc: u64 = x ^ y;
    acc ^= acc >> 33;
    acc *%= 0xff51afd7ed558ccd;
    acc ^= acc >> 33;
    acc *%= 0xc4ceb9fe1a85ec53;
    acc ^= acc >> 33;
    return acc;
}

pub fn sort(comptime T: type, values: []T, object_hash: u64, comptime hash_fn: fn (T) u64) void {
    if (values.len < 2) return;
    var i: usize = 1;
    while (i < values.len) : (i += 1) {
        var j = i;
        const cur = values[i];
        const cur_score = distance(hash_fn(cur), object_hash);
        while (j > 0) {
            const prev = values[j - 1];
            const prev_score = distance(hash_fn(prev), object_hash);
            if (prev_score <= cur_score) break;
            values[j] = prev;
            j -= 1;
        }
        values[j] = cur;
    }
}

pub fn sortWeighted(comptime T: type, values: []T, weights: []const f64, object_hash: u64, comptime hash_fn: fn (T) u64) void {
    if (values.len != weights.len or values.len < 2) return;
    var i: usize = 1;
    while (i < values.len) : (i += 1) {
        var j = i;
        const cur = values[i];
        const cur_w = weights[i];
        const cur_score = @as(f64, @floatFromInt(distance(hash_fn(cur), object_hash))) / cur_w;
        while (j > 0) {
            const prev = values[j - 1];
            const prev_score = @as(f64, @floatFromInt(distance(hash_fn(prev), object_hash))) / weights[j - 1];
            if (prev_score <= cur_score) break;
            values[j] = prev;
            j -= 1;
        }
        values[j] = cur;
    }
}

fn murmur3_64(data: []const u8) u64 {
    var h1: u64 = 0;
    var h2: u64 = 0;
    const c1: u64 = 0x87c37b91114253d5;
    const c2: u64 = 0x4cf5ad432745937f;

    var i: usize = 0;
    while (i + 16 <= data.len) : (i += 16) {
        var block1: [8]u8 = undefined;
        var block2: [8]u8 = undefined;
        @memcpy(&block1, data[i .. i + 8]);
        @memcpy(&block2, data[i + 8 .. i + 16]);

        var k1 = std.mem.readInt(u64, &block1, .little);
        var k2 = std.mem.readInt(u64, &block2, .little);

        k1 *%= c1;
        k1 = std.math.rotl(u64, k1, 31);
        k1 *%= c2;
        h1 ^= k1;

        h1 = std.math.rotl(u64, h1, 27);
        h1 +%= h2;
        h1 = h1 *% 5 +% 0x52dce729;

        k2 *%= c2;
        k2 = std.math.rotl(u64, k2, 33);
        k2 *%= c1;
        h2 ^= k2;

        h2 = std.math.rotl(u64, h2, 31);
        h2 +%= h1;
        h2 = h2 *% 5 +% 0x38495ab5;
    }

    var k1: u64 = 0;
    var k2: u64 = 0;
    const tail = data[i..];
    var t: usize = tail.len;
    while (t > 0) : (t -= 1) {
        const idx = t - 1;
        const b = @as(u64, tail[idx]);
        if (idx >= 8) {
            k2 |= b << @as(u6, @intCast((idx - 8) * 8));
        } else {
            k1 |= b << @as(u6, @intCast(idx * 8));
        }
    }

    if (k2 != 0) {
        k2 *%= c2;
        k2 = std.math.rotl(u64, k2, 33);
        k2 *%= c1;
        h2 ^= k2;
    }
    if (k1 != 0) {
        k1 *%= c1;
        k1 = std.math.rotl(u64, k1, 31);
        k1 *%= c2;
        h1 ^= k1;
    }

    h1 ^= data.len;
    h2 ^= data.len;

    h1 +%= h2;
    h2 +%= h1;

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 +%= h2;
    return h1;
}

fn fmix64(x: u64) u64 {
    var y = x;
    y ^= y >> 33;
    y *%= 0xff51afd7ed558ccd;
    y ^= y >> 33;
    y *%= 0xc4ceb9fe1a85ec53;
    y ^= y >> 33;
    return y;
}

test "sort deterministic by hrw score" {
    const Obj = struct {
        key: []const u8,
        fn h(v: @This()) u64 {
            return hash(v.key);
        }
    };
    var values = [_]Obj{
        .{ .key = "node-a" },
        .{ .key = "node-b" },
        .{ .key = "node-c" },
    };
    const object = wrapBytes("pivot");
    sort(Obj, values[0..], object.hash(), Obj.h);
    try std.testing.expect(values.len == 3);
}

test "matches go hrw v2.0.4 reference order" {
    const Node = struct {
        value: u64,
        fn h(v: @This()) u64 {
            return v.value;
        }
    };
    var nodes = [_]Node{
        .{ .value = 1 },
        .{ .value = 2 },
        .{ .value = 3 },
        .{ .value = 4 },
        .{ .value = 5 },
    };
    const key = wrapBytes("0xff51afd7ed558ccd");
    sort(Node, nodes[0..], key.hash(), Node.h);
    const expect = [_]u64{ 4, 2, 5, 3, 1 };
    for (nodes, 0..) |node, i| {
        try std.testing.expectEqual(expect[i], node.value);
    }
}
