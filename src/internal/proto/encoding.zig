const std = @import("std");

pub const StableMessage = struct {
    ctx: *const anyopaque,
    marshaledSizeFn: *const fn (ctx: *const anyopaque) usize,
    marshalStableFn: *const fn (ctx: *const anyopaque, out: []u8) void,

    pub fn marshaledSize(self: StableMessage) usize {
        return self.marshaledSizeFn(self.ctx);
    }

    pub fn marshalStable(self: StableMessage, out: []u8) void {
        self.marshalStableFn(self.ctx, out);
    }
};

pub fn marshalMessage(allocator: std.mem.Allocator, msg: StableMessage) ![]u8 {
    const out = try allocator.alloc(u8, msg.marshaledSize());
    msg.marshalStable(out);
    return out;
}

pub fn putTag(out: []u8, field_num: u32, wire_type: u8) usize {
    return putVarint(out, (@as(u64, field_num) << 3) | wire_type);
}

pub fn putVarint(out: []u8, value: u64) usize {
    var x = value;
    var i: usize = 0;
    while (x >= 0x80) : (i += 1) {
        out[i] = @as(u8, @intCast((x & 0x7f) | 0x80));
        x >>= 7;
    }
    out[i] = @as(u8, @intCast(x));
    return i + 1;
}

pub fn putBytes(out: []u8, data: []const u8) usize {
    const n = putVarint(out, data.len);
    @memcpy(out[n .. n + data.len], data);
    return n + data.len;
}

test "varint encodes deterministic bytes" {
    var out: [10]u8 = undefined;
    const n = putVarint(&out, 300);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u8, 0xac), out[0]);
    try std.testing.expectEqual(@as(u8, 0x02), out[1]);
}
