const std = @import("std");
const gf127 = @import("gf127.zig");

pub const Size: usize = 64;

const GF127 = gf127.GF127;

pub const Hasher = struct {
    x: [4]GF127 = undefined,

    pub fn init() Hasher {
        var h = Hasher{};
        h.reset();
        return h;
    }

    pub fn reset(self: *Hasher) void {
        self.x[0] = .{ .lo = 1, .hi = 0 };
        self.x[1] = .{ .lo = 0, .hi = 0 };
        self.x[2] = .{ .lo = 0, .hi = 0 };
        self.x[3] = .{ .lo = 1, .hi = 0 };
    }

    pub fn update(self: *Hasher, data: []const u8) void {
        var tmp: GF127 = undefined;
        for (data) |b| {
            mulBitRight(&self.x[0], &self.x[1], &self.x[2], &self.x[3], b & 0x80 != 0, &tmp);
            mulBitRight(&self.x[0], &self.x[1], &self.x[2], &self.x[3], b & 0x40 != 0, &tmp);
            mulBitRight(&self.x[0], &self.x[1], &self.x[2], &self.x[3], b & 0x20 != 0, &tmp);
            mulBitRight(&self.x[0], &self.x[1], &self.x[2], &self.x[3], b & 0x10 != 0, &tmp);
            mulBitRight(&self.x[0], &self.x[1], &self.x[2], &self.x[3], b & 0x08 != 0, &tmp);
            mulBitRight(&self.x[0], &self.x[1], &self.x[2], &self.x[3], b & 0x04 != 0, &tmp);
            mulBitRight(&self.x[0], &self.x[1], &self.x[2], &self.x[3], b & 0x02 != 0, &tmp);
            mulBitRight(&self.x[0], &self.x[1], &self.x[2], &self.x[3], b & 0x01 != 0, &tmp);
        }
    }

    pub fn finish(self: *Hasher) [Size]u8 {
        var out: [Size]u8 = undefined;
        @memcpy(out[0..16], &self.x[0].bytes());
        @memcpy(out[16..32], &self.x[2].bytes());
        @memcpy(out[32..48], &self.x[1].bytes());
        @memcpy(out[48..64], &self.x[3].bytes());
        return out;
    }
};

fn mulBitRight(c00: *GF127, c10: *GF127, c01: *GF127, c11: *GF127, bit: bool, tmp: *GF127) void {
    if (bit) {
        tmp.* = c00.*;
        c00.* = GF127.mul10(c00.*);
        c00.* = GF127.add(c00.*, c01.*);
        tmp.* = GF127.mul11(tmp.*);
        c01.* = GF127.add(c01.*, tmp.*);

        tmp.* = c10.*;
        c10.* = GF127.mul10(c10.*);
        c10.* = GF127.add(c10.*, c11.*);
        tmp.* = GF127.mul11(tmp.*);
        c11.* = GF127.add(c11.*, tmp.*);
    } else {
        tmp.* = c00.*;
        c00.* = GF127.add(GF127.mul10(c00.*), c01.*);
        c01.* = tmp.*;

        tmp.* = c10.*;
        c10.* = GF127.add(GF127.mul10(c10.*), c11.*);
        c11.* = tmp.*;
    }
}

const Sl2 = struct {
    m: [2][2]GF127,

    fn mul(a: Sl2, b: Sl2) Sl2 {
        var x: [4]GF127 = undefined;
        x[0] = GF127.mul(a.m[0][0], b.m[0][0]);
        x[1] = GF127.mul(a.m[0][0], b.m[0][1]);
        x[2] = GF127.mul(a.m[1][0], b.m[0][0]);
        x[3] = GF127.mul(a.m[1][0], b.m[0][1]);

        var out = Sl2{ .m = undefined };
        out.m[0][0] = GF127.add(GF127.mul(a.m[0][1], b.m[1][0]), x[0]);
        out.m[0][1] = GF127.add(GF127.mul(a.m[0][1], b.m[1][1]), x[1]);
        out.m[1][0] = GF127.add(GF127.mul(a.m[1][1], b.m[1][0]), x[2]);
        out.m[1][1] = GF127.add(GF127.mul(a.m[1][1], b.m[1][1]), x[3]);
        return out;
    }

    fn inv(self: Sl2) Sl2 {
        var t: [2]GF127 = undefined;
        t[0] = GF127.add(GF127.mul(self.m[0][0], self.m[1][1]), GF127.mul(self.m[0][1], self.m[1][0]));
        t[1] = GF127.inv(t[0]);
        return .{
            .m = .{
                .{ GF127.mul(t[1], self.m[1][1]), GF127.mul(t[1], self.m[0][1]) },
                .{ GF127.mul(t[1], self.m[1][0]), GF127.mul(t[1], self.m[0][0]) },
            },
        };
    }

    fn fromBytes(data: []const u8) !Sl2 {
        if (data.len != Size) return error.InvalidLength;
        var out = Sl2{ .m = undefined };
        var b0: [16]u8 = undefined;
        var b1: [16]u8 = undefined;
        var b2: [16]u8 = undefined;
        var b3: [16]u8 = undefined;
        @memcpy(&b0, data[0..16]);
        @memcpy(&b1, data[16..32]);
        @memcpy(&b2, data[32..48]);
        @memcpy(&b3, data[48..64]);
        out.m[0][0] = try GF127.fromBytes(b0);
        out.m[0][1] = try GF127.fromBytes(b1);
        out.m[1][0] = try GF127.fromBytes(b2);
        out.m[1][1] = try GF127.fromBytes(b3);
        return out;
    }

    fn toBytes(self: Sl2) [Size]u8 {
        var out: [Size]u8 = undefined;
        @memcpy(out[0..16], &self.m[0][0].bytes());
        @memcpy(out[16..32], &self.m[0][1].bytes());
        @memcpy(out[32..48], &self.m[1][0].bytes());
        @memcpy(out[48..64], &self.m[1][1].bytes());
        return out;
    }
};

pub fn sum(data: []const u8) [Size]u8 {
    var h = Hasher.init();
    h.update(data);
    return h.finish();
}

pub fn concat(allocator: std.mem.Allocator, hashes: []const []const u8) ![]u8 {
    var acc = Sl2{
        .m = .{
            .{ .{ .lo = 1, .hi = 0 }, .{ .lo = 0, .hi = 0 } },
            .{ .{ .lo = 0, .hi = 0 }, .{ .lo = 1, .hi = 0 } },
        },
    };
    for (hashes) |h| {
        const m = try Sl2.fromBytes(h);
        acc = Sl2.mul(acc, m);
    }
    const out = acc.toBytes();
    return try allocator.dupe(u8, &out);
}

pub fn validate(h: []const u8, hs: []const []const u8) !bool {
    if (h.len != Size or hs.len == 0) return false;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const combined = try concat(gpa.allocator(), hs);
    defer gpa.allocator().free(combined);
    return std.mem.eql(u8, h, combined);
}

test "matches go tzhash v1.8.4 reference vectors" {
    const empty = sum(&[_]u8{});
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("00000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"),
        &empty,
    );
    const one = sum(&[_]u8{0});
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("00000000000000000000000000000151000000000000000000000000000000800000000000000000000000000000008000000000000000000000000000000051"),
        &one,
    );
    const two = sum(&[_]u8{ 1, 2 });
    try std.testing.expectEqualSlices(
        u8,
        &fromHex("000000000000000000000000000139800000000000000000000000000000c0010000000000000000000000000000b98100000000000000000000000000007981"),
        &two,
    );
}

fn fromHex(comptime s: []const u8) [Size]u8 {
    comptime {
        if (s.len != Size * 2) @compileError("invalid hex length");
    }
    var out: [Size]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
