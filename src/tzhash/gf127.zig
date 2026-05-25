const std = @import("std");

pub const Size: usize = 16;

const msb64: u64 = 1 << 63;
const x127x631 = GF127{ .lo = msb64 + 1, .hi = msb64 };

/// Element of GF(2^127) represented as lo + hi * x^64.
pub const GF127 = struct {
    lo: u64 = 0,
    hi: u64 = 0,

    pub fn add(a: GF127, b: GF127) GF127 {
        return .{ .lo = a.lo ^ b.lo, .hi = a.hi ^ b.hi };
    }

    pub fn mul(a: GF127, b: GF127) GF127 {
        var r = GF127{};
        var d = a;
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            if ((b.lo & (@as(u64, 1) << @intCast(i))) != 0) {
                r = add(r, d);
            }
            d = mul10(d);
        }
        i = 0;
        while (i < 63) : (i += 1) {
            if ((b.hi & (@as(u64, 1) << @intCast(i))) != 0) {
                r = add(r, d);
            }
            d = mul10(d);
        }
        return r;
    }

    pub fn mul10(a: GF127) GF127 {
        const c = a.lo >> 63;
        var b = GF127{
            .lo = a.lo << 1,
            .hi = (a.hi << 1) ^ c,
        };
        const mask = b.hi & msb64;
        b.lo ^= mask | (mask >> 63);
        b.hi ^= mask;
        return b;
    }

    pub fn mul11(a: GF127) GF127 {
        const c = a.lo >> 63;
        var b = GF127{
            .lo = a.lo ^ (a.lo << 1),
            .hi = a.hi ^ (a.hi << 1) ^ c,
        };
        const mask = b.hi & msb64;
        b.lo ^= mask | (mask >> 63);
        b.hi ^= mask;
        return b;
    }

    pub fn inv(a: GF127) GF127 {
        var u = a;
        var v = x127x631;
        var c = GF127{ .lo = 1, .hi = 0 };
        var d = GF127{};

        while (msb(u) != 0) {
            var du = msb(u);
            const dv = msb(v);
            if (du < dv) {
                const tu = u;
                u = v;
                v = tu;
                du = dv;
                const tc = c;
                c = d;
                d = tc;
            }

            const x = xN(du - dv);
            u = add(u, mul(x, v));
            if (msb(u) == 127) {
                u = add(u, x127x631);
            }
            c = add(c, mul(x, d));
        }
        return c;
    }

    pub fn bytes(self: GF127) [Size]u8 {
        var out: [Size]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], self.hi, .big);
        std.mem.writeInt(u64, out[8..16], self.lo, .big);
        return out;
    }

    pub fn fromBytes(data: [Size]u8) !GF127 {
        const hi = std.mem.readInt(u64, data[0..8], .big);
        const lo = std.mem.readInt(u64, data[8..16], .big);
        if (hi & msb64 != 0) return error.InvalidMsb;
        return .{ .lo = lo, .hi = hi };
    }
};

fn msb(a: GF127) u7 {
    const leading = @clz(a.hi);
    if (leading == 64) {
        return @intCast(127 - @clz(a.lo));
    }
    return @intCast(127 - leading);
}

fn xN(n: u7) GF127 {
    if (n < 64) {
        return .{ .lo = @as(u64, 1) << @intCast(n), .hi = 0 };
    }
    return .{ .lo = 0, .hi = @as(u64, 1) << @intCast(n - 64) };
}

test "gf127 mul identity" {
    const one = GF127{ .lo = 1, .hi = 0 };
    const a = GF127{ .lo = 0x1234, .hi = 0x5678 };
    try std.testing.expect(a.lo == GF127.mul(a, one).lo);
}
