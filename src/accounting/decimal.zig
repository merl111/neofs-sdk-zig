const std = @import("std");

pub const Decimal = struct {
    value: i64,
    precision: u32,

    pub fn init(value: i64, precision: u32) Decimal {
        return .{ .value = value, .precision = precision };
    }

    pub fn fromProto(value: i64, precision: u32) Decimal {
        return .{ .value = value, .precision = precision };
    }

    pub fn add(self: Decimal, other: Decimal) !Decimal {
        if (self.precision != other.precision) return error.PrecisionMismatch;
        return .{ .value = self.value + other.value, .precision = self.precision };
    }

    pub fn formatString(self: Decimal, allocator: std.mem.Allocator) ![]u8 {
        if (self.precision == 0) {
            return std.fmt.allocPrint(allocator, "{d}", .{self.value});
        }
        if (self.value < 0) return error.NegativeValue;

        var pow: i64 = 1;
        var i: u32 = 0;
        while (i < self.precision) : (i += 1) pow *= 10;

        const int_part = @divTrunc(self.value, pow);
        const frac_part: u64 = @intCast(@rem(self.value, pow));

        const digits = try std.fmt.allocPrint(allocator, "{d}", .{frac_part});
        defer allocator.free(digits);

        const prec: usize = @intCast(self.precision);
        var padded = try allocator.alloc(u8, prec);
        defer allocator.free(padded);
        const pad_count = prec - @min(prec, digits.len);
        @memset(padded[0..pad_count], '0');
        @memcpy(padded[pad_count..][0..digits.len], digits);

        var end = padded.len;
        while (end > 0 and padded[end - 1] == '0') end -= 1;
        if (end == 0) {
            return std.fmt.allocPrint(allocator, "{d}", .{int_part});
        }
        return std.fmt.allocPrint(allocator, "{d}.{s}", .{ int_part, padded[0..end] });
    }
};

test "decimal add" {
    const a = Decimal.init(1000, 2);
    const b = Decimal.init(250, 2);
    const c = try a.add(b);
    try std.testing.expectEqual(@as(i64, 1250), c.value);
}

test "decimal format gas" {
    const allocator = std.testing.allocator;

    const whole = try Decimal.init(100_000_000, 8).formatString(allocator);
    defer allocator.free(whole);
    try std.testing.expectEqualStrings("1", whole);

    const frac = try Decimal.init(5, 8).formatString(allocator);
    defer allocator.free(frac);
    try std.testing.expectEqualStrings("0.00000005", frac);
}
