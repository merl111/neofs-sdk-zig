const std = @import("std");

/// Weighted random selection using Vose's alias method.
pub const Sampler = struct {
    probabilities: []f64,
    alias: []i32,
    prng: std.Random.DefaultPrng,

    pub fn init(allocator: std.mem.Allocator, weights: []const f64) !Sampler {
        const n = weights.len;
        const probabilities = try allocator.alloc(f64, n);
        errdefer allocator.free(probabilities);
        const alias = try allocator.alloc(i32, n);
        errdefer allocator.free(alias);

        var scaled = try allocator.alloc(f64, n);
        defer allocator.free(scaled);
        for (weights, 0..) |w, i| scaled[i] = w * @as(f64, @floatFromInt(n));

        var small: std.ArrayList(usize) = .{};
        defer small.deinit(allocator);
        var large: std.ArrayList(usize) = .{};
        defer large.deinit(allocator);
        for (scaled, 0..) |p, i| {
            if (p < 1.0) try small.append(allocator, i) else try large.append(allocator, i);
        }

        while (small.items.len > 0 and large.items.len > 0) {
            const l = small.pop().?;
            const g = large.pop().?;
            probabilities[l] = scaled[l];
            alias[l] = @intCast(g);
            scaled[g] = scaled[g] + scaled[l] - 1.0;
            if (scaled[g] < 1.0) try small.append(allocator, g) else try large.append(allocator, g);
        }
        while (large.items.len > 0) {
            const g = large.pop().?;
            probabilities[g] = 1.0;
        }
        while (small.items.len > 0) {
            const l = small.pop().?;
            probabilities[l] = 1.0;
        }

        var seed: u64 = undefined;
        std.crypto.random.bytes(std.mem.asBytes(&seed));
        return .{
            .probabilities = probabilities,
            .alias = alias,
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    pub fn deinit(self: *Sampler, allocator: std.mem.Allocator) void {
        allocator.free(self.probabilities);
        allocator.free(self.alias);
    }

    pub fn next(self: *Sampler) usize {
        const n = self.alias.len;
        const i = self.prng.random().intRangeLessThan(usize, 0, n);
        if (self.prng.random().float(f64) < self.probabilities[i]) return i;
        return @intCast(self.alias[i]);
    }
};

test "sampler distribution" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var sampler = try Sampler.init(gpa.allocator(), &.{ 1.0, 1.0, 1.0 });
    defer sampler.deinit(gpa.allocator());
    var counts = [_]usize{ 0, 0, 0 };
    var i: usize = 0;
    while (i < 300) : (i += 1) counts[sampler.next()] += 1;
    for (counts) |c| try std.testing.expect(c > 50);
}
