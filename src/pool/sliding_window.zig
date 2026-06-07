const std = @import("std");
const clock = @import("../util/clock.zig");

/// Sliding-window error counter for node health monitoring.
pub const SlidingWindow = struct {
    window_ns: i64,
    limit: i64,
    prev_count: i64 = 0,
    curr_count: i64 = 0,
    window_start_ns: i64,
    locked: std.atomic.Value(bool) = .init(false),

    pub fn init(window_ns: i64, limit: i64) SlidingWindow {
        return .{
            .window_ns = window_ns,
            .limit = limit,
            .window_start_ns = @intCast(clock.nanoTimestamp()),
        };
    }

    pub fn allow(self: *SlidingWindow) bool {
        const now: i64 = @intCast(clock.nanoTimestamp());
        self.advance(now);
        self.curr_count += 1;
        const elapsed = now - self.window_start_ns;
        if (elapsed >= self.window_ns) return self.curr_count < self.limit;
        const weighted_prev = @divTrunc(self.prev_count * (self.window_ns - elapsed), self.window_ns);
        return (self.curr_count + weighted_prev) < self.limit;
    }

    pub fn current(self: *const SlidingWindow) i64 {
        return self.curr_count;
    }

    fn advance(self: *SlidingWindow, now: i64) void {
        if (now - self.window_start_ns < self.window_ns) return;
        while (self.locked.cmpxchgStrong(false, true, .acquire, .monotonic) != null) {
            std.Thread.yield() catch {};
        }
        defer self.locked.store(false, .release);
        const start = self.window_start_ns;
        const elapsed = now - start;
        if (elapsed < self.window_ns) return;
        if (elapsed < self.window_ns * 2) {
            self.prev_count = self.curr_count;
        } else {
            self.prev_count = 0;
        }
        self.curr_count = 0;
        self.window_start_ns = now - @rem(now, self.window_ns);
    }
};

test "sliding window threshold" {
    var sw = SlidingWindow.init(1_000_000_000, 4);
    try std.testing.expect(sw.allow());
    try std.testing.expect(sw.allow());
    try std.testing.expect(sw.allow());
    try std.testing.expect(!sw.allow());
}
