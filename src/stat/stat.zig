const std = @import("std");

pub const Method = enum {
    balance_get,
    container_put,
    container_get,
    object_put,
    object_get,
};

pub const OperationStat = struct {
    method: Method,
    ok: bool,
    elapsed_ms: u64,
};

pub const SnapshotEntry = struct {
    method: Method,
    total: usize,
    failed: usize,
};

pub const Monitor = struct {
    allocator: std.mem.Allocator,
    totals: std.AutoHashMap(Method, usize),
    failures: std.AutoHashMap(Method, usize),

    pub fn init(allocator: std.mem.Allocator) Monitor {
        return .{
            .allocator = allocator,
            .totals = std.AutoHashMap(Method, usize).init(allocator),
            .failures = std.AutoHashMap(Method, usize).init(allocator),
        };
    }

    pub fn deinit(self: *Monitor) void {
        self.totals.deinit();
        self.failures.deinit();
    }

    pub fn record(self: *Monitor, item: OperationStat) !void {
        const total = try self.totals.getOrPut(item.method);
        if (!total.found_existing) total.value_ptr.* = 0;
        total.value_ptr.* += 1;
        if (!item.ok) {
            const fail = try self.failures.getOrPut(item.method);
            if (!fail.found_existing) fail.value_ptr.* = 0;
            fail.value_ptr.* += 1;
        }
    }

    pub fn snapshot(self: *Monitor, allocator: std.mem.Allocator) ![]SnapshotEntry {
        var out: std.ArrayList(SnapshotEntry) = .{};
        var it = self.totals.iterator();
        while (it.next()) |entry| {
            try out.append(allocator, .{
                .method = entry.key_ptr.*,
                .total = entry.value_ptr.*,
                .failed = self.failures.get(entry.key_ptr.*) orelse 0,
            });
        }
        return out.toOwnedSlice(allocator);
    }
};

test "monitor accumulates totals and failures" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var mon = Monitor.init(allocator);
    defer mon.deinit();

    try mon.record(.{ .method = .container_put, .ok = true, .elapsed_ms = 1 });
    try mon.record(.{ .method = .container_put, .ok = false, .elapsed_ms = 2 });

    const snap = try mon.snapshot(allocator);
    defer allocator.free(snap);
    try std.testing.expectEqual(@as(usize, 1), snap.len);
    try std.testing.expectEqual(@as(usize, 2), snap[0].total);
    try std.testing.expectEqual(@as(usize, 1), snap[0].failed);
}
