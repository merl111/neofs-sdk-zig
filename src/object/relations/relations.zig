const std = @import("std");

pub const Relation = struct {
    parent: [32]u8,
    child: [32]u8,
};

pub fn linearChain(allocator: std.mem.Allocator, ids: []const [32]u8) ![]Relation {
    if (ids.len < 2) return allocator.alloc(Relation, 0);
    var out = try allocator.alloc(Relation, ids.len - 1);
    var i: usize = 0;
    while (i + 1 < ids.len) : (i += 1) {
        out[i] = .{ .parent = ids[i], .child = ids[i + 1] };
    }
    return out;
}
