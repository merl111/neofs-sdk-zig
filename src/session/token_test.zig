const std = @import("std");
const session = @import("token.zig");

test "session token new sets epochs and verb" {
    const tok = session.new(.put, 10, 20);
    try std.testing.expectEqual(session.Verb.put, tok.verb);
    try std.testing.expectEqual(@as(u64, 10), tok.nbf_epoch);
    try std.testing.expectEqual(@as(u64, 20), tok.exp_epoch);
    try std.testing.expect(!std.mem.eql(u8, &tok.id, &([_]u8{0} ** 16)));
}

test "session token ids are unique" {
    const a = session.new(.get, 1, 2);
    const b = session.new(.get, 1, 2);
    try std.testing.expect(!std.mem.eql(u8, &a.id, &b.id));
}
