const std = @import("std");

pub fn syscallId(name: []const u8) u32 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &hash, .{});
    return std.mem.readInt(u32, hash[0..4], .little);
}
