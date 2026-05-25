const digest = @import("digest.zig");

pub const Size = digest.Size;
pub const Hasher = digest.Hasher;

pub fn sum(data: []const u8) [Size]u8 {
    return digest.sum(data);
}

pub fn concat(allocator: @import("std").mem.Allocator, hashes: []const []const u8) ![]u8 {
    return digest.concat(allocator, hashes);
}

pub fn validate(h: []const u8, hs: []const []const u8) !bool {
    return digest.validate(h, hs);
}
