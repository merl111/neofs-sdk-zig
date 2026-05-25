const std = @import("std");

pub const Version = struct {
    major: u32,
    minor: u32,

    pub fn init(major: u32, minor: u32) Version {
        return .{ .major = major, .minor = minor };
    }

    pub fn format(self: Version, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("v{d}.{d}", .{ self.major, self.minor });
    }
};

pub fn current() Version {
    return Version.init(2, 22);
}

test "current version is v2.22" {
    const v = current();
    try std.testing.expectEqual(@as(u32, 2), v.major);
    try std.testing.expectEqual(@as(u32, 22), v.minor);
}
