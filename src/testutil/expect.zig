const std = @import("std");

pub fn errMsg(err: anyerror) []const u8 {
    return @errorName(err);
}

pub fn expectErrorContains(comptime expected_substring: []const u8, err: anyerror) !void {
    const msg = errMsg(err);
    if (std.mem.indexOf(u8, msg, expected_substring) == null and
        std.mem.indexOf(u8, @errorName(err), expected_substring) == null)
    {
        return error.TestExpectedError;
    }
}

test "expectErrorContains matches error name" {
    try expectErrorContains("OutOfMemory", error.OutOfMemory);
}
