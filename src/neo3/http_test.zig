const std = @import("std");
const http = @import("http.zig");

test "live n3 getblockcount" {
    var io_ctx = std.Io.Threaded.init(std.testing.allocator, .{});
    defer io_ctx.deinit();
    const body = try http.post(
        std.testing.allocator,
        io_ctx.io(),
        "http://seed1t5.neo.org:20332",
        "application/json",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":[]}",
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"result\"") != null);
}
