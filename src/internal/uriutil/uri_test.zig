const std = @import("std");
const uri = @import("uri.zig");

test "parse grpc and grpcs endpoints" {
    const cases = [_]struct {
        input: []const u8,
        host: []const u8,
        tls: bool,
    }{
        .{ .input = "127.0.0.1:8080", .host = "127.0.0.1:8080", .tls = false },
        .{ .input = "grpc://127.0.0.1:8080", .host = "127.0.0.1:8080", .tls = false },
        .{ .input = "grpcs://127.0.0.1:8082", .host = "127.0.0.1:8082", .tls = true },
    };

    for (cases) |tc| {
        const parsed = try uri.parse(tc.input);
        try std.testing.expectEqualStrings(tc.host, parsed.host);
        try std.testing.expectEqual(tc.tls, parsed.tls);
    }
}

test "parse rejects missing port" {
    try std.testing.expectError(error.MissingPort, uri.parse("127.0.0.1"));
    try std.testing.expectError(error.MissingPort, uri.parse("grpc://127.0.0.1"));
}
