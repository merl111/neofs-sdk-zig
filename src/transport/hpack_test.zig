const std = @import("std");
const hpack = @import("hpack.zig");

test "hpack decodes indexed static table entry" {
    const allocator = std.testing.allocator;

    var decoder: hpack.Decoder = .{ .allocator = allocator };
    defer decoder.deinit();

    // Index 8 in the static table is :status = 200.
    const input = [_]u8{0x88};
    const headers = try decoder.decode(&input);
    defer decoder.freeHeaders(headers);

    try std.testing.expectEqual(@as(usize, 1), headers.len);
    try std.testing.expectEqualStrings(":status", headers[0].name);
    try std.testing.expectEqualStrings("200", headers[0].value);
}

test "hpack decodes literal grpc trailer headers" {
    const allocator = std.testing.allocator;

    var decoder: hpack.Decoder = .{ .allocator = allocator };
    defer decoder.deinit();

    const input = [_]u8{
        0x00, 0x0b, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's',
        0x01, '0',
        0x00, 0x0c, 'g', 'r', 'p', 'c', '-', 'm', 'e', 's', 's', 'a', 'g', 'e',
        0x02, 'o', 'k',
    };
    const headers = try decoder.decode(&input);
    defer decoder.freeHeaders(headers);

    try std.testing.expectEqual(@as(usize, 2), headers.len);
    try std.testing.expectEqualStrings("grpc-status", headers[0].name);
    try std.testing.expectEqualStrings("0", headers[0].value);
    try std.testing.expectEqualStrings("grpc-message", headers[1].name);
    try std.testing.expectEqualStrings("ok", headers[1].value);
}

test "hpack rejects invalid indexed representation" {
    const allocator = std.testing.allocator;

    var decoder: hpack.Decoder = .{ .allocator = allocator };
    defer decoder.deinit();

    const input = [_]u8{0x80};
    try std.testing.expectError(error.InvalidHpack, decoder.decode(&input));
}
