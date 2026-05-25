const std = @import("std");
const object_pb = @import("../proto/gen/object/types.pb.zig");

fn encodeMessage(comptime T: type, allocator: std.mem.Allocator, msg: T) ![]u8 {
    var w: std.Io.Writer.Allocating = .init(allocator);
    defer w.deinit();
    try msg.encode(&w.writer, allocator);
    return allocator.dupe(u8, w.written());
}

test "golden object get body bytes match neofs-sdk-go fixture" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const body = object_pb.GetRequest.Body{
        .address = .{
            .container_id = .{ .value = try allocator.dupe(u8, "any_container") },
            .object_id = .{ .value = try allocator.dupe(u8, "any_object") },
        },
        .raw = true,
    };
    defer {
        var mutable = body;
        mutable.deinit(allocator);
    }

    const encoded = try encodeMessage(object_pb.GetRequest.Body, allocator, body);
    defer allocator.free(encoded);

    const expected = [_]u8{
        10, 31, 10, 15, 10, 13, 97, 110, 121, 95, 99, 111, 110, 116, 97, 105, 110, 101, 114,
        18, 12, 10, 10, 97, 110, 121, 95, 111, 98, 106, 101, 99, 116, 16, 1,
    };
    try std.testing.expectEqualSlices(u8, &expected, encoded);
}
