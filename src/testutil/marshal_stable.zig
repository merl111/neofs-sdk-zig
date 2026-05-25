//! Round-trip and determinism tests for protobuf messages (Go prototest.TestMarshalStable).
const std = @import("std");

pub fn encodeMessage(
    comptime Msg: type,
    allocator: std.mem.Allocator,
    msg: Msg,
) ![]u8 {
    var w: std.Io.Writer.Allocating = .init(allocator);
    defer w.deinit();
    try msg.encode(&w.writer, allocator);
    return try allocator.dupe(u8, w.written());
}

pub fn decodeMessage(
    comptime Msg: type,
    allocator: std.mem.Allocator,
    data: []const u8,
) !Msg {
    var reader = std.Io.Reader.fixed(data);
    return try Msg.decode(&reader, allocator);
}

/// Encodes, decodes, re-encodes; requires identical bytes on second encode.
pub fn testRoundTrip(comptime Msg: type, allocator: std.mem.Allocator, msg: Msg) !void {
    const encoded = try encodeMessage(Msg, allocator, msg);
    defer allocator.free(encoded);

    var decoded = try decodeMessage(Msg, allocator, encoded);
    defer decoded.deinit(allocator);

    const reencoded = try encodeMessage(Msg, allocator, decoded);
    defer allocator.free(reencoded);

    try std.testing.expectEqualSlices(u8, encoded, reencoded);
}

/// Verifies protobuf field tags are in ascending order (NeoFS stable marshal contract).
pub fn expectAscendingFieldTags(data: []const u8) !void {
    var off: usize = 0;
    var prev: i32 = -1;
    while (off < data.len) {
        const tag = try readVarint(data[off..]);
        const tag_len = varintLen(data[off..]);
        off += tag_len;
        const field_num: i32 = @intCast(tag >> 3);
        if (field_num <= prev) return error.FieldOrderViolation;
        prev = field_num;
        const wire_type = tag & 7;
        off += try skipField(data[off..], wire_type);
    }
}

fn readVarint(data: []const u8) !u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    for (data) |b| {
        result |= @as(u64, b & 0x7f) << shift;
        if ((b & 0x80) == 0) return result;
        shift += 7;
        if (shift > 63) return error.InvalidVarint;
    }
    return error.InvalidVarint;
}

fn varintLen(data: []const u8) usize {
    var i: usize = 0;
    while (i < data.len and (data[i] & 0x80) != 0) : (i += 1) {}
    return i + 1;
}

fn skipField(data: []const u8, wire_type: u64) !usize {
    return switch (wire_type) {
        0 => varintLen(data),
        1 => 8,
        2 => blk: {
            const len = try readVarint(data);
            const len_len = varintLen(data);
            break :blk len_len + @as(usize, @intCast(len));
        },
        5 => 4,
        else => error.UnsupportedWireType,
    };
}
