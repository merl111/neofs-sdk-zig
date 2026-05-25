const std = @import("std");
const object = @import("../object.zig");
const checksum = @import("../../checksum/checksum.zig");

pub const Chunk = struct {
    index: u32,
    payload: []const u8,
    checksum: checksum.Checksum,
};

test {
    _ = @import("slicer_test.zig");
}

pub fn slicePayload(allocator: std.mem.Allocator, payload: []const u8, chunk_size: usize) ![]Chunk {
    if (chunk_size == 0) return error.InvalidChunkSize;
    var list: std.ArrayList(Chunk) = .{};
    errdefer list.deinit(allocator);

    var offset: usize = 0;
    var idx: u32 = 0;
    while (offset < payload.len) : (idx += 1) {
        const end = @min(offset + chunk_size, payload.len);
        const part = payload[offset..end];
        const cs = try checksum.newFromData(allocator, .sha256, part);
        try list.append(allocator, .{ .index = idx, .payload = part, .checksum = cs });
        offset = end;
    }
    return list.toOwnedSlice(allocator);
}

pub fn asObjects(allocator: std.mem.Allocator, chunks: []const Chunk) ![]object.Object {
    var list: std.ArrayList(object.Object) = .{};
    errdefer list.deinit(allocator);
    for (chunks) |chunk| {
        try list.append(allocator, .{ .payload = chunk.payload, .payload_checksum = chunk.checksum });
    }
    return list.toOwnedSlice(allocator);
}
