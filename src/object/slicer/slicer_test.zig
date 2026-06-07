const std = @import("std");
const slicer = @import("slicer.zig");

test "slice payload into chunks with checksums" {
    const allocator = std.testing.allocator;

    const payload = "abcdefghij";
    const chunks = try slicer.slicePayload(allocator, payload, 4);
    defer {
        for (chunks) |c| allocator.free(c.checksum.value);
        allocator.free(chunks);
    }

    try std.testing.expectEqual(@as(usize, 3), chunks.len);
    try std.testing.expectEqualStrings("abcd", chunks[0].payload);
    try std.testing.expectEqualStrings("efgh", chunks[1].payload);
    try std.testing.expectEqualStrings("ij", chunks[2].payload);
    try std.testing.expectEqual(@as(u32, 0), chunks[0].index);
    try std.testing.expectEqual(@as(u32, 2), chunks[2].index);
}

test "zero chunk size is rejected" {
    try std.testing.expectError(error.InvalidChunkSize, slicer.slicePayload(std.testing.allocator, "x", 0));
}
