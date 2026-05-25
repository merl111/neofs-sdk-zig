const std = @import("std");
const netmap_grpc = @import("../src/proto/gen/grpc/netmap_service.zig");
const wire = @import("../src/internal/proto/encoding.zig");

test "grpc LocalNodeInfo spike call path exists" {
    // The transport layer is intentionally still a stub in this phase.
    try std.testing.expectError(error.TransportNotImplemented, netmap_grpc.Service.unaryCall("/neo.fs.v2.netmap.NetmapService/LocalNodeInfo", ""));
}

test "stable varint bytes match Go reference for value 300" {
    var out: [10]u8 = undefined;
    const n = wire.putVarint(&out, 300);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u8, 0xac), out[0]);
    try std.testing.expectEqual(@as(u8, 0x02), out[1]);
}
