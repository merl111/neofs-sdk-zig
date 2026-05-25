const std = @import("std");
const accounting_pb = @import("proto/gen/accounting/types.pb.zig");
const accounting_service = @import("proto/gen/accounting/service.zig");
const wire = @import("internal/proto/encoding.zig");

test "generated protobuf type is usable" {
    var d = accounting_pb.Decimal{};
    d.value = 42;
    d.precision = 2;
    try std.testing.expectEqual(@as(i64, 42), d.value);
    try std.testing.expectEqual(@as(u32, 2), d.precision);
}

test "generated service VTable is usable" {
    const UserData = struct { calls: usize = 0 };
    const Err = error{Denied};
    const V = accounting_service.AccountingService(UserData, Err);
    const Server = accounting_service.AccountingServiceServer(UserData, Err);
    const Client = accounting_service.AccountingServiceClient(UserData, Err);
    try std.testing.expectEqualStrings("AccountingService", V.service_name);

    const impl = struct {
        fn call(ud: *UserData, req: accounting_pb.BalanceRequest) Err!accounting_pb.BalanceResponse {
            _ = req;
            ud.calls += 1;
            return .{};
        }
    }.call;
    var userdata = UserData{};
    var server = Server.init(&userdata, .{ .Balance = impl });
    var client = Client.init(&server);
    const response = try client.Balance(.{});
    _ = response;
    try std.testing.expectEqual(@as(usize, 1), userdata.calls);
}

test "stable varint bytes match Go reference for value 300" {
    var out: [10]u8 = undefined;
    const n = wire.putVarint(&out, 300);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u8, 0xac), out[0]);
    try std.testing.expectEqual(@as(u8, 0x02), out[1]);
}
