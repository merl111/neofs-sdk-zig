const std = @import("std");
const sdk = @import("neofs_sdk");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var client = sdk.client.Client.init(gpa.allocator());
    defer client.deinit();
    try client.dial("grpc://localhost:8080", false, 10_000);
    std.debug.print("connected to {s}\n", .{"grpc://localhost:8080"});
}
