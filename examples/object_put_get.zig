const std = @import("std");
const sdk = @import("neofs_sdk");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = sdk.client.Client.init(allocator);
    client.dial("grpc://localhost:8080", false, 10_000);

    const object_id = try client.objectPut(.{
        .payload = "hello neofs",
    });
    _ = try client.objectGet(object_id);
}
