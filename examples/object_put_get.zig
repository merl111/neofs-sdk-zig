const std = @import("std");
const sdk = @import("neofs_sdk");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var client = sdk.client.Client.init(allocator);
    defer client.deinit();
    try client.dial(init.io, "grpc://localhost:8080", false, 10_000);

    const object_id = try client.objectPut(.{
        .payload = "hello neofs",
    });
    _ = try client.objectGet(object_id);
}
