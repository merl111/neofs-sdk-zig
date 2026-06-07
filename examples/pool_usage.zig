const std = @import("std");
const sdk = @import("neofs_sdk");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var p = sdk.pool.Pool.init(allocator, init.io);
    defer p.deinit();

    try p.addNode(.{ .endpoint = "grpc://node-a:8080" });
    try p.addNode(.{ .endpoint = "grpc://node-b:8080" });
    try p.dial();
}
