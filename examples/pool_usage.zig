const std = @import("std");
const sdk = @import("neofs_sdk");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var p = sdk.pool.Pool.init(gpa.allocator());
    defer p.deinit();

    try p.addNode(.{ .endpoint = "grpc://node-a:8080" });
    try p.addNode(.{ .endpoint = "grpc://node-b:8080" });
    try p.dial();
}
