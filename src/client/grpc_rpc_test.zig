const std = @import("std");
const testing = std.testing;
const grpc_rpc = @import("grpc_rpc.zig");
const mock_transport = @import("mock_transport.zig");
const request = @import("request.zig");
const container_init = @import("../container/init.zig");
const crypto_ecdsa = @import("../crypto/ecdsa/keys.zig");
const user = @import("../user/id.zig");
const netmap_pb = @import("../proto/gen/netmap/types.pb.zig");
const container_pb = @import("../proto/gen/container/types.pb.zig");

fn verifyRequestRoundTrip(comptime RequestType: type, request_bytes: []const u8) !void {
    const allocator = std.testing.allocator;

    var reader = std.Io.Reader.fixed(request_bytes);
    var decoded = try RequestType.decode(&reader, allocator);
    defer decoded.deinit(allocator);
    try request.verifySignedRequestMessage(decoded);

    var w: std.Io.Writer.Allocating = .init(allocator);
    defer w.deinit();
    try decoded.encode(&w.writer, allocator);
    var reader2 = std.Io.Reader.fixed(w.written());
    var decoded2 = try RequestType.decode(&reader2, allocator);
    defer decoded2.deinit(allocator);
    try request.verifySignedRequestMessage(decoded2);
}

fn networkInfoSuccessResponse(allocator: std.mem.Allocator, epoch: u64) ![]u8 {
    const resp = netmap_pb.NetworkInfoResponse{
        .body = .{
            .network_info = .{
                .current_epoch = epoch,
            },
        },
        .meta_header = .{
            .status = .{
                .code = 0,
                .message = "",
            },
        },
    };
    return try mock_transport.Client.encodeResponse(allocator, resp);
}

fn containerPutSuccessResponse(allocator: std.mem.Allocator, container_id: [32]u8) ![]u8 {
    var resp = container_pb.PutResponse{
        .body = .{
            .container_id = .{
                .value = try allocator.dupe(u8, &container_id),
            },
        },
        .meta_header = .{
            .status = .{
                .code = 0,
                .message = "",
            },
        },
    };
    defer resp.deinit(allocator);
    return try mock_transport.Client.encodeResponse(allocator, resp);
}

test "networkInfo records signed NetworkInfoRequest bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var mock = mock_transport.Client.init(allocator);
    defer mock.deinit();

    const resp_bytes = try networkInfoSuccessResponse(allocator, 1234);
    defer allocator.free(resp_bytes);
    try mock.setResponse("/neo.fs.v2.netmap.NetmapService/NetworkInfo", resp_bytes);

    const epoch = try grpc_rpc.networkInfo(allocator, &mock, "grpc-rpc-test-signer");
    try testing.expectEqual(@as(u64, 1234), epoch);
    try testing.expectEqual(@as(usize, 1), mock.callCount());

    const call = mock.lastCall() orelse return error.TestExpectedRecordedCall;
    try testing.expectEqualStrings("/neo.fs.v2.netmap.NetmapService/NetworkInfo", call.path);
    try verifyRequestRoundTrip(netmap_pb.NetworkInfoRequest, call.request);
}

test "containerPut records signed PutRequest bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const owner_seed = [_]u8{0x61} ** 32;
    const owner_kp = try crypto_ecdsa.KeyPair.fromSeed(owner_seed);
    const owner = user.ID.fromCompressedPublicKey(owner_kp.publicKeyBytes());

    const nonce = try container_init.randomNonce(allocator);
    defer allocator.free(nonce);
    const cont = try container_init.newContainer(allocator, owner, nonce, "grpc-rpc-test");
    defer container_init.deinitContainer(allocator, cont);

    var expected_cid: [32]u8 = undefined;
    @memset(&expected_cid, 0xAB);

    var mock = mock_transport.Client.init(allocator);
    defer mock.deinit();

    const resp_bytes = try containerPutSuccessResponse(allocator, expected_cid);
    defer allocator.free(resp_bytes);
    try mock.setResponse("/neo.fs.v2.container.ContainerService/Put", resp_bytes);

    const cid = try grpc_rpc.containerPut(allocator, &mock, &owner_seed, cont);
    try testing.expectEqual(expected_cid, cid);
    try testing.expectEqual(@as(usize, 1), mock.callCount());

    const call = mock.lastCall() orelse return error.TestExpectedRecordedCall;
    try testing.expectEqualStrings("/neo.fs.v2.container.ContainerService/Put", call.path);
    try verifyRequestRoundTrip(container_pb.PutRequest, call.request);

    var reader = std.Io.Reader.fixed(call.request);
    var decoded = try container_pb.PutRequest.decode(&reader, allocator);
    defer decoded.deinit(allocator);
    try testing.expect(decoded.body != null);
    try testing.expect(decoded.body.?.container != null);
    try testing.expect(decoded.verify_header != null);
    try testing.expect(decoded.meta_header != null);
    try testing.expectEqual(request.default_request_ttl, decoded.meta_header.?.ttl);
}
