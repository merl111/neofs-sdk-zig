//! Parse and verify a placement policy (no network required).
const std = @import("std");
const sdk = @import("neofs_sdk");

const sample_policy =
    \\REP 1 IN X
    \\CBF 1
    \\SELECT 2 IN SAME Location FROM * AS X
;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var parsed = try sdk.netmap.policy.decodeString(allocator, sample_policy);
    defer sdk.netmap.policy.deinitPolicy(&parsed, allocator);
    try sdk.netmap.policy.verifyPolicy(allocator, parsed);

    const analysis = sdk.container_placement.analyzeParsed(parsed);
    var stdout_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &stdout_buf);
    try stdout.writeAll("Policy OK:\n");
    try sdk.container_placement.printPolicyAnalysis(stdout, analysis);

    const wire = try sdk.container_placement.stableFromParsed(allocator, parsed);
    defer sdk.container_placement.deinitPlacementPolicy(allocator, wire);
    try stdout.print("Wire: {d} replica(s), {d} selector(s), {d} filter(s), CBF {d}\n", .{
        wire.replicas.len,
        wire.selectors.len,
        wire.filters.len,
        wire.backup_factor,
    });
}
