pub const Trust = struct {
    peer_id: []const u8,
    value: f64,
};

pub const PeerToPeerTrust = struct {
    trusting_peer_id: []const u8,
    trust: Trust,
};

pub const GlobalTrust = struct {
    manager_peer_id: []const u8,
    trust: Trust,
};

test "reputation structs carry trust values" {
    const t: Trust = .{ .peer_id = "peer-a", .value = 0.5 };
    const p2p: PeerToPeerTrust = .{
        .trusting_peer_id = "peer-b",
        .trust = t,
    };
    const global: GlobalTrust = .{
        .manager_peer_id = "manager",
        .trust = t,
    };

    try @import("std").testing.expect(p2p.trust.value == global.trust.value);
}
