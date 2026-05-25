const std = @import("std");
const wc_crypto = @import("crypto.zig");

pub const Pairing = struct {
    topic: []u8,
    sym_key_hex: []u8,
    relay_protocol: []const u8 = "irn",
    expiry_timestamp: u64,

    pub fn deinit(self: *Pairing, allocator: std.mem.Allocator) void {
        allocator.free(self.topic);
        allocator.free(self.sym_key_hex);
        self.* = undefined;
    }
};

pub const compatibility_version: u8 = 3;

pub fn newPairing(allocator: std.mem.Allocator, now: u64, ttl_secs: u64) !Pairing {
    const sym_key_raw = try allocator.alloc(u8, 32);
    defer allocator.free(sym_key_raw);
    std.crypto.random.bytes(sym_key_raw);
    const sym_key_hex = try wc_crypto.encodeHex(allocator, sym_key_raw);
    errdefer allocator.free(sym_key_hex);
    const topic = try wc_crypto.sha256Hex(allocator, sym_key_raw);
    errdefer allocator.free(topic);
    return .{
        .topic = topic,
        .sym_key_hex = sym_key_hex,
        .expiry_timestamp = now + ttl_secs,
    };
}

pub fn topicFromSymKey(allocator: std.mem.Allocator, sym_key_hex: []const u8) ![]u8 {
    const sym_key_raw = try wc_crypto.decodeHex(allocator, sym_key_hex);
    defer allocator.free(sym_key_raw);
    return wc_crypto.sha256Hex(allocator, sym_key_raw);
}

pub fn buildUri(
    allocator: std.mem.Allocator,
    pairing: Pairing,
    methods: []const []const u8,
) ![]u8 {
    var methods_csv = std.ArrayList(u8){};
    defer methods_csv.deinit(allocator);
    for (methods, 0..) |m, i| {
        if (i != 0) try methods_csv.appendSlice(allocator, "],[");
        try methods_csv.appendSlice(allocator, m);
    }
    return std.fmt.allocPrint(
        allocator,
        "wc:{s}@2?symKey={s}&methods=[{s}]&relay-protocol={s}&expiryTimestamp={d}&wccv={d}",
        .{ pairing.topic, pairing.sym_key_hex, methods_csv.items, pairing.relay_protocol, pairing.expiry_timestamp, compatibility_version },
    );
}

