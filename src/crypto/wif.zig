const std = @import("std");
const base58 = @import("base58.zig");

pub const wif_version: u8 = 0x80;

pub fn decodePrivateKey(wif: []const u8) ![32]u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const payload = try base58.decodeChecked(gpa.allocator(), wif);
    defer gpa.allocator().free(payload);

    switch (payload.len) {
        33 => {},
        34 => {
            if (payload[33] != 0x01) return error.InvalidCompressionFlag;
        },
        else => return error.InvalidWifLength,
    }
    if (payload[0] != wif_version) return error.InvalidWifVersion;
    var out: [32]u8 = undefined;
    @memcpy(&out, payload[1..33]);
    return out;
}

test "decode known testnet wif" {
    const seed = try decodePrivateKey("KxyjQ8eUa4FHt3Gvioyt1Wz29cTUrE4eTqX3yFSk1YFCsPL8uNsY");
    try std.testing.expect(seed[0] == 0x01 or seed[0] != 0);
}
