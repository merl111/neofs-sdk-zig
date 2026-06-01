const std = @import("std");
const crypto_wif = @import("../crypto/wif.zig");
const keys = @import("../crypto/ecdsa/keys.zig");
const user = @import("../user/id.zig");
const emit = @import("emit.zig");
const hash_mod = @import("hash.zig");
const contracts = @import("../walletconnect/contracts.zig");

test "transfer script builder smoke" {
    const wif = "KzdwXaE24ehicH5cE8omKKtM19Lhaq6WJbKE1aa44Zmemw8yJS4T";
    const secret = try crypto_wif.decodePrivateKey(std.testing.allocator, wif);
    const kp = try keys.KeyPair.fromSecretBytes(&secret);
    const owner = user.ID.fromKeyPair(kp);
    const owner_addr = try owner.encodeToString(std.testing.allocator);
    defer std.testing.allocator.free(owner_addr);
    try std.testing.expectEqualStrings("NjCLHJskkdJexGR91DoiiwafKCuUCgVTZF", owner_addr);

    const from_hash = hash_mod.scriptHashFromAddress(owner.bytes);
    const deposit_id = try user.ID.decodeString(std.testing.allocator, contracts.Network.testnet.neofsAddress());
    const to_hash = hash_mod.scriptHashFromAddress(deposit_id.bytes);
    const gas_hash = try hash_mod.parseLeHexHash160(contracts.gas_script_hash_be);

    var builder = emit.Builder.init(std.testing.allocator);
    defer builder.deinit(std.testing.allocator);
    try builder.invokeWithAssert(std.testing.allocator, gas_hash, "transfer", &.{
        .{ .hash160 = from_hash },
        .{ .hash160 = to_hash },
        .{ .int = 10_000_000 },
        .null,
    });
    try std.testing.expect(builder.script().len > 20);
}

test "deposit addresses match script hashes" {
    inline for (.{
        .{ contracts.Network.mainnet, "NNxVrKjLsRkWsmGgmuNXLcMswtxTGaNQLk", "2cafa46838e8b564468ebd868dcafdd99dce6221" },
        .{ contracts.Network.testnet, "NZAUkYbJ1Cb2HrNmwZ1pg9xYHBhm2FgtKV", "3c3f4b84773ef0141576e48c3ff60e5078235891" },
    }) |case| {
        const network, const addr, const le_hex = case;
        try std.testing.expectEqualStrings(addr, network.neofsAddress());
        const id = try user.ID.decodeString(std.testing.allocator, addr);
        const hash = hash_mod.scriptHashFromAddress(id.bytes);
        const parsed = try hash_mod.parseLeHexHash160("0x" ++ le_hex);
        try std.testing.expectEqual(parsed, hash);
    }
}
