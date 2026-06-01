const std = @import("std");
const contracts = @import("../walletconnect/contracts.zig");
const crypto_wif = @import("../crypto/wif.zig");
const keys = @import("../crypto/ecdsa/keys.zig");
const user = @import("../user/id.zig");
const emit = @import("emit.zig");
const hash_mod = @import("hash.zig");
const rpc = @import("rpc.zig");
const tx_mod = @import("transaction.zig");

/// Transfer GAS on N3 to the NeoFS deposit account (sidechain processing contract).
pub fn depositGas(
    allocator: std.mem.Allocator,
    io: std.Io,
    wif: []const u8,
    network: contracts.Network,
    amount_datoshi: i64,
    rpc_url: []const u8,
) ![]u8 {
    if (amount_datoshi <= 0) return error.InvalidAmount;

    const secret = try crypto_wif.decodePrivateKey(allocator, wif);
    const kp = try keys.KeyPair.fromSecretBytes(&secret);
    const owner = user.ID.fromKeyPair(kp);
    const from_hash = hash_mod.scriptHashFromAddress(owner.bytes);
    const deposit_id = try user.ID.decodeString(allocator, network.neofsAddress());
    const to_hash = hash_mod.scriptHashFromAddress(deposit_id.bytes);

    var builder = emit.Builder.init(allocator);
    defer builder.deinit(allocator);
    try builder.invokeWithAssert(allocator, try gasScriptHash(), "transfer", &.{
        .{ .hash160 = from_hash },
        .{ .hash160 = to_hash },
        .{ .int = amount_datoshi },
        .null,
    });
    const script = builder.script();

    var client = try rpc.Client.init(allocator, io, rpc_url);
    defer client.deinit();

    const version = try client.getVersion();
    const block_count = try client.getBlockCount();
    const signer_le = try hash_mod.scriptHashLeHex(allocator, from_hash);
    defer allocator.free(signer_le);

    const invoke = try client.invokeScript(script, signer_le);
    const valid_until = rpc.validUntilBlock(block_count, version.validators_count);

    const script_owned = try allocator.dupe(u8, script);
    errdefer allocator.free(script_owned);
    const signers = try allocator.alloc(tx_mod.Signer, 1);
    errdefer allocator.free(signers);
    signers[0] = .{ .account = from_hash, .scopes = .called_by_entry };
    const witnesses = try allocator.alloc(tx_mod.Witness, 1);
    errdefer allocator.free(witnesses);
    const verification = hash_mod.verificationScript(&kp.publicKeyBytes());
    const verification_copy = try allocator.dupe(u8, &verification);
    errdefer allocator.free(verification_copy);
    witnesses[0] = .{ .invocation = &.{}, .verification = verification_copy };

    var transaction = tx_mod.Transaction{
        .nonce = tx_mod.randomNonce(),
        .system_fee = invoke.gas_consumed,
        .network_fee = 0,
        .valid_until_block = valid_until,
        .signers = signers,
        .script = script_owned,
        .witnesses = witnesses,
    };

    const unsigned_bytes = try transaction.encode(allocator);
    defer allocator.free(unsigned_bytes);
    transaction.network_fee = try client.calculateNetworkFee(unsigned_bytes);

    try transaction.sign(allocator, kp, version.network_magic);
    const signed_bytes = try transaction.encode(allocator);
    defer allocator.free(signed_bytes);
    const relay_hash = try client.sendRawTransaction(signed_bytes);
    defer allocator.free(relay_hash);

    const tx_hash = try transaction.hash(allocator);
    const txid = try hashToLeHex(allocator, tx_hash);

    allocator.free(script_owned);
    allocator.free(signers);
    allocator.free(verification_copy);
    allocator.free(transaction.witnesses[0].invocation);
    allocator.free(witnesses);

    return txid;
}

fn hashToLeHex(allocator: std.mem.Allocator, hash: hash_mod.Hash256) ![]u8 {
    var reversed: [32]u8 = undefined;
    for (0..32) |i| reversed[i] = hash[31 - i];
    return std.fmt.allocPrint(allocator, "{x}", .{reversed});
}

fn gasScriptHash() !hash_mod.Hash160 {
    return hash_mod.parseLeHexHash160(contracts.gas_script_hash_be);
}

