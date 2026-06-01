const std = @import("std");

pub const gas_script_hash_be = "0xd2a4cff31913016155e38e474a2c06d08be276cf";

pub const Network = enum {
    mainnet,
    testnet,

    /// Script hash (LE hex) of the NeoFS sidechain deposit account (processing contract).
    pub fn neofsScriptHashLe(self: Network) []const u8 {
        return switch (self) {
            .mainnet => "2cafa46838e8b564468ebd868dcafdd99dce6221",
            .testnet => "3c3f4b84773ef0141576e48c3ff60e5078235891",
        };
    }

    /// N3 address that receives GAS deposits credited to NeoFS balances.
    pub fn neofsAddress(self: Network) []const u8 {
        return switch (self) {
            .mainnet => "NNxVrKjLsRkWsmGgmuNXLcMswtxTGaNQLk",
            .testnet => "NZAUkYbJ1Cb2HrNmwZ1pg9xYHBhm2FgtKV",
        };
    }
};

pub fn networkFromChain(chain_id: []const u8) ?Network {
    if (std.mem.indexOf(u8, chain_id, "testnet") != null) return .testnet;
    if (std.mem.indexOf(u8, chain_id, "mainnet") != null) return .mainnet;
    return null;
}

pub fn networkFromRpcEndpoint(endpoint: ?[]const u8) ?Network {
    const ep = endpoint orelse return null;
    if (std.mem.indexOf(u8, ep, ".t5.") != null or std.mem.indexOf(u8, ep, "testnet") != null) {
        return .testnet;
    }
    if (std.mem.indexOf(u8, ep, ".storage.fs.") != null or std.mem.indexOf(u8, ep, "mainnet") != null) {
        return .mainnet;
    }
    return null;
}
