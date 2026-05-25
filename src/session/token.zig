const std = @import("std");

pub const Verb = enum {
    put,
    get,
    delete,
};

pub const Token = struct {
    id: [16]u8,
    verb: Verb,
    exp_epoch: u64,
    nbf_epoch: u64,
};

test {
    _ = @import("token_test.zig");
}

pub fn new(verb: Verb, nbf_epoch: u64, exp_epoch: u64) Token {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return .{
        .id = id,
        .verb = verb,
        .nbf_epoch = nbf_epoch,
        .exp_epoch = exp_epoch,
    };
}
