const std = @import("std");
const builtin = @import("builtin");

threadlocal var csprng_state: ?std.Random.DefaultCsprng = null;

fn fillSecure(buf: []u8) void {
    var pos: usize = 0;
    while (pos < buf.len) {
        const n = readRandom(buf[pos..]);
        pos += n;
    }
}

fn readRandom(buf: []u8) usize {
    if (@TypeOf(std.c.getrandom) != void) {
        const rc = std.c.getrandom(buf.ptr, buf.len, 0);
        if (rc < 0) @panic("getrandom failed");
        return @intCast(rc);
    }
    if (builtin.os.tag == .linux) {
        return std.os.linux.getrandom(buf.ptr, buf.len, 0);
    }
    @panic("no secure random source available");
}

fn getCsprng() *std.Random.DefaultCsprng {
    if (csprng_state == null) {
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        fillSecure(&seed);
        csprng_state = std.Random.DefaultCsprng.init(seed);
    }
    return &csprng_state.?;
}

/// Fills `buf` with cryptographically secure random bytes.
pub fn randomBytes(buf: []u8) void {
    getCsprng().fill(buf);
}
