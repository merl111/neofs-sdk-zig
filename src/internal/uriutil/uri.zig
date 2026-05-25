const std = @import("std");

pub const Parsed = struct {
    host: []const u8,
    tls: bool,
};

pub fn parse(uri: []const u8) !Parsed {
    const grpc_scheme = "grpc://";
    const grpcs_scheme = "grpcs://";

    if (std.mem.startsWith(u8, uri, grpcs_scheme)) {
        const host = uri[grpcs_scheme.len..];
        try requirePort(host);
        return .{ .host = host, .tls = true };
    }
    if (std.mem.startsWith(u8, uri, grpc_scheme)) {
        const host = uri[grpc_scheme.len..];
        try requirePort(host);
        return .{ .host = host, .tls = false };
    }
    try requirePort(uri);
    return .{ .host = uri, .tls = false };
}

fn requirePort(host: []const u8) !void {
    if (std.mem.indexOfScalar(u8, host, ':') == null) return error.MissingPort;
}

test {
    _ = @import("uri_test.zig");
}
