const std = @import("std");
const csprng = @import("../crypto/csprng.zig");
const net = std.Io.net;
const HostName = net.HostName;

const public_nameservers = [_]net.Ip4Address{
    .{ .bytes = .{ 8, 8, 8, 8 }, .port = 53 },
    .{ .bytes = .{ 1, 1, 1, 1 }, .port = 53 },
};

/// Well-known NeoFS public node hostnames. Used when the system resolver fails
/// (common on broken/misconfigured DNS) and UDP to public resolvers is blocked.
const known_neofs_hosts = [_]struct { []const u8, [4]u8 }{
    .{ "st1.storage.fs.neo.org", .{ 157, 90, 176, 145 } },
    .{ "st2.storage.fs.neo.org", .{ 149, 56, 16, 141 } },
    .{ "st3.storage.fs.neo.org", .{ 135, 181, 79, 214 } },
    .{ "st4.storage.fs.neo.org", .{ 51, 178, 66, 162 } },
    .{ "st1.t5.fs.neo.org", .{ 65, 21, 148, 207 } },
    .{ "st2.t5.fs.neo.org", .{ 159, 69, 183, 7 } },
    .{ "st3.t5.fs.neo.org", .{ 159, 223, 36, 204 } },
    .{ "st4.t5.fs.neo.org", .{ 137, 184, 119, 245 } },
};

pub const ConnectError = HostName.ConnectError || HostName.ValidateError;

/// TCP connect to `host`:`port`, falling back to alternate DNS when the system
/// resolver fails.
pub fn connectTcp(io: std.Io, host: []const u8, port: u16) ConnectError!net.Stream {
    const host_name = try HostName.init(host);
    return HostName.connect(host_name, io, port, .{ .mode = .stream }) catch |err| switch (err) {
        error.NameServerFailure, error.UnknownHostName => blk: {
            const ip4 = resolveA(io, host) catch return err;
            var ip_buf: [15]u8 = undefined;
            const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
                ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3],
            }) catch return error.UnknownHostName;
            const ip_host = try HostName.init(ip_str);
            break :blk try HostName.connect(ip_host, io, port, .{ .mode = .stream });
        },
        else => |e| return e,
    };
}

fn resolveA(io: std.Io, host: []const u8) HostName.LookupError!net.Ip4Address {
    if (lookupKnownHost(host)) |ip| return ip;
    if (resolveViaUdp(io, host)) |ip| return ip;
    if (lookupKnownHost(host)) |ip| return ip;
    return error.UnknownHostName;
}

fn lookupKnownHost(host: []const u8) ?net.Ip4Address {
    var trimmed = host;
    if (std.mem.endsWith(u8, trimmed, ".")) trimmed = trimmed[0 .. trimmed.len - 1];
    for (known_neofs_hosts) |entry| {
        if (std.ascii.eqlIgnoreCase(trimmed, entry[0])) {
            return .{ .bytes = entry[1], .port = 0 };
        }
    }
    return null;
}

fn resolveViaUdp(io: std.Io, host: []const u8) ?net.Ip4Address {
    var query_buf: [280]u8 = undefined;
    var query_id: [2]u8 = undefined;
    csprng.randomBytes(&query_id);
    const query_len = writeAQuery(&query_buf, host, query_id);
    const query = query_buf[0..query_len];

    const local: net.IpAddress = .{ .ip4 = net.Ip4Address.unspecified(0) };
    const socket = local.bind(io, .{ .mode = .dgram }) catch return null;
    defer socket.close(io);

    var recv_buf: [512]u8 = undefined;
    const timeout: std.Io.Timeout = .{ .duration = .{
        .raw = .fromMilliseconds(2_000),
        .clock = .real,
    } };

    for (public_nameservers) |ns| {
        const dest: net.IpAddress = .{ .ip4 = ns };
        socket.send(io, &dest, query) catch continue;
        const msg = socket.receiveTimeout(io, &recv_buf, timeout) catch continue;
        if (parseAResponse(msg.data, query_id)) |ip| return ip;
    }
    return null;
}

fn writeAQuery(q: *[280]u8, dname: []const u8, query_id: [2]u8) usize {
    var name = dname;
    if (std.mem.endsWith(u8, name, ".")) name.len -= 1;
    const n = 17 + name.len + @intFromBool(name.len != 0);

    q[0..2].* = query_id;
    @memset(q[2..n], 0);
    q[2] = 1; // standard query
    q[5] = 1; // QDCOUNT
    @memcpy(q[13..][0..name.len], name);
    var i: usize = 13;
    var j: usize = undefined;
    while (q[i] != 0) : (i = j + 1) {
        j = i;
        while (q[j] != 0 and q[j] != '.') : (j += 1) {}
        q[i - 1] = @intCast(j - i);
    }
    q[i + 1] = @intFromEnum(HostName.DnsRecord.A);
    q[i + 3] = 1; // IN class
    return n;
}

fn parseAResponse(packet: []const u8, query_id: [2]u8) ?net.Ip4Address {
    if (packet.len < 12) return null;
    if (packet[0] != query_id[0] or packet[1] != query_id[1]) return null;
    if ((packet[3] & 15) != 0) return null;
    var dr = HostName.DnsResponse.init(packet) catch return null;
    while (dr.next() catch null) |record| {
        if (record.rr != .A) continue;
        const data = record.packet[record.data_off..][0..record.data_len];
        if (data.len != 4) continue;
        return .{ .bytes = data[0..4].*, .port = 0 };
    }
    return null;
}

test "known NeoFS host lookup" {
    const ip = lookupKnownHost("st1.storage.fs.neo.org").?;
    try std.testing.expectEqual(@as(u8, 157), ip.bytes[0]);
    try std.testing.expectEqual(@as(u8, 145), ip.bytes[3]);
}

test "writeAQuery encodes st1 host" {
    var q: [280]u8 = undefined;
    const len = writeAQuery(&q, "st1.storage.fs.neo.org", .{ 0xab, 0xcd });
    try std.testing.expect(len > 12);
    try std.testing.expectEqual(@as(u8, 0xab), q[0]);
}
