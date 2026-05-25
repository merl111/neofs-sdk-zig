const std = @import("std");

/// Minimal HPACK decoder (RFC 7541) with dynamic-table tracking and Huffman
/// decoding. Enough to read HTTP/2 response headers and gRPC trailers
/// (grpc-status, grpc-message).
pub const Decoder = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .{},
    max_size: usize = 4096,
    used_size: usize = 0,

    pub const Entry = struct {
        name: []u8,
        value: []u8,
    };

    pub const Header = struct {
        name: []u8,
        value: []u8,
    };

    pub fn deinit(self: *Decoder) void {
        for (self.entries.items) |e| {
            self.allocator.free(e.name);
            self.allocator.free(e.value);
        }
        self.entries.deinit(self.allocator);
    }

    /// Decode an HPACK header block fragment. The returned headers own their
    /// memory and must be freed by `freeHeaders`.
    pub fn decode(self: *Decoder, input: []const u8) ![]Header {
        var headers: std.ArrayList(Header) = .{};
        errdefer {
            for (headers.items) |h| {
                self.allocator.free(h.name);
                self.allocator.free(h.value);
            }
            headers.deinit(self.allocator);
        }

        var p: usize = 0;
        while (p < input.len) {
            const b = input[p];
            if (b & 0x80 != 0) {
                const idx = try readInt(input, &p, 7);
                if (idx == 0) return error.InvalidHpack;
                const e = try self.lookupIndex(idx);
                try headers.append(self.allocator, .{
                    .name = try self.allocator.dupe(u8, e.name),
                    .value = try self.allocator.dupe(u8, e.value),
                });
            } else if (b & 0xC0 == 0x40) {
                const idx = try readInt(input, &p, 6);
                const name = if (idx == 0)
                    try readString(self.allocator, input, &p)
                else blk: {
                    const e = try self.lookupIndex(idx);
                    break :blk try self.allocator.dupe(u8, e.name);
                };
                errdefer self.allocator.free(name);
                const value = try readString(self.allocator, input, &p);
                errdefer self.allocator.free(value);

                const name_copy = try self.allocator.dupe(u8, name);
                errdefer self.allocator.free(name_copy);
                const value_copy = try self.allocator.dupe(u8, value);
                errdefer self.allocator.free(value_copy);

                try self.addEntry(name, value);
                try headers.append(self.allocator, .{ .name = name_copy, .value = value_copy });
            } else if (b & 0xE0 == 0x20) {
                const new_size = try readInt(input, &p, 5);
                self.setMaxSize(new_size);
            } else {
                const idx = try readInt(input, &p, 4);
                const name = if (idx == 0)
                    try readString(self.allocator, input, &p)
                else blk: {
                    const e = try self.lookupIndex(idx);
                    break :blk try self.allocator.dupe(u8, e.name);
                };
                errdefer self.allocator.free(name);
                const value = try readString(self.allocator, input, &p);
                try headers.append(self.allocator, .{ .name = name, .value = value });
            }
        }
        return headers.toOwnedSlice(self.allocator);
    }

    pub fn freeHeaders(self: *Decoder, headers: []Header) void {
        for (headers) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
        self.allocator.free(headers);
    }

    fn lookupIndex(self: *Decoder, idx: usize) !Entry {
        if (idx <= static_table.len) {
            const s = static_table[idx - 1];
            return .{
                .name = @constCast(s.name),
                .value = @constCast(s.value),
            };
        }
        const dyn_idx = idx - static_table.len - 1;
        if (dyn_idx >= self.entries.items.len) return error.InvalidHpackIndex;
        return self.entries.items[dyn_idx];
    }

    fn addEntry(self: *Decoder, name: []u8, value: []u8) !void {
        const entry_size = name.len + value.len + 32;
        try self.entries.insert(self.allocator, 0, .{ .name = name, .value = value });
        self.used_size += entry_size;
        try self.evictToFit();
    }

    fn evictToFit(self: *Decoder) !void {
        while (self.used_size > self.max_size and self.entries.items.len > 0) {
            const last = self.entries.pop().?;
            self.used_size -= last.name.len + last.value.len + 32;
            self.allocator.free(last.name);
            self.allocator.free(last.value);
        }
    }

    pub fn setMaxSize(self: *Decoder, size: usize) void {
        self.max_size = size;
        self.evictToFit() catch {};
    }
};

fn readInt(input: []const u8, p: *usize, prefix_bits: u3) !usize {
    if (p.* >= input.len) return error.HpackTruncated;
    const mask: u8 = (@as(u8, 1) << prefix_bits) - 1;
    var value: usize = input[p.*] & mask;
    p.* += 1;
    if (value < mask) return value;
    var m: u6 = 0;
    while (true) {
        if (p.* >= input.len) return error.HpackTruncated;
        const b = input[p.*];
        p.* += 1;
        value += (@as(usize, b & 0x7f)) << m;
        if (b & 0x80 == 0) return value;
        m += 7;
        if (m >= 64) return error.HpackIntegerOverflow;
    }
}

fn readString(allocator: std.mem.Allocator, input: []const u8, p: *usize) ![]u8 {
    if (p.* >= input.len) return error.HpackTruncated;
    const huffman = input[p.*] & 0x80 != 0;
    const len = try readInt(input, p, 7);
    if (p.* + len > input.len) return error.HpackTruncated;
    const raw = input[p.* .. p.* + len];
    p.* += len;
    if (huffman) return decodeHuffman(allocator, raw);
    return allocator.dupe(u8, raw);
}

fn decodeHuffman(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .{};
    errdefer out.deinit(allocator);
    var code: u64 = 0;
    var code_bits: u8 = 0;
    for (raw) |byte| {
        var bit_index: u8 = 0;
        while (bit_index < 8) : (bit_index += 1) {
            const shift: u3 = @intCast(7 - bit_index);
            const bit: u1 = @intCast((byte >> shift) & 1);
            code = (code << 1) | bit;
            code_bits += 1;
            if (lookupHuffman(code, code_bits)) |sym| {
                if (sym == 256) return error.HpackEosSymbol;
                try out.append(allocator, @intCast(sym));
                code = 0;
                code_bits = 0;
            }
        }
    }
    return out.toOwnedSlice(allocator);
}

fn lookupHuffman(code: u64, bits: u8) ?u16 {
    for (huffman_table, 0..) |entry, i| {
        if (entry.bits == bits and entry.code == code) return @intCast(i);
    }
    return null;
}

const StaticEntry = struct { name: []const u8, value: []const u8 };

const static_table = [_]StaticEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

const HuffEntry = struct { code: u64, bits: u8 };

/// HPACK Static Huffman code table (RFC 7541 Appendix B). Indexed by symbol
/// (0..255 for octets; 256 is EOS). Each row is { code, bit-length }.
const huffman_table = [_]HuffEntry{
    .{ .code = 0x1ff8, .bits = 13 }, .{ .code = 0x7fffd8, .bits = 23 }, .{ .code = 0xfffffe2, .bits = 28 }, .{ .code = 0xfffffe3, .bits = 28 },
    .{ .code = 0xfffffe4, .bits = 28 }, .{ .code = 0xfffffe5, .bits = 28 }, .{ .code = 0xfffffe6, .bits = 28 }, .{ .code = 0xfffffe7, .bits = 28 },
    .{ .code = 0xfffffe8, .bits = 28 }, .{ .code = 0xffffea, .bits = 24 }, .{ .code = 0x3ffffffc, .bits = 30 }, .{ .code = 0xfffffe9, .bits = 28 },
    .{ .code = 0xfffffea, .bits = 28 }, .{ .code = 0x3ffffffd, .bits = 30 }, .{ .code = 0xfffffeb, .bits = 28 }, .{ .code = 0xfffffec, .bits = 28 },
    .{ .code = 0xfffffed, .bits = 28 }, .{ .code = 0xfffffee, .bits = 28 }, .{ .code = 0xfffffef, .bits = 28 }, .{ .code = 0xffffff0, .bits = 28 },
    .{ .code = 0xffffff1, .bits = 28 }, .{ .code = 0xffffff2, .bits = 28 }, .{ .code = 0x3ffffffe, .bits = 30 }, .{ .code = 0xffffff3, .bits = 28 },
    .{ .code = 0xffffff4, .bits = 28 }, .{ .code = 0xffffff5, .bits = 28 }, .{ .code = 0xffffff6, .bits = 28 }, .{ .code = 0xffffff7, .bits = 28 },
    .{ .code = 0xffffff8, .bits = 28 }, .{ .code = 0xffffff9, .bits = 28 }, .{ .code = 0xffffffa, .bits = 28 }, .{ .code = 0xffffffb, .bits = 28 },
    .{ .code = 0x14, .bits = 6 }, .{ .code = 0x3f8, .bits = 10 }, .{ .code = 0x3f9, .bits = 10 }, .{ .code = 0xffa, .bits = 12 },
    .{ .code = 0x1ff9, .bits = 13 }, .{ .code = 0x15, .bits = 6 }, .{ .code = 0xf8, .bits = 8 }, .{ .code = 0x7fa, .bits = 11 },
    .{ .code = 0x3fa, .bits = 10 }, .{ .code = 0x3fb, .bits = 10 }, .{ .code = 0xf9, .bits = 8 }, .{ .code = 0x7fb, .bits = 11 },
    .{ .code = 0xfa, .bits = 8 }, .{ .code = 0x16, .bits = 6 }, .{ .code = 0x17, .bits = 6 }, .{ .code = 0x18, .bits = 6 },
    .{ .code = 0x0, .bits = 5 }, .{ .code = 0x1, .bits = 5 }, .{ .code = 0x2, .bits = 5 }, .{ .code = 0x19, .bits = 6 },
    .{ .code = 0x1a, .bits = 6 }, .{ .code = 0x1b, .bits = 6 }, .{ .code = 0x1c, .bits = 6 }, .{ .code = 0x1d, .bits = 6 },
    .{ .code = 0x1e, .bits = 6 }, .{ .code = 0x1f, .bits = 6 }, .{ .code = 0x5c, .bits = 7 }, .{ .code = 0xfb, .bits = 8 },
    .{ .code = 0x7ffc, .bits = 15 }, .{ .code = 0x20, .bits = 6 }, .{ .code = 0xffb, .bits = 12 }, .{ .code = 0x3fc, .bits = 10 },
    .{ .code = 0x1ffa, .bits = 13 }, .{ .code = 0x21, .bits = 6 }, .{ .code = 0x5d, .bits = 7 }, .{ .code = 0x5e, .bits = 7 },
    .{ .code = 0x5f, .bits = 7 }, .{ .code = 0x60, .bits = 7 }, .{ .code = 0x61, .bits = 7 }, .{ .code = 0x62, .bits = 7 },
    .{ .code = 0x63, .bits = 7 }, .{ .code = 0x64, .bits = 7 }, .{ .code = 0x65, .bits = 7 }, .{ .code = 0x66, .bits = 7 },
    .{ .code = 0x67, .bits = 7 }, .{ .code = 0x68, .bits = 7 }, .{ .code = 0x69, .bits = 7 }, .{ .code = 0x6a, .bits = 7 },
    .{ .code = 0x6b, .bits = 7 }, .{ .code = 0x6c, .bits = 7 }, .{ .code = 0x6d, .bits = 7 }, .{ .code = 0x6e, .bits = 7 },
    .{ .code = 0x6f, .bits = 7 }, .{ .code = 0x70, .bits = 7 }, .{ .code = 0x71, .bits = 7 }, .{ .code = 0x72, .bits = 7 },
    .{ .code = 0xfc, .bits = 8 }, .{ .code = 0x73, .bits = 7 }, .{ .code = 0xfd, .bits = 8 }, .{ .code = 0x1ffb, .bits = 13 },
    .{ .code = 0x7fff0, .bits = 19 }, .{ .code = 0x1ffc, .bits = 13 }, .{ .code = 0x3ffc, .bits = 14 }, .{ .code = 0x22, .bits = 6 },
    .{ .code = 0x7ffd, .bits = 15 }, .{ .code = 0x3, .bits = 5 }, .{ .code = 0x23, .bits = 6 }, .{ .code = 0x4, .bits = 5 },
    .{ .code = 0x24, .bits = 6 }, .{ .code = 0x5, .bits = 5 }, .{ .code = 0x25, .bits = 6 }, .{ .code = 0x26, .bits = 6 },
    .{ .code = 0x27, .bits = 6 }, .{ .code = 0x6, .bits = 5 }, .{ .code = 0x74, .bits = 7 }, .{ .code = 0x75, .bits = 7 },
    .{ .code = 0x28, .bits = 6 }, .{ .code = 0x29, .bits = 6 }, .{ .code = 0x2a, .bits = 6 }, .{ .code = 0x7, .bits = 5 },
    .{ .code = 0x2b, .bits = 6 }, .{ .code = 0x76, .bits = 7 }, .{ .code = 0x2c, .bits = 6 }, .{ .code = 0x8, .bits = 5 },
    .{ .code = 0x9, .bits = 5 }, .{ .code = 0x2d, .bits = 6 }, .{ .code = 0x77, .bits = 7 }, .{ .code = 0x78, .bits = 7 },
    .{ .code = 0x79, .bits = 7 }, .{ .code = 0x7a, .bits = 7 }, .{ .code = 0x7b, .bits = 7 }, .{ .code = 0x7ffe, .bits = 15 },
    .{ .code = 0x7fc, .bits = 11 }, .{ .code = 0x3ffd, .bits = 14 }, .{ .code = 0x1ffd, .bits = 13 }, .{ .code = 0xffffffc, .bits = 28 },
    .{ .code = 0xfffe6, .bits = 20 }, .{ .code = 0x3fffd2, .bits = 22 }, .{ .code = 0xfffe7, .bits = 20 }, .{ .code = 0xfffe8, .bits = 20 },
    .{ .code = 0x3fffd3, .bits = 22 }, .{ .code = 0x3fffd4, .bits = 22 }, .{ .code = 0x3fffd5, .bits = 22 }, .{ .code = 0x7fffd9, .bits = 23 },
    .{ .code = 0x3fffd6, .bits = 22 }, .{ .code = 0x7fffda, .bits = 23 }, .{ .code = 0x7fffdb, .bits = 23 }, .{ .code = 0x7fffdc, .bits = 23 },
    .{ .code = 0x7fffdd, .bits = 23 }, .{ .code = 0x7fffde, .bits = 23 }, .{ .code = 0xffffeb, .bits = 24 }, .{ .code = 0x7fffdf, .bits = 23 },
    .{ .code = 0xffffec, .bits = 24 }, .{ .code = 0xffffed, .bits = 24 }, .{ .code = 0x3fffd7, .bits = 22 }, .{ .code = 0x7fffe0, .bits = 23 },
    .{ .code = 0xffffee, .bits = 24 }, .{ .code = 0x7fffe1, .bits = 23 }, .{ .code = 0x7fffe2, .bits = 23 }, .{ .code = 0x7fffe3, .bits = 23 },
    .{ .code = 0x7fffe4, .bits = 23 }, .{ .code = 0x1fffdc, .bits = 21 }, .{ .code = 0x3fffd8, .bits = 22 }, .{ .code = 0x7fffe5, .bits = 23 },
    .{ .code = 0x3fffd9, .bits = 22 }, .{ .code = 0x7fffe6, .bits = 23 }, .{ .code = 0x7fffe7, .bits = 23 }, .{ .code = 0xffffef, .bits = 24 },
    .{ .code = 0x3fffda, .bits = 22 }, .{ .code = 0x1fffdd, .bits = 21 }, .{ .code = 0xfffe9, .bits = 20 }, .{ .code = 0x3fffdb, .bits = 22 },
    .{ .code = 0x3fffdc, .bits = 22 }, .{ .code = 0x7fffe8, .bits = 23 }, .{ .code = 0x7fffe9, .bits = 23 }, .{ .code = 0x1fffde, .bits = 21 },
    .{ .code = 0x7fffea, .bits = 23 }, .{ .code = 0x3fffdd, .bits = 22 }, .{ .code = 0x3fffde, .bits = 22 }, .{ .code = 0xfffff0, .bits = 24 },
    .{ .code = 0x1fffdf, .bits = 21 }, .{ .code = 0x3fffdf, .bits = 22 }, .{ .code = 0x7fffeb, .bits = 23 }, .{ .code = 0x7fffec, .bits = 23 },
    .{ .code = 0x1fffe0, .bits = 21 }, .{ .code = 0x1fffe1, .bits = 21 }, .{ .code = 0x3fffe0, .bits = 22 }, .{ .code = 0x1fffe2, .bits = 21 },
    .{ .code = 0x7fffed, .bits = 23 }, .{ .code = 0x3fffe1, .bits = 22 }, .{ .code = 0x7fffee, .bits = 23 }, .{ .code = 0x7fffef, .bits = 23 },
    .{ .code = 0xfffea, .bits = 20 }, .{ .code = 0x3fffe2, .bits = 22 }, .{ .code = 0x3fffe3, .bits = 22 }, .{ .code = 0x3fffe4, .bits = 22 },
    .{ .code = 0x7ffff0, .bits = 23 }, .{ .code = 0x3fffe5, .bits = 22 }, .{ .code = 0x3fffe6, .bits = 22 }, .{ .code = 0x7ffff1, .bits = 23 },
    .{ .code = 0x3ffffe0, .bits = 26 }, .{ .code = 0x3ffffe1, .bits = 26 }, .{ .code = 0xfffeb, .bits = 20 }, .{ .code = 0x7fff1, .bits = 19 },
    .{ .code = 0x3fffe7, .bits = 22 }, .{ .code = 0x7ffff2, .bits = 23 }, .{ .code = 0x3fffe8, .bits = 22 }, .{ .code = 0x1ffffec, .bits = 25 },
    .{ .code = 0x3ffffe2, .bits = 26 }, .{ .code = 0x3ffffe3, .bits = 26 }, .{ .code = 0x3ffffe4, .bits = 26 }, .{ .code = 0x7ffffde, .bits = 27 },
    .{ .code = 0x7ffffdf, .bits = 27 }, .{ .code = 0x3ffffe5, .bits = 26 }, .{ .code = 0xfffff1, .bits = 24 }, .{ .code = 0x1ffffed, .bits = 25 },
    .{ .code = 0x7fff2, .bits = 19 }, .{ .code = 0x1fffe3, .bits = 21 }, .{ .code = 0x3ffffe6, .bits = 26 }, .{ .code = 0x7ffffe0, .bits = 27 },
    .{ .code = 0x7ffffe1, .bits = 27 }, .{ .code = 0x3ffffe7, .bits = 26 }, .{ .code = 0x7ffffe2, .bits = 27 }, .{ .code = 0xfffff2, .bits = 24 },
    .{ .code = 0x1fffe4, .bits = 21 }, .{ .code = 0x1fffe5, .bits = 21 }, .{ .code = 0x3ffffe8, .bits = 26 }, .{ .code = 0x3ffffe9, .bits = 26 },
    .{ .code = 0xffffffd, .bits = 28 }, .{ .code = 0x7ffffe3, .bits = 27 }, .{ .code = 0x7ffffe4, .bits = 27 }, .{ .code = 0x7ffffe5, .bits = 27 },
    .{ .code = 0xfffec, .bits = 20 }, .{ .code = 0xfffff3, .bits = 24 }, .{ .code = 0xfffed, .bits = 20 }, .{ .code = 0x1fffe6, .bits = 21 },
    .{ .code = 0x3fffe9, .bits = 22 }, .{ .code = 0x1fffe7, .bits = 21 }, .{ .code = 0x1fffe8, .bits = 21 }, .{ .code = 0x7ffff3, .bits = 23 },
    .{ .code = 0x3fffea, .bits = 22 }, .{ .code = 0x3fffeb, .bits = 22 }, .{ .code = 0x1ffffee, .bits = 25 }, .{ .code = 0x1ffffef, .bits = 25 },
    .{ .code = 0xfffff4, .bits = 24 }, .{ .code = 0xfffff5, .bits = 24 }, .{ .code = 0x3ffffea, .bits = 26 }, .{ .code = 0x7ffff4, .bits = 23 },
    .{ .code = 0x3ffffeb, .bits = 26 }, .{ .code = 0x7ffffe6, .bits = 27 }, .{ .code = 0x3ffffec, .bits = 26 }, .{ .code = 0x3ffffed, .bits = 26 },
    .{ .code = 0x7ffffe7, .bits = 27 }, .{ .code = 0x7ffffe8, .bits = 27 }, .{ .code = 0x7ffffe9, .bits = 27 }, .{ .code = 0x7ffffea, .bits = 27 },
    .{ .code = 0x7ffffeb, .bits = 27 }, .{ .code = 0xffffffe, .bits = 28 }, .{ .code = 0x7ffffec, .bits = 27 }, .{ .code = 0x7ffffed, .bits = 27 },
    .{ .code = 0x7ffffee, .bits = 27 }, .{ .code = 0x7ffffef, .bits = 27 }, .{ .code = 0x7fffff0, .bits = 27 }, .{ .code = 0x3ffffee, .bits = 26 },
    .{ .code = 0x3fffffff, .bits = 30 }, // EOS (256)
};
