const std = @import("std");

pub fn post(
    allocator: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    content_type: []const u8,
    body: []const u8,
) ![]u8 {
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    var response: std.Io.Writer.Allocating = .init(allocator);
    defer response.deinit();

    const headers = [_]std.http.Header{
        .{ .name = "Content-Type", .value = content_type },
    };

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = body,
        .keep_alive = false,
        .extra_headers = &headers,
        .response_writer = &response.writer,
    });
    if (result.status.class() != .success) return error.HttpError;
    return try allocator.dupe(u8, response.written());
}

pub const BodyReader = union(enum) {
    reader: *std.Io.Reader,
};

pub fn readBodyAfterHeaders(allocator: std.mem.Allocator, src: BodyReader, headers_with_terminator: []const u8) ![]u8 {
    if (isChunked(headers_with_terminator)) {
        return readChunkedBody(allocator, src);
    }
    if (parseContentLength(headers_with_terminator)) |content_length| {
        const body = try allocator.alloc(u8, content_length);
        errdefer allocator.free(body);
        try readExact(src, body);
        return body;
    }
    var body = std.ArrayList(u8).empty;
    errdefer body.deinit(allocator);
    while (true) {
        var buf: [1024]u8 = undefined;
        const got = readSome(src, &buf) catch break;
        if (got == 0) break;
        try body.appendSlice(allocator, buf[0..got]);
    }
    return body.toOwnedSlice(allocator);
}

fn readChunkedBody(allocator: std.mem.Allocator, src: BodyReader) ![]u8 {
    var body = std.ArrayList(u8).empty;
    errdefer body.deinit(allocator);
    while (true) {
        const size_line = try readLine(allocator, src);
        defer allocator.free(size_line);
        const trimmed = std.mem.trim(u8, size_line, " \t\r\n");
        const size_hex = if (std.mem.indexOfScalar(u8, trimmed, ';')) |semi| trimmed[0..semi] else trimmed;
        const chunk_size = try std.fmt.parseInt(usize, size_hex, 16);
        if (chunk_size == 0) break;
        const prev = body.items.len;
        try body.resize(allocator, prev + chunk_size);
        try readExact(src, body.items[prev..][0..chunk_size]);
        var crlf: [2]u8 = undefined;
        try readExact(src, &crlf);
        if (crlf[0] != '\r' or crlf[1] != '\n') return error.InvalidChunkedBody;
    }
    return body.toOwnedSlice(allocator);
}

fn readLine(allocator: std.mem.Allocator, src: BodyReader) ![]u8 {
    var line = std.ArrayList(u8).empty;
    errdefer line.deinit(allocator);
    while (true) {
        var b: [1]u8 = undefined;
        try readExact(src, &b);
        try line.append(allocator, b[0]);
        if (line.items.len >= 2 and line.items[line.items.len - 2] == '\r' and line.items[line.items.len - 1] == '\n') {
            return line.toOwnedSlice(allocator);
        }
        if (line.items.len > 4096) return error.HeaderTooLarge;
    }
}

fn readExact(src: BodyReader, buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const got = try readSome(src, buf[off..]);
        if (got == 0) return error.EndOfStream;
        off += got;
    }
}

fn readSome(src: BodyReader, buf: []u8) !usize {
    return switch (src) {
        .reader => |reader| reader.readSliceShort(buf),
    };
}

fn isChunked(headers: []const u8) bool {
    var it = std.mem.splitSequence(u8, headers, "\r\n");
    while (it.next()) |line| {
        if (line.len >= 18 and std.ascii.eqlIgnoreCase(line[0..18], "transfer-encoding:")) {
            return std.ascii.indexOfIgnoreCase(line, "chunked") != null;
        }
    }
    return false;
}

fn parseContentLength(headers: []const u8) ?usize {
    var it = std.mem.splitSequence(u8, headers, "\r\n");
    while (it.next()) |line| {
        if (line.len >= 15 and std.ascii.eqlIgnoreCase(line[0..15], "content-length:")) {
            const value = std.mem.trim(u8, line[15..], " \t");
            return std.fmt.parseInt(usize, value, 10) catch null;
        }
    }
    return null;
}
