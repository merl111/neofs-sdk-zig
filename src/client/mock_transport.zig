const std = @import("std");

pub const RecordedCall = struct {
    path: []u8,
    request: []u8,
};

/// In-memory gRPC transport for unit tests. Records protobuf request bytes
/// passed to `unaryCall` and returns canned responses registered per path.
pub const Client = struct {
    allocator: std.mem.Allocator,
    calls: std.ArrayList(RecordedCall),
    responses: std.StringHashMap([]u8),

    pub fn init(allocator: std.mem.Allocator) Client {
        return .{
            .allocator = allocator,
            .calls = .{},
            .responses = std.StringHashMap([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        self.clearCalls();
        self.calls.deinit(self.allocator);
        var it = self.responses.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.responses.deinit();
    }

    pub fn clearCalls(self: *Client) void {
        for (self.calls.items) |call| {
            self.allocator.free(call.path);
            self.allocator.free(call.request);
        }
        self.calls.clearRetainingCapacity();
    }

    pub fn setResponse(self: *Client, path: []const u8, response: []const u8) !void {
        const key = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(key);
        const val = try self.allocator.dupe(u8, response);
        if (self.responses.fetchRemove(path)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }
        try self.responses.put(key, val);
    }

    pub fn encodeResponse(allocator: std.mem.Allocator, msg: anytype) ![]u8 {
        var w: std.Io.Writer.Allocating = .init(allocator);
        defer w.deinit();
        try msg.encode(&w.writer, allocator);
        return try allocator.dupe(u8, w.written());
    }

    pub fn unaryCall(self: *Client, path: []const u8, request: []const u8) ![]u8 {
        try self.calls.append(self.allocator, .{
            .path = try self.allocator.dupe(u8, path),
            .request = try self.allocator.dupe(u8, request),
        });
        const response = self.responses.get(path) orelse return error.NoMockResponse;
        return try self.allocator.dupe(u8, response);
    }

    pub fn callCount(self: *const Client) usize {
        return self.calls.items.len;
    }

    pub fn lastCall(self: *const Client) ?RecordedCall {
        if (self.calls.items.len == 0) return null;
        return self.calls.items[self.calls.items.len - 1];
    }
};
