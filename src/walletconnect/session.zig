const std = @import("std");

pub const Session = struct {
    topic: []u8,
    chain_id: []u8,
    account: []u8,
    methods: std.ArrayListUnmanaged([]u8) = .empty,
    expiry: u64 = 0,
    sym_key_hex: ?[]u8 = null,

    pub fn deinit(self: *Session, allocator: std.mem.Allocator) void {
        allocator.free(self.topic);
        allocator.free(self.chain_id);
        allocator.free(self.account);
        if (self.sym_key_hex) |v| allocator.free(v);
        for (self.methods.items) |m| allocator.free(m);
        self.methods.deinit(allocator);
        self.* = undefined;
    }

    pub fn toJson(self: Session, allocator: std.mem.Allocator) ![]u8 {
        var methods = std.ArrayList([]const u8){};
        defer methods.deinit(allocator);
        for (self.methods.items) |m| try methods.append(allocator, m);
        var w: std.Io.Writer.Allocating = .init(allocator);
        try w.writer.print("{f}", .{std.json.fmt(.{
            .topic = self.topic,
            .chain_id = self.chain_id,
            .account = self.account,
            .methods = methods.items,
            .expiry = self.expiry,
            .sym_key_hex = self.sym_key_hex orelse "",
        }, .{})});
        return try w.toOwnedSlice();
    }
};

pub fn saveSession(path: []const u8, session: Session, allocator: std.mem.Allocator) !void {
    const json = try session.toJson(allocator);
    defer allocator.free(json);
    const file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(json);
}

pub fn loadSession(path: []const u8, allocator: std.mem.Allocator) !?Session {
    const data = std.fs.cwd().readFileAlloc(allocator, path, 1 << 20) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(data);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, data, .{}) catch return error.InvalidSessionFile;
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return error.InvalidSessionFile;
    const topic = root.object.get("topic") orelse return error.InvalidSessionFile;
    const chain_id = root.object.get("chain_id") orelse return error.InvalidSessionFile;
    const account = root.object.get("account") orelse return error.InvalidSessionFile;
    const methods = root.object.get("methods") orelse return error.InvalidSessionFile;
    const expiry = root.object.get("expiry") orelse return error.InvalidSessionFile;
    if (topic != .string or chain_id != .string or account != .string or methods != .array or expiry != .integer) {
        return error.InvalidSessionFile;
    }
    const sym_key_v = root.object.get("sym_key_hex");
    const sym_key_hex: ?[]u8 = if (sym_key_v) |sk| blk: {
        if (sk != .string or sk.string.len == 0) break :blk null;
        break :blk try allocator.dupe(u8, sk.string);
    } else null;

    var session = Session{
        .topic = try allocator.dupe(u8, topic.string),
        .chain_id = try allocator.dupe(u8, chain_id.string),
        .account = try allocator.dupe(u8, account.string),
        .methods = .empty,
        .expiry = @intCast(expiry.integer),
        .sym_key_hex = sym_key_hex,
    };
    errdefer session.deinit(allocator);
    for (methods.array.items) |m| {
        if (m != .string) continue;
        try session.methods.append(allocator, try allocator.dupe(u8, m.string));
    }
    return session;
}

