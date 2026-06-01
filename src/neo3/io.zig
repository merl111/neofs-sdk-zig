const std = @import("std");

pub const Writer = struct {
    buf: std.ArrayList(u8),

    pub fn init(_: std.mem.Allocator) Writer {
        return .{ .buf = .empty };
    }

    pub fn deinit(self: *Writer, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
    }

    pub fn bytes(self: *const Writer) []const u8 {
        return self.buf.items;
    }

    pub fn writeByte(self: *Writer, allocator: std.mem.Allocator, b: u8) !void {
        try self.buf.append(allocator, b);
    }

    pub fn writeBytes(self: *Writer, allocator: std.mem.Allocator, data: []const u8) !void {
        try self.buf.appendSlice(allocator, data);
    }

    pub fn writeU32LE(self: *Writer, allocator: std.mem.Allocator, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try self.writeBytes(allocator, &b);
    }

    pub fn writeU64LE(self: *Writer, allocator: std.mem.Allocator, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try self.writeBytes(allocator, &b);
    }

    pub fn writeVarUint(self: *Writer, allocator: std.mem.Allocator, val: u64) !void {
        var scratch: [9]u8 = undefined;
        const n = putVarUint(&scratch, val);
        try self.writeBytes(allocator, scratch[0..n]);
    }

    pub fn writeVarBytes(self: *Writer, allocator: std.mem.Allocator, data: []const u8) !void {
        try self.writeVarUint(allocator, data.len);
        try self.writeBytes(allocator, data);
    }
};

fn putVarUint(data: []u8, val: u64) usize {
    if (val < 0xfd) {
        data[0] = @intCast(val);
        return 1;
    }
    if (val < 0xffff) {
        data[0] = 0xfd;
        std.mem.writeInt(u16, data[1..3], @intCast(val), .little);
        return 3;
    }
    if (val < 0xffff_ffff) {
        data[0] = 0xfe;
        std.mem.writeInt(u32, data[1..5], @intCast(val), .little);
        return 5;
    }
    data[0] = 0xff;
    std.mem.writeInt(u64, data[1..9], val, .little);
    return 9;
}
