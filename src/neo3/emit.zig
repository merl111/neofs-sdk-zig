const std = @import("std");
const io_mod = @import("io.zig");
const interop = @import("interop.zig");
const hash_mod = @import("hash.zig");

pub const Opcode = enum(u8) {
    PUSHINT8 = 0x00,
    PUSHNULL = 0x0B,
    PUSHDATA1 = 0x0C,
    PUSHDATA2 = 0x0D,
    PUSHDATA4 = 0x0E,
    PUSHM1 = 0x0F,
    PUSH0 = 0x10,
    ASSERT = 0x39,
    SYSCALL = 0x41,
    PACK = 0xC0,
};

pub const call_flag_all: i64 = 15;

pub const Builder = struct {
    w: io_mod.Writer,

    pub fn init(allocator: std.mem.Allocator) Builder {
        return .{ .w = io_mod.Writer.init(allocator) };
    }

    pub fn deinit(self: *Builder, allocator: std.mem.Allocator) void {
        self.w.deinit(allocator);
    }

    pub fn script(self: *Builder) []const u8 {
        return self.w.bytes();
    }

    pub fn pushNull(self: *Builder, allocator: std.mem.Allocator) !void {
        try self.w.writeByte(allocator, @intFromEnum(Opcode.PUSHNULL));
    }

    pub fn pushBool(self: *Builder, allocator: std.mem.Allocator, ok: bool) !void {
        try self.w.writeByte(allocator, if (ok) 0x08 else 0x09);
    }

    pub fn pushInt(self: *Builder, allocator: std.mem.Allocator, value: i64) !void {
        if (value == -1) {
            try self.w.writeByte(allocator, @intFromEnum(Opcode.PUSHM1));
            return;
        }
        if (value >= 0 and value < 16) {
            try self.w.writeByte(allocator, @intFromEnum(Opcode.PUSH0) + @as(u8, @intCast(value)));
            return;
        }
        if (value >= 0) {
            try pushI64Le(self, allocator, value);
            return;
        }
        try pushBigInt(self, allocator, value);
    }

    pub fn pushBytes(self: *Builder, allocator: std.mem.Allocator, data: []const u8) !void {
        const n = data.len;
        if (n < 0x100) {
            try self.w.writeByte(allocator, @intFromEnum(Opcode.PUSHDATA1));
            try self.w.writeByte(allocator, @intCast(n));
        } else if (n < 0x10000) {
            try self.w.writeByte(allocator, @intFromEnum(Opcode.PUSHDATA2));
            var len_buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &len_buf, @intCast(n), .little);
            try self.w.writeBytes(allocator, &len_buf);
        } else {
            try self.w.writeByte(allocator, @intFromEnum(Opcode.PUSHDATA4));
            var len_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &len_buf, @intCast(n), .little);
            try self.w.writeBytes(allocator, &len_buf);
        }
        try self.w.writeBytes(allocator, data);
    }

    pub fn pushString(self: *Builder, allocator: std.mem.Allocator, s: []const u8) !void {
        try self.pushBytes(allocator, s);
    }

    pub fn pushHash160(self: *Builder, allocator: std.mem.Allocator, h: hash_mod.Hash160) !void {
        try self.pushBytes(allocator, &h);
    }

    pub fn syscall(self: *Builder, allocator: std.mem.Allocator, api: []const u8) !void {
        try self.w.writeByte(allocator, @intFromEnum(Opcode.SYSCALL));
        var id_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &id_buf, interop.syscallId(api), .little);
        try self.w.writeBytes(allocator, &id_buf);
    }

    pub fn packArray(self: *Builder, allocator: std.mem.Allocator, count: usize) !void {
        try self.pushInt(allocator, @intCast(count));
        try self.w.writeByte(allocator, @intFromEnum(Opcode.PACK));
    }

    pub fn appCallNoArgs(
        self: *Builder,
        allocator: std.mem.Allocator,
        contract_be: hash_mod.Hash160,
        operation: []const u8,
        flag: i64,
    ) !void {
        try self.pushInt(allocator, flag);
        try self.pushString(allocator, operation);
        try self.pushHash160(allocator, contract_be);
        try self.syscall(allocator, "System.Contract.Call");
    }

    pub fn invokeWithAssert(
        self: *Builder,
        allocator: std.mem.Allocator,
        contract_be: hash_mod.Hash160,
        operation: []const u8,
        args: []const Arg,
    ) !void {
        var i: isize = @intCast(args.len);
        while (i > 0) {
            i -= 1;
            try pushArg(self, allocator, args[@intCast(i)]);
        }
        try self.packArray(allocator, args.len);
        try self.appCallNoArgs(allocator, contract_be, operation, call_flag_all);
        try self.w.writeByte(allocator, @intFromEnum(Opcode.ASSERT));
    }
};

pub const Arg = union(enum) {
    int: i64,
    hash160: hash_mod.Hash160,
    null,
};

fn pushArg(builder: *Builder, allocator: std.mem.Allocator, arg: Arg) !void {
    switch (arg) {
        .int => |v| try builder.pushInt(allocator, v),
        .hash160 => |h| try builder.pushHash160(allocator, h),
        .null => try builder.pushNull(allocator),
    }
}

fn pushI64Le(builder: *Builder, allocator: std.mem.Allocator, value: i64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(i64, &buf, value, .little);
    try builder.w.writeByte(allocator, @intFromEnum(Opcode.PUSHINT8) + 3);
    try builder.w.writeBytes(allocator, &buf);
}

fn pushBigInt(builder: *Builder, allocator: std.mem.Allocator, value: i64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(i64, &buf, value, .little);
    var start: usize = 0;
    while (start < buf.len and buf[start] == 0) start += 1;
    if (start == buf.len) {
        try builder.w.writeByte(allocator, @intFromEnum(Opcode.PUSH0));
        return;
    }
    var end = buf.len;
    while (end > start and buf[end - 1] == 0) end -= 1;
    const slice = buf[start..end];
    const len_m1: u8 = if (slice.len > 0) @intCast(slice.len - 1) else 0;
    const pad_size: u8 = 8 - @as(u8, @intCast(@clz(len_m1)));
    try builder.w.writeByte(allocator, @intFromEnum(Opcode.PUSHINT8) + pad_size);
    var padded: [32]u8 = undefined;
    @memcpy(padded[0..slice.len], slice);
    if (slice.len > 0 and slice[slice.len - 1] & 0x80 != 0) {
        @memset(padded[slice.len..], 0xFF);
    }
    const width: usize = @as(usize, 1) << @intCast(pad_size);
    try builder.w.writeBytes(allocator, padded[0..width]);
}
