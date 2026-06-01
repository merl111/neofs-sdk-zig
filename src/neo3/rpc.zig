const std = @import("std");
const hash_mod = @import("hash.zig");
const http = @import("http.zig");
pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: []u8,
    id: u64 = 1,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, endpoint: []const u8) !Client {
        return .{
            .allocator = allocator,
            .io = io,
            .endpoint = try allocator.dupe(u8, endpoint),
        };
    }

    pub fn deinit(self: *Client) void {
        self.allocator.free(self.endpoint);
    }

    pub fn getBlockCount(self: *Client) !u32 {
        const raw = try self.call("getblockcount", "[]");
        defer self.allocator.free(raw);
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{});
        defer parsed.deinit();
        const result = objectField(parsed.value, "result") orelse return error.InvalidResponse;
        return @intCast(try expectInt(result));
    }

    pub fn getVersion(self: *Client) !Version {
        const raw = try self.call("getversion", "[]");
        defer self.allocator.free(raw);
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{});
        defer parsed.deinit();
        const result = objectField(parsed.value, "result") orelse return error.InvalidResponse;
        const protocol = objectField(result, "protocol") orelse return error.InvalidResponse;
        const network = objectField(protocol, "network") orelse return error.InvalidResponse;
        const validators = objectField(protocol, "validatorscount") orelse return error.InvalidResponse;
        return .{
            .network_magic = @intCast(try expectInt(network)),
            .validators_count = @intCast(try expectInt(validators)),
        };
    }

    pub fn invokeScript(
        self: *Client,
        script: []const u8,
        signer_account_le: []const u8,
    ) !InvokeResult {
        const b64 = try base64Encode(self.allocator, script);
        defer self.allocator.free(b64);
        const params = try std.fmt.allocPrint(self.allocator,
            "[\"{s}\",[{{\"account\":\"{s}\",\"scopes\":\"CalledByEntry\"}}]]",
            .{ b64, signer_account_le },
        );
        defer self.allocator.free(params);
        const raw = try self.call("invokescript", params);
        defer self.allocator.free(raw);
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{});
        defer parsed.deinit();
        const result = objectField(parsed.value, "result") orelse return error.InvalidResponse;
        const state = objectField(result, "state") orelse return error.InvalidResponse;
        if (state != .string or !std.mem.eql(u8, state.string, "HALT")) {
            if (objectField(result, "exception")) |ex| {
                if (ex == .string) std.log.err("invokescript fault: {s}", .{ex.string});
            }
            return error.InvokeFailed;
        }
        const gas = objectField(result, "gasconsumed") orelse return error.InvalidResponse;
        return .{ .gas_consumed = try expectInt(gas) };
    }

    pub fn calculateNetworkFee(self: *Client, tx_bytes: []const u8) !i64 {
        const b64 = try base64Encode(self.allocator, tx_bytes);
        defer self.allocator.free(b64);
        const params = try std.fmt.allocPrint(self.allocator, "[\"{s}\"]", .{b64});
        defer self.allocator.free(params);
        const raw = try self.call("calculatenetworkfee", params);
        defer self.allocator.free(raw);
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{});
        defer parsed.deinit();
        const result = objectField(parsed.value, "result") orelse return error.InvalidResponse;
        const fee = objectField(result, "networkfee") orelse return error.InvalidResponse;
        return try expectInt(fee);
    }

    pub fn sendRawTransaction(self: *Client, tx_bytes: []const u8) ![]u8 {
        const b64 = try base64Encode(self.allocator, tx_bytes);
        defer self.allocator.free(b64);
        const params = try std.fmt.allocPrint(self.allocator, "[\"{s}\"]", .{b64});
        defer self.allocator.free(params);
        const raw = try self.call("sendrawtransaction", params);
        defer self.allocator.free(raw);
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, raw, .{});
        defer parsed.deinit();
        const result = objectField(parsed.value, "result") orelse return error.InvalidResponse;
        const hash_val = objectField(result, "hash") orelse return error.InvalidResponse;
        const hash_str = switch (hash_val) {
            .string => |s| s,
            else => return error.InvalidResponse,
        };
        const trimmed = if (std.mem.startsWith(u8, hash_str, "0x")) hash_str[2..] else hash_str;
        return try self.allocator.dupe(u8, trimmed);
    }

    fn call(self: *Client, method: []const u8, params_json: []const u8) ![]u8 {
        const body = try std.fmt.allocPrint(self.allocator,
            "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{s}}}",
            .{ self.id, method, params_json },
        );
        defer self.allocator.free(body);
        self.id += 1;

        const response_body = try http.post(self.allocator, self.io, self.endpoint, "application/json", body);
        defer self.allocator.free(response_body);

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, response_body, .{});
        defer parsed.deinit();
        if (objectField(parsed.value, "error")) |err_val| {
            if (err_val == .object) {
                if (objectField(err_val, "message")) |msg| {
                    if (msg == .string) return error.RpcError;
                }
            }
            return error.RpcError;
        }
        return try self.allocator.dupe(u8, response_body);
    }
};

pub const Version = struct {
    network_magic: u32,
    validators_count: u32,
};

pub const InvokeResult = struct {
    gas_consumed: i64,
};

fn objectField(value: std.json.Value, key: []const u8) ?std.json.Value {
    if (value != .object) return null;
    return value.object.get(key);
}

fn expectInt(value: std.json.Value) !i64 {
    return switch (value) {
        .integer => |v| v,
        .float => |v| @intFromFloat(v),
        .string => |s| std.fmt.parseInt(i64, s, 10),
        else => error.InvalidResponse,
    };
}

fn base64Encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const size = std.base64.standard.Encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, size);
    _ = std.base64.standard.Encoder.encode(out, data);
    return out;
}

pub fn validUntilBlock(block_count: u32, validators_count: u32) u32 {
    return block_count + validators_count + 1;
}
