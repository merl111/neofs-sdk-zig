const std = @import("std");
const errors = @import("errors.zig");
const session_pb = @import("../../proto/gen/session/types.pb.zig");

const Stored = struct {
    code: i32,
    message: []const u8,
};

var last: ?Stored = null;

pub fn clear(allocator: std.mem.Allocator) void {
    _ = allocator;
    last = null;
}

pub fn validate(allocator: std.mem.Allocator, meta_header: ?session_pb.ResponseMetaHeader) !void {
    clear(allocator);
    const meta = meta_header orelse return;
    const st = meta.status orelse return;
    if (st.code != 0) {
        std.log.err("neofs: server status code={d} message={s}", .{ st.code, st.message });
        last = .{
            .code = @intCast(st.code),
            .message = st.message,
        };
        return errors.fromCode(@intCast(st.code));
    }
}

/// Returns an owned one-line error summary, or null if no NeoFS status was recorded.
pub fn takeFormatted(allocator: std.mem.Allocator) ?[]u8 {
    const stored = last orelse return null;
    last = null;

    const detail = friendlyDetail(stored.message);
    if (detail.len > 0) {
        return std.fmt.allocPrint(allocator, "status: code = {d} message = {s}", .{ stored.code, detail }) catch null;
    }
    return std.fmt.allocPrint(allocator, "status: code = {d}", .{stored.code}) catch null;
}

pub fn friendlyDetail(message: []const u8) []const u8 {
    const needle = "unhandled exception: \"";
    if (std.mem.indexOf(u8, message, needle)) |idx| {
        const rest = message[idx + needle.len ..];
        if (std.mem.indexOfScalar(u8, rest, '"')) |end| {
            return rest[0..end];
        }
    }
    if (std.mem.indexOf(u8, message, "message = ")) |idx| {
        return std.mem.trim(u8, message[idx + "message = ".len ..], " \r\n\t");
    }
    return std.mem.trim(u8, message, " \r\n\t");
}

test "fromCode maps response status codes" {
    const errors_mod = @import("errors.zig");
    const code = @intFromEnum(@import("../../proto/status/codes.zig").Code.object_not_found);
    try std.testing.expectEqual(error.ObjectNotFound, errors_mod.fromCode(code));
}

test "validate success clears stored status" {
    const meta = session_pb.ResponseMetaHeader{
        .status = .{
            .code = 0,
            .message = "",
        },
    };
    try validate(std.testing.allocator, meta);
    try std.testing.expect(takeFormatted(std.testing.allocator) == null);
}

test "friendlyDetail extracts contract exception" {
    const raw = "chain/client: contract execution finished with state FAULT; exception: at instruction 5828 (THROW): unhandled exception: \"insufficient balance to create container\"";
    try std.testing.expectEqualStrings("insufficient balance to create container", friendlyDetail(raw));
}
