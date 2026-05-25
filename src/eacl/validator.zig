const std = @import("std");
const table = @import("table.zig");

pub const Validator = struct {};

pub const CalculateError = error{
    HeaderSourceError,
};

pub fn calculateAction(v: Validator, unit: table.ValidationUnit) CalculateError!struct {
    action: table.Action,
    matched: bool,
} {
    _ = v;
    for (unit.table.records.items) |record| {
        if (record.operation != unit.operation) continue;
        if (!targetMatches(unit, record)) continue;

        const filter_result = matchFilters(unit.hdr_src, record.filters) catch return .{
            .action = .deny,
            .matched = false,
        };
        switch (filter_result) {
            .missing_headers => return .{ .action = .allow, .matched = false },
            .all_matched => return .{ .action = record.action, .matched = true },
            .not_matched => {},
        }
    }
    return .{ .action = .allow, .matched = false };
}

const FilterMatchResult = enum {
    all_matched,
    not_matched,
    missing_headers,
};

pub fn matchFilters(hdr_src: table.HeaderSource, filters: []const table.Filter) CalculateError!FilterMatchResult {
    var matched: usize = 0;

    filter_loop: for (filters) |filter| {
        const hdrs = hdr_src.headersOfType(filter.header_type);
        if (!hdrs.ok) return .missing_headers;

        const m = filter.match;
        if (m == .num_gt or m == .num_ge or m == .num_lt or m == .num_le) {
            if (!isDecimalString(filter.value)) continue;
        } else if (m == .unspecified) {
            continue;
        }

        for (hdrs.headers) |header| {
            if (!std.mem.eql(u8, header.key, filter.key)) continue;

            switch (m) {
                .not_present => {
                    matched += 1;
                    continue :filter_loop;
                },
                .string_equal => {
                    if (!std.mem.eql(u8, header.value, filter.value)) continue;
                },
                .string_not_equal => {
                    if (std.mem.eql(u8, header.value, filter.value)) continue;
                },
                .num_gt, .num_ge, .num_lt, .num_le => {
                    if (!isDecimalString(header.value)) continue;
                    const cmp = cmpDecimalStrings(header.value, filter.value);
                    switch (m) {
                        .num_gt => if (cmp != .gt) continue,
                        .num_ge => if (cmp != .gt and cmp != .eq) continue,
                        .num_lt => if (cmp != .lt) continue,
                        .num_le => if (cmp != .lt and cmp != .eq) continue,
                        else => continue,
                    }
                },
                else => continue,
            }

            matched += 1;
            continue :filter_loop;
        }

        if (m == .not_present) matched += 1;
    }

    if (matched == filters.len) return .all_matched;
    return .not_matched;
}

pub fn targetMatches(unit: table.ValidationUnit, record: table.Record) bool {
    for (record.targets) |target| {
        if (target.role == .system) continue;

        var check_role = true;

        if (target.keys.len != 0) {
            check_role = false;
            if (unit.sender_key) |key| {
                for (target.keys) |pub_key| {
                    if (std.mem.eql(u8, pub_key, key)) return true;
                }
            }
        }

        if (target.accounts.len != 0) {
            check_role = false;
            if (unit.account) |acc| {
                for (target.accounts) |account| {
                    if (std.mem.eql(u8, &account, &acc)) return true;
                }
            }
        }

        if (check_role and unit.role == target.role) return true;
    }
    return false;
}

const DecimalCmp = enum { lt, eq, gt };

fn isDecimalString(s: []const u8) bool {
    if (s.len == 0) return false;
    var i: usize = 0;
    if (s[0] == '-') {
        if (s.len == 1) return false;
        i = 1;
    }
    for (s[i..]) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

fn cmpDecimalStrings(a: []const u8, b: []const u8) DecimalCmp {
    const neg_a = a.len > 0 and a[0] == '-';
    const neg_b = b.len > 0 and b[0] == '-';
    if (neg_a != neg_b) return if (neg_a) .lt else .gt;

    const sa = if (neg_a) trimLeadingZeros(a[1..]) else trimLeadingZeros(a);
    const sb = if (neg_b) trimLeadingZeros(b[1..]) else trimLeadingZeros(b);

    if (sa.len != sb.len) {
        const gt = sa.len > sb.len;
        if (neg_a) return if (gt) .lt else .gt;
        return if (gt) .gt else .lt;
    }
    const ord = std.mem.order(u8, sa, sb);
    if (ord == .eq) return .eq;
    const gt = ord == .gt;
    if (neg_a) return if (gt) .lt else .gt;
    return if (gt) .gt else .lt;
}

fn trimLeadingZeros(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i + 1 < s.len and s[i] == '0') : (i += 1) {}
    return s[i..];
}
