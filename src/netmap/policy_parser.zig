//! Native lexer/parser for NeoFS placement policy strings (`Query.g4` / `QueryLexer.g4`).
const std = @import("std");
const netmap_pb = @import("../proto/gen/netmap/types.pb.zig");

pub const PlacementPolicy = netmap_pb.PlacementPolicy;
pub const Filter = netmap_pb.Filter;
pub const Selector = netmap_pb.Selector;
pub const Replica = netmap_pb.Replica;
pub const ECRule = netmap_pb.PlacementPolicy.ECRule;
pub const Operation = netmap_pb.Operation;
pub const Clause = netmap_pb.Clause;

pub const mainFilterName = "*";

pub const ParseError = error{
    SyntaxError,
    InvalidPolicy,
    UnknownFilter,
    UnknownSelector,
    InvalidNumber,
    OutOfMemory,
};

const Token = enum {
    eof,
    and_op,
    or_op,
    simple_op,
    rep,
    @"in",
    as,
    cbf,
    select,
    from,
    filter,
    wildcard,
    ec,
    clause_same,
    clause_distinct,
    l_paren,
    r_paren,
    at,
    ec_sep,
    ident,
    number,
    string,
};

const Lexer = struct {
    src: []const u8,
    i: usize = 0,

    fn peek(self: Lexer) ?u8 {
        if (self.i >= self.src.len) return null;
        return self.src[self.i];
    }

    fn bump(self: *Lexer) ?u8 {
        const c = self.peek() orelse return null;
        self.i += 1;
        return c;
    }

    fn skipWs(self: *Lexer) void {
        while (self.peek()) |c| {
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                _ = self.bump();
            } else break;
        }
    }

    fn matchWord(self: *Lexer, word: []const u8) bool {
        if (self.i + word.len > self.src.len) return false;
        if (!std.mem.eql(u8, self.src[self.i .. self.i + word.len], word)) return false;
        if (self.i + word.len < self.src.len) {
            const after = self.src[self.i + word.len];
            if ((after >= 'a' and after <= 'z') or (after >= 'A' and after <= 'Z') or
                (after >= '0' and after <= '9') or after == '_')
                return false;
        }
        self.i += word.len;
        return true;
    }

    fn readIdent(self: *Lexer, start: usize) []const u8 {
        while (self.peek()) |c| {
            if ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
                (c >= '0' and c <= '9') or c == '_')
            {
                _ = self.bump();
            } else break;
        }
        return self.src[start..self.i];
    }

    fn readNumber(self: *Lexer, start: usize) []const u8 {
        while (self.peek()) |c| {
            if (c >= '0' and c <= '9') _ = self.bump() else break;
        }
        return self.src[start..self.i];
    }

    fn unescapeString(_: *Lexer, allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(allocator);
        var j: usize = 0;
        while (j < raw.len) : (j += 1) {
            if (raw[j] == '\\' and j + 1 < raw.len) {
                j += 1;
                const esc = raw[j];
                switch (esc) {
                    'n' => try out.append(allocator, '\n'),
                    't' => try out.append(allocator, '\t'),
                    'r' => try out.append(allocator, '\r'),
                    'b' => try out.append(allocator, 8),
                    'f' => try out.append(allocator, '\x0c'),
                    'u' => {
                        if (j + 4 >= raw.len) return ParseError.SyntaxError;
                        const hex = raw[j + 1 .. j + 5];
                        const cp = try std.fmt.parseInt(u21, hex, 16);
                        var buf: [4]u8 = undefined;
                        const len = try std.unicode.utf8Encode(cp, &buf);
                        try out.appendSlice(allocator, buf[0..len]);
                        j += 4;
                    },
                    else => try out.append(allocator, esc),
                }
            } else {
                try out.append(allocator, raw[j]);
            }
        }
        return try out.toOwnedSlice(allocator);
    }

    fn readString(self: *Lexer, allocator: std.mem.Allocator, quote: u8) ![]u8 {
        const start = self.i;
        while (self.peek()) |c| {
            if (c == '\\') {
                _ = self.bump();
                if (self.bump() == null) return ParseError.SyntaxError;
                continue;
            }
            if (c == quote) {
                const raw = self.src[start..self.i];
                _ = self.bump();
                return self.unescapeString(allocator, raw);
            }
            _ = self.bump();
        }
        return ParseError.SyntaxError;
    }

    fn next(self: *Lexer, allocator: std.mem.Allocator) ParseError!struct { tok: Token, text: []const u8, owned: ?[]u8 = null } {
        self.skipWs();
        const start = self.i;
        const c = self.peek() orelse return .{ .tok = .eof, .text = "" };

        if (c == '(') {
            _ = self.bump();
            return .{ .tok = .l_paren, .text = "(" };
        }
        if (c == ')') {
            _ = self.bump();
            return .{ .tok = .r_paren, .text = ")" };
        }
        if (c == '@') {
            _ = self.bump();
            return .{ .tok = .at, .text = "@" };
        }
        if (c == '*') {
            _ = self.bump();
            return .{ .tok = .wildcard, .text = "*" };
        }
        if (c == '/') {
            _ = self.bump();
            return .{ .tok = .ec_sep, .text = "/" };
        }
        if (c == '"' or c == '\'') {
            _ = self.bump();
            const owned = self.readString(allocator, c) catch return ParseError.SyntaxError;
            return .{ .tok = .string, .text = owned, .owned = owned };
        }

        if (c >= '0' and c <= '9') {
            if (c == '0' and (self.i + 1 >= self.src.len or self.src[self.i + 1] < '0' or self.src[self.i + 1] > '9')) {
                _ = self.bump();
                return .{ .tok = .number, .text = "0" };
            }
            if (c == '0') return ParseError.SyntaxError;
            const text = self.readNumber(start);
            return .{ .tok = .number, .text = text };
        }

        if ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_') {
            const word = self.readIdent(start);
            if (std.mem.eql(u8, word, "AND")) return .{ .tok = .and_op, .text = word };
            if (std.mem.eql(u8, word, "OR")) return .{ .tok = .or_op, .text = word };
            if (std.mem.eql(u8, word, "EQ") or std.mem.eql(u8, word, "NE") or
                std.mem.eql(u8, word, "GE") or std.mem.eql(u8, word, "GT") or
                std.mem.eql(u8, word, "LT") or std.mem.eql(u8, word, "LE"))
                return .{ .tok = .simple_op, .text = word };
            if (std.ascii.eqlIgnoreCase(word, "REP")) return .{ .tok = .rep, .text = word };
            if (std.ascii.eqlIgnoreCase(word, "IN")) return .{ .tok = .@"in", .text = word };
            if (std.ascii.eqlIgnoreCase(word, "AS")) return .{ .tok = .as, .text = word };
            if (std.ascii.eqlIgnoreCase(word, "CBF")) return .{ .tok = .cbf, .text = word };
            if (std.ascii.eqlIgnoreCase(word, "SELECT")) return .{ .tok = .select, .text = word };
            if (std.ascii.eqlIgnoreCase(word, "FROM")) return .{ .tok = .from, .text = word };
            if (std.ascii.eqlIgnoreCase(word, "FILTER")) return .{ .tok = .filter, .text = word };
            if (std.ascii.eqlIgnoreCase(word, "EC")) return .{ .tok = .ec, .text = word };
            if (std.mem.eql(u8, word, "SAME")) return .{ .tok = .clause_same, .text = word };
            if (std.mem.eql(u8, word, "DISTINCT")) return .{ .tok = .clause_distinct, .text = word };
            return .{ .tok = .ident, .text = word };
        }

        return ParseError.SyntaxError;
    }
};

const Parser = struct {
    lexer: Lexer,
    allocator: std.mem.Allocator,
    tok: Token = .eof,
    text: []const u8 = "",
    owned: ?[]u8 = null,

    fn deinitCurrent(self: *Parser) void {
        if (self.owned) |o| {
            self.allocator.free(o);
            self.owned = null;
        }
    }

    fn advance(self: *Parser) ParseError!void {
        self.deinitCurrent();
        const n = try self.lexer.next(self.allocator);
        self.tok = n.tok;
        self.text = n.text;
        self.owned = n.owned;
    }

    fn expect(self: *Parser, t: Token) ParseError!void {
        if (self.tok != t) return ParseError.SyntaxError;
        try self.advance();
    }

    fn dup(self: *Parser, s: []const u8) ParseError![]u8 {
        return self.allocator.dupe(u8, s) catch return ParseError.OutOfMemory;
    }

    fn parseU32(_: *Parser, text: []const u8) ParseError!u32 {
        const v = std.fmt.parseInt(u32, text, 10) catch return ParseError.InvalidNumber;
        return v;
    }

    fn identText(self: *Parser) ParseError![]u8 {
        return switch (self.tok) {
            .ident, .rep, .@"in", .as, .select, .from, .filter, .ec => self.dup(self.text),
            else => ParseError.SyntaxError,
        };
    }

    fn consumeIdent(self: *Parser) ParseError![]u8 {
        const s = try self.identText();
        try self.advance();
        return s;
    }

    fn operationFromText(text: []const u8) Operation {
        if (std.mem.eql(u8, text, "EQ")) return .EQ;
        if (std.mem.eql(u8, text, "NE")) return .NE;
        if (std.mem.eql(u8, text, "GT")) return .GT;
        if (std.mem.eql(u8, text, "GE")) return .GE;
        if (std.mem.eql(u8, text, "LT")) return .LT;
        if (std.mem.eql(u8, text, "LE")) return .LE;
        if (std.mem.eql(u8, text, "OR")) return .OR;
        if (std.mem.eql(u8, text, "AND")) return .AND;
        return .OPERATION_UNSPECIFIED;
    }

    fn clauseFromText(text: []const u8) Clause {
        if (std.mem.eql(u8, text, "SAME")) return .SAME;
        if (std.mem.eql(u8, text, "DISTINCT")) return .DISTINCT;
        return .CLAUSE_UNSPECIFIED;
    }

    fn parseFilterKey(self: *Parser) ParseError![]u8 {
        return switch (self.tok) {
            .ident, .rep, .@"in", .as, .select, .from, .filter, .ec => self.consumeIdent(),
            .string => blk: {
                const s = try self.dup(self.text);
                try self.advance();
                break :blk s;
            },
            else => ParseError.SyntaxError,
        };
    }

    fn parseFilterValue(self: *Parser) ParseError![]u8 {
        return switch (self.tok) {
            .ident, .rep, .@"in", .as, .select, .from, .filter, .ec => self.consumeIdent(),
            .number => blk: {
                const s = try self.dup(self.text);
                try self.advance();
                break :blk s;
            },
            .string => blk: {
                const s = try self.dup(self.text);
                try self.advance();
                break :blk s;
            },
            else => ParseError.SyntaxError,
        };
    }

    fn parseExpr(self: *Parser) ParseError!Filter {
        if (self.tok == .at) {
            try self.advance();
            const name = try self.consumeIdent();
            return .{ .name = name };
        }
        const key = try self.parseFilterKey();
        if (self.tok != .simple_op) return ParseError.SyntaxError;
        const op = operationFromText(self.text);
        try self.advance();
        const value = try self.parseFilterValue();
        return .{ .key = key, .op = op, .value = value };
    }

    fn mergeBinary(self: *Parser, op: Operation, f1: Filter, f2: Filter) ParseError!Filter {
        var f: Filter = .{ .op = op };
        var left = f1;
        if (left.op == op and left.filters.items.len > 0) {
            try f.filters.appendSlice(self.allocator, left.filters.items);
            left.filters = .empty;
            left.deinit(self.allocator);
        } else {
            try f.filters.append(self.allocator, left);
        }
        try f.filters.append(self.allocator, f2);
        return f;
    }

    fn parseFilterExprPrimary(self: *Parser) ParseError!Filter {
        if (self.tok == .l_paren) {
            try self.advance();
            const inner = try self.parseFilterExpr();
            try self.expect(.r_paren);
            return inner;
        }
        return self.parseExpr();
    }

    fn parseFilterExprAnd(self: *Parser) ParseError!Filter {
        var left = try self.parseFilterExprPrimary();
        while (self.tok == .and_op) {
            const op_text = self.text;
            try self.advance();
            const right = try self.parseFilterExprPrimary();
            const merged = try self.mergeBinary(operationFromText(op_text), left, right);
            left = merged;
        }
        return left;
    }

    fn parseFilterExpr(self: *Parser) ParseError!Filter {
        var left = try self.parseFilterExprAnd();
        while (self.tok == .or_op) {
            const op_text = self.text;
            try self.advance();
            const right = try self.parseFilterExprAnd();
            const merged = try self.mergeBinary(operationFromText(op_text), left, right);
            left = merged;
        }
        return left;
    }

    fn parseFilterStmt(self: *Parser) ParseError!Filter {
        try self.expect(.filter);
        var expr = try self.parseFilterExpr();
        try self.expect(.as);
        const name = try self.consumeIdent();
        expr.name = name;
        return expr;
    }

    fn parseIdentWC(self: *Parser) ParseError![]u8 {
        if (self.tok == .wildcard) {
            const s = try self.dup(mainFilterName);
            try self.advance();
            return s;
        }
        return self.consumeIdent();
    }

    fn parseSelectStmt(self: *Parser) ParseError!Selector {
        try self.expect(.select);
        const count = try self.parseU32(self.text);
        try self.expect(.number);
        var sel: Selector = .{ .count = count };
        if (self.tok == .@"in") {
            try self.advance();
            if (self.tok == .clause_same or self.tok == .clause_distinct) {
                sel.clause = clauseFromText(self.text);
                try self.advance();
            }
            sel.attribute = try self.consumeIdent();
        }
        try self.expect(.from);
        sel.filter = try self.parseIdentWC();
        if (self.tok == .as) {
            try self.advance();
            sel.name = try self.consumeIdent();
        }
        return sel;
    }

    fn parseRepStmt(self: *Parser) ParseError!Replica {
        try self.expect(.rep);
        const count = try self.parseU32(self.text);
        try self.expect(.number);
        var rep: Replica = .{ .count = count };
        if (self.tok == .@"in") {
            try self.advance();
            rep.selector = try self.consumeIdent();
        }
        return rep;
    }

    fn parseEcStmt(self: *Parser) ParseError!ECRule {
        try self.expect(.ec);
        const data = try self.parseU32(self.text);
        try self.expect(.number);
        try self.expect(.ec_sep);
        const parity = try self.parseU32(self.text);
        try self.expect(.number);
        var rule: ECRule = .{ .data_part_num = data, .parity_part_num = parity };
        if (self.tok == .@"in") {
            try self.advance();
            rule.selector = try self.consumeIdent();
        }
        return rule;
    }

    fn parseRuleStmt(self: *Parser, policy: *PlacementPolicy) ParseError!void {
        if (self.tok == .ec) {
            const rule = try self.parseEcStmt();
            try policy.ec_rules.append(self.allocator, rule);
            return;
        }
        if (self.tok == .rep) {
            const rep = try self.parseRepStmt();
            try policy.replicas.append(self.allocator, rep);
            return;
        }
        return ParseError.SyntaxError;
    }

    fn parseCbfStmt(self: *Parser) ParseError!u32 {
        try self.expect(.cbf);
        const v = try self.parseU32(self.text);
        try self.expect(.number);
        return v;
    }

    fn parsePolicy(self: *Parser) ParseError!PlacementPolicy {
        var policy: PlacementPolicy = .{};
        errdefer policy.deinit(self.allocator);
        while (self.tok == .rep or self.tok == .ec) {
            try self.parseRuleStmt(&policy);
        }
        if (policy.replicas.items.len == 0 and policy.ec_rules.items.len == 0) {
            return ParseError.InvalidPolicy;
        }
        if (self.tok == .cbf) {
            policy.container_backup_factor = try self.parseCbfStmt();
        }
        while (self.tok == .select) {
            const sel = try self.parseSelectStmt();
            try policy.selectors.append(self.allocator, sel);
        }
        while (self.tok == .filter) {
            const flt = try self.parseFilterStmt();
            try policy.filters.append(self.allocator, flt);
        }
        if (self.tok != .eof) return ParseError.SyntaxError;
        try validatePolicy(self.allocator, policy);
        return policy;
    }
};

pub fn validatePolicy(allocator: std.mem.Allocator, policy: PlacementPolicy) ParseError!void {
    var seen_filters = std.StringHashMap(void).init(allocator);
    defer seen_filters.deinit();
    for (policy.filters.items) |f| {
        try seen_filters.put(f.name, {});
    }

    var seen_selectors = std.StringHashMap(void).init(allocator);
    defer seen_selectors.deinit();
    for (policy.selectors.items) |s| {
        const flt = s.filter;
        if (flt.len != 0 and !std.mem.eql(u8, flt, mainFilterName) and seen_filters.get(flt) == null) {
            return ParseError.UnknownFilter;
        }
        try seen_selectors.put(s.name, {});
    }

    for (policy.replicas.items) |r| {
        if (r.selector.len != 0 and seen_selectors.get(r.selector) == null) {
            return ParseError.UnknownSelector;
        }
    }

    for (policy.ec_rules.items) |r| {
        if (r.selector.len != 0 and seen_selectors.get(r.selector) == null) {
            return ParseError.UnknownSelector;
        }
    }
}

/// Parses a placement policy string into an owned [PlacementPolicy].
pub fn decodeString(allocator: std.mem.Allocator, input: []const u8) ParseError!PlacementPolicy {
    var parser = Parser{
        .lexer = .{ .src = input },
        .allocator = allocator,
    };
    try parser.advance();
    return parser.parsePolicy();
}

pub fn deinitPolicy(policy: *PlacementPolicy, allocator: std.mem.Allocator) void {
    policy.deinit(allocator);
}

fn operationString(op: Operation) []const u8 {
    return switch (op) {
        .EQ => "EQ",
        .NE => "NE",
        .GT => "GT",
        .GE => "GE",
        .LT => "LT",
        .LE => "LE",
        .OR => "OR",
        .AND => "AND",
        else => "",
    };
}

fn writeFilterString(writer: *std.Io.Writer, f: Filter) !void {
    const op = f.op;
    const unspecified = op == .OPERATION_UNSPECIFIED;
    if (f.key.len > 0) {
        try writer.print("{s} {s} {s}", .{ f.key, operationString(op), f.value });
    } else if (f.name.len > 0 and unspecified) {
        try writer.print("@{s}", .{f.name});
    }
    for (f.filters.items, 0..) |sub, i| {
        if (i != 0) try writer.print(" {s} ", .{operationString(op)});
        try writeFilterString(writer, sub);
    }
    if (f.name.len > 0 and !unspecified) {
        try writer.print(" AS {s}", .{f.name});
    }
}

/// Encodes a placement policy into the NeoFS policy language string.
pub fn encodeString(allocator: std.mem.Allocator, policy: PlacementPolicy) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    var written_smth = false;

    const write_line_prefix = struct {
        fn call(list: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator, ws: *bool) !void {
            if (ws.*) try list.append(alloc, '\n');
            ws.* = true;
        }
    }.call;

    for (policy.replicas.items) |r| {
        try write_line_prefix(&buf, allocator, &written_smth);
        if (r.selector.len > 0) {
            try buf.print(allocator, "REP {d} IN {s}", .{ r.count, r.selector });
        } else {
            try buf.print(allocator, "REP {d}", .{r.count});
        }
    }

    for (policy.ec_rules.items) |rule| {
        try write_line_prefix(&buf, allocator, &written_smth);
        if (rule.selector.len > 0) {
            try buf.print(allocator, "EC {d}/{d} IN {s}", .{ rule.data_part_num, rule.parity_part_num, rule.selector });
        } else {
            try buf.print(allocator, "EC {d}/{d}", .{ rule.data_part_num, rule.parity_part_num });
        }
    }

    if (policy.container_backup_factor > 0) {
        try write_line_prefix(&buf, allocator, &written_smth);
        try buf.print(allocator, "CBF {d}", .{policy.container_backup_factor});
    }

    for (policy.selectors.items) |s| {
        try write_line_prefix(&buf, allocator, &written_smth);
        try buf.print(allocator, "SELECT {d}", .{s.count});
        if (s.attribute.len > 0) {
            const clause: []const u8 = switch (s.clause) {
                .SAME => "SAME ",
                .DISTINCT => "DISTINCT ",
                else => "",
            };
            try buf.print(allocator, " IN {s}{s}", .{ clause, s.attribute });
        }
        if (s.filter.len > 0) {
            try buf.print(allocator, " FROM {s}", .{s.filter});
        }
        if (s.name.len > 0) {
            try buf.print(allocator, " AS {s}", .{s.name});
        }
    }

    for (policy.filters.items) |f| {
        try write_line_prefix(&buf, allocator, &written_smth);
        try buf.appendSlice(allocator, "FILTER ");
        var filter_writer: std.Io.Writer.Allocating = .init(allocator);
        defer filter_writer.deinit();
        try writeFilterString(&filter_writer.writer, f);
        try buf.appendSlice(allocator, filter_writer.written());
    }

    return try buf.toOwnedSlice(allocator);
}

const max_object_replicas_per_set: u32 = 8;
const max_container_nodes_in_set: u32 = 64;
const max_rep_rules: usize = 256;
const max_container_nodes: u32 = 512;
const default_container_backup_factor: u32 = 3;

fn selectorByName(policy: PlacementPolicy, name: []const u8) ?Selector {
    for (policy.selectors.items) |s| {
        if (std.mem.eql(u8, s.name, name)) return s;
    }
    return null;
}

/// Returns `null` when valid; otherwise an allocated human-readable error message.
pub fn verifyPolicyErrmsg(allocator: std.mem.Allocator, policy: PlacementPolicy) !?[]const u8 {
    if (policy.replicas.items.len > max_rep_rules) {
        return try std.fmt.allocPrint(allocator, "more than {d} REP rules", .{max_rep_rules});
    }

    const bf: u32 = if (policy.container_backup_factor == 0)
        default_container_backup_factor
    else
        policy.container_backup_factor;

    var cnr_node_count: u32 = 0;
    for (policy.replicas.items, 0..) |rep, i| {
        const r_num = rep.count;
        if (r_num > max_object_replicas_per_set) {
            return try std.fmt.allocPrint(allocator, "invalid REP rule #{d}: more than {d} object replicas", .{ i, max_object_replicas_per_set });
        }
        const s_num: u32 = if (rep.selector.len > 0) blk: {
            const sel = selectorByName(policy, rep.selector) orelse {
                return try std.fmt.allocPrint(allocator, "invalid REP rule #{d}: missing selector \"{s}\"", .{ i, rep.selector });
            };
            break :blk sel.count;
        } else r_num;
        const nodes_in_set = bf * s_num;
        if (nodes_in_set > max_container_nodes_in_set) {
            return try std.fmt.allocPrint(allocator, "invalid REP rule #{d}: more than {d} nodes", .{ i, max_container_nodes_in_set });
        }
        cnr_node_count +|= nodes_in_set;
        if (cnr_node_count > max_container_nodes) {
            return try std.fmt.allocPrint(allocator, "more than {d} nodes in total", .{max_container_nodes});
        }
    }

    for (policy.ec_rules.items, 0..) |rule, i| {
        const s_num: u32 = if (rule.selector.len > 0) blk: {
            const sel = selectorByName(policy, rule.selector) orelse {
                return try std.fmt.allocPrint(allocator, "invalid EC rule #{d}: missing selector \"{s}\"", .{ i, rule.selector });
            };
            break :blk sel.count;
        } else rule.data_part_num + rule.parity_part_num;
        const nodes_in_set = bf * s_num;
        if (nodes_in_set > max_container_nodes_in_set) {
            return try std.fmt.allocPrint(allocator, "invalid EC rule #{d}: more than {d} nodes", .{ i, max_container_nodes_in_set });
        }
        cnr_node_count +|= nodes_in_set;
        if (cnr_node_count > max_container_nodes) {
            return try std.fmt.allocPrint(allocator, "more than {d} nodes in total", .{max_container_nodes});
        }
    }

    return null;
}

pub fn verifyPolicy(allocator: std.mem.Allocator, policy: PlacementPolicy) !void {
    if (try verifyPolicyErrmsg(allocator, policy)) |msg| {
        defer allocator.free(msg);
        return error.InvalidPolicy;
    }
}

test "decode simple rep and cbf" {
    var p = try decodeString(std.testing.allocator, "REP 3 CBF 2");
    defer deinitPolicy(&p, std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 3), p.replicas.items[0].count);
    try std.testing.expectEqual(@as(u32, 2), p.container_backup_factor);
}

test "decode rep with selector and filters" {
    const s =
        \\REP 1
        \\SELECT 2 IN SAME Location FROM * AS X
        \\FILTER Country EQ UA AS FromUA
    ;
    var p = try decodeString(std.testing.allocator, s);
    defer deinitPolicy(&p, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), p.replicas.items.len);
    try std.testing.expectEqual(@as(usize, 1), p.selectors.items.len);
    try std.testing.expectEqual(@as(usize, 1), p.filters.items.len);
    try std.testing.expect(std.mem.eql(u8, p.selectors.items[0].name, "X"));
    try std.testing.expect(std.mem.eql(u8, p.filters.items[0].name, "FromUA"));
}

test "decode ec rule" {
    var p = try decodeString(std.testing.allocator, "EC 3/1");
    defer deinitPolicy(&p, std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 3), p.ec_rules.items[0].data_part_num);
    try std.testing.expectEqual(@as(u32, 1), p.ec_rules.items[0].parity_part_num);
}

test "reject trailing garbage" {
    try std.testing.expectError(ParseError.SyntaxError, decodeString(std.testing.allocator, "REP 1 trailing"));
}

test "reject unknown selector reference" {
    try std.testing.expectError(ParseError.UnknownSelector, decodeString(std.testing.allocator, "REP 1 IN missing"));
}

test "decode filter expression with reference and comparison" {
    const s =
        \\REP 1
        \\SELECT 2 IN City FROM Good
        \\FILTER Country EQ UA AS FromUA
        \\FILTER @FromUA AND Rating GT 7 AS Good
    ;
    var p = try decodeString(std.testing.allocator, s);
    defer deinitPolicy(&p, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), p.filters.items.len);
    try std.testing.expectEqual(Operation.AND, p.filters.items[1].op);
    try std.testing.expectEqual(@as(usize, 2), p.filters.items[1].filters.items.len);
}
