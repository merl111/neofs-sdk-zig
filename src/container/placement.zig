//! Placement policy presets for container creation (replica + backup factor).
//!
//! NeoFS supports a full policy language (`REP 3`, `EC 3/1`, selectors, …).
//! [netmap.policy] parses policy strings; this module provides presets and
//! conversion into the stable container wire shape.

const std = @import("std");
const stable = @import("../internal/proto/stable.zig");
const netmap = @import("../netmap/netmap.zig");

pub const Preset = struct {
    id: []const u8,
    label: []const u8,
    description: []const u8,
    /// Equivalent NeoFS policy language string (informational).
    policy_hint: []const u8,
    replica_count: u64,
    backup_factor: u64,
};

pub const presets = [_]Preset{
    .{
        .id = "single",
        .label = "Single replica",
        .description = "One copy per object; minimal storage use",
        .policy_hint = "REP 1 CBF 1",
        .replica_count = 1,
        .backup_factor = 1,
    },
    .{
        .id = "standard",
        .label = "Standard (3 replicas)",
        .description = "Three copies; typical production default",
        .policy_hint = "REP 3 CBF 1",
        .replica_count = 3,
        .backup_factor = 1,
    },
    .{
        .id = "ha",
        .label = "High availability",
        .description = "Three replicas with higher backup factor",
        .policy_hint = "REP 3 CBF 2",
        .replica_count = 3,
        .backup_factor = 2,
    },
    .{
        .id = "geo-2",
        .label = "Two replicas",
        .description = "Two copies; balance between cost and redundancy",
        .policy_hint = "REP 2 CBF 1",
        .replica_count = 2,
        .backup_factor = 1,
    },
};

pub fn findById(id: []const u8) ?Preset {
    for (presets) |p| {
        if (std.mem.eql(u8, p.id, id)) return p;
    }
    return null;
}

pub fn defaultPreset() Preset {
    return presets[1]; // standard REP 3
}

pub fn buildPolicy(
    allocator: std.mem.Allocator,
    replica_count: u64,
    backup_factor: u64,
) !stable.PlacementPolicy {
    if (replica_count == 0) return error.InvalidReplicaCount;
    if (backup_factor == 0) return error.InvalidBackupFactor;

    const replicas = try allocator.alloc(stable.Replica, 1);
    errdefer allocator.free(replicas);
    replicas[0] = .{ .count = replica_count };

    return .{
        .replicas = replicas,
        .backup_factor = backup_factor,
    };
}

pub fn buildFromPreset(allocator: std.mem.Allocator, preset: Preset) !stable.PlacementPolicy {
    return buildPolicy(allocator, preset.replica_count, preset.backup_factor);
}

/// Parses policy text produced by NeoFS tooling into [stable.PlacementPolicy].
/// Human-readable breakdown of a parsed placement policy.
pub const PolicyAnalysis = struct {
    replica_count: u64 = 0,
    backup_factor: u64 = 1,
    rep_rules: u32 = 0,
    ec_rules: u32 = 0,
    selectors: u32 = 0,
    filters: u32 = 0,
    uses_named_selectors: bool = false,
};

/// True when the policy uses SELECT/FILTER/EC sections not yet sent on container PUT by this SDK.
pub fn policyNeedsAdvancedWire(parsed: netmap.policy.PlacementPolicy) bool {
    if (parsed.selectors.items.len > 0) return true;
    if (parsed.filters.items.len > 0) return true;
    if (parsed.ec_rules.items.len > 0) return true;
    return false;
}

pub fn analyzePolicyString(allocator: std.mem.Allocator, policy: []const u8) !PolicyAnalysis {
    var parsed = try netmap.policy.decodeString(allocator, policy);
    defer netmap.policy.deinitPolicy(&parsed, allocator);
    return analyzeParsed(parsed);
}

pub fn analyzeParsed(parsed: netmap.policy.PlacementPolicy) PolicyAnalysis {
    var out = PolicyAnalysis{
        .backup_factor = if (parsed.container_backup_factor == 0) 1 else parsed.container_backup_factor,
        .rep_rules = @intCast(parsed.replicas.items.len),
        .ec_rules = @intCast(parsed.ec_rules.items.len),
        .selectors = @intCast(parsed.selectors.items.len),
        .filters = @intCast(parsed.filters.items.len),
    };
    for (parsed.replicas.items) |r| {
        out.replica_count += r.count;
        if (r.selector.len > 0) out.uses_named_selectors = true;
    }
    return out;
}

pub fn printPolicyAnalysis(writer: anytype, a: PolicyAnalysis) !void {
    try writer.print("  replica rules: {d}\n", .{a.rep_rules});
    if (a.rep_rules > 0) try writer.print("  object copies (sum of REP): {d}\n", .{a.replica_count});
    try writer.print("  container backup factor (CBF): {d}\n", .{a.backup_factor});
    if (a.selectors > 0) try writer.print("  SELECT rules: {d}\n", .{a.selectors});
    if (a.filters > 0) try writer.print("  FILTER rules: {d}\n", .{a.filters});
    if (a.ec_rules > 0) try writer.print("  EC rules: {d}\n", .{a.ec_rules});
    if (a.uses_named_selectors) try writer.writeAll("  uses REP … IN <selector> references\n");
}

pub fn stableFromParsed(allocator: std.mem.Allocator, parsed: netmap.policy.PlacementPolicy) !stable.PlacementPolicy {
    if (parsed.replicas.items.len == 0 and parsed.ec_rules.items.len == 0) return error.InvalidPolicy;

    const replicas = try allocator.alloc(stable.Replica, parsed.replicas.items.len);
    errdefer allocator.free(replicas);
    for (parsed.replicas.items, replicas) |src, *dst| {
        dst.* = .{
            .count = src.count,
            .selector = try allocator.dupe(u8, src.selector),
        };
    }

    const selectors = try allocator.alloc(stable.Selector, parsed.selectors.items.len);
    errdefer {
        for (selectors) |s| stable.deinitSelector(allocator, s);
        allocator.free(selectors);
    }
    for (parsed.selectors.items, selectors) |src, *dst| {
        dst.* = .{
            .name = try allocator.dupe(u8, src.name),
            .count = src.count,
            .clause = @intFromEnum(src.clause),
            .attribute = try allocator.dupe(u8, src.attribute),
            .filter = try allocator.dupe(u8, src.filter),
        };
    }

    const filters = try allocator.alloc(stable.Filter, parsed.filters.items.len);
    errdefer {
        for (filters) |f| stable.deinitFilter(allocator, f);
        allocator.free(filters);
    }
    for (parsed.filters.items, 0..) |src, i| {
        filters[i] = try stableFilterFromParsed(allocator, src);
    }

    const ec_rules = try allocator.alloc(stable.ECRule, parsed.ec_rules.items.len);
    errdefer allocator.free(ec_rules);
    for (parsed.ec_rules.items, ec_rules) |src, *dst| {
        dst.* = .{
            .data_part_num = src.data_part_num,
            .parity_part_num = src.parity_part_num,
            .selector = try allocator.dupe(u8, src.selector),
        };
    }

    const backup_factor: u64 = if (parsed.container_backup_factor == 0)
        1
    else
        parsed.container_backup_factor;

    return .{
        .replicas = replicas,
        .backup_factor = backup_factor,
        .selectors = selectors,
        .filters = filters,
        .ec_rules = ec_rules,
    };
}

fn stableFilterFromParsed(allocator: std.mem.Allocator, src: netmap.policy.Filter) !stable.Filter {
    const subs = try allocator.alloc(stable.Filter, src.filters.items.len);
    errdefer allocator.free(subs);
    for (src.filters.items, subs) |sub, *dst| {
        dst.* = try stableFilterFromParsed(allocator, sub);
    }
    return .{
        .name = try allocator.dupe(u8, src.name),
        .key = try allocator.dupe(u8, src.key),
        .op = @intFromEnum(src.op),
        .value = try allocator.dupe(u8, src.value),
        .filters = subs,
    };
}

pub fn parsePolicyString(allocator: std.mem.Allocator, policy: []const u8) !stable.PlacementPolicy {
    var parsed = try netmap.policy.decodeString(allocator, policy);
    defer netmap.policy.deinitPolicy(&parsed, allocator);
    return stableFromParsed(allocator, parsed);
}

pub fn deinitPlacementPolicy(allocator: std.mem.Allocator, policy: stable.PlacementPolicy) void {
    stable.deinitPlacementPolicy(allocator, policy);
}

test "policyNeedsAdvancedWire detects select and filter" {
    const s =
        \\REP 1
        \\SELECT 2 IN SAME Location FROM * AS X
    ;
    var parsed = try netmap.policy.decodeString(std.testing.allocator, s);
    defer netmap.policy.deinitPolicy(&parsed, std.testing.allocator);
    try std.testing.expect(policyNeedsAdvancedWire(parsed));
}

test "parsePolicyString maps rep and cbf" {
    const p = try parsePolicyString(std.testing.allocator, "REP 2 CBF 3");
    defer std.testing.allocator.free(@constCast(p.replicas));
    try std.testing.expectEqual(@as(u64, 2), p.replicas[0].count);
    try std.testing.expectEqual(@as(u64, 3), p.backup_factor);
}

test "parsePolicyString maps select filter and cbf" {
    const s =
        \\REP 1
        \\SELECT 2 IN SAME Location FROM * AS X
        \\FILTER Country EQ UA AS FromUA
        \\CBF 2
    ;
    const p = try parsePolicyString(std.testing.allocator, s);
    defer stable.deinitPlacementPolicy(std.testing.allocator, p);
    try std.testing.expectEqual(@as(u64, 1), p.replicas[0].count);
    try std.testing.expectEqual(@as(u64, 2), p.backup_factor);
    try std.testing.expectEqual(@as(usize, 1), p.selectors.len);
    try std.testing.expectEqual(@as(usize, 1), p.filters.len);
}
