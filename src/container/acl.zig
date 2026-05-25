//! Predefined NeoFS container BasicACL values (aligned with neofs-sdk-go/container/acl).

const std = @import("std");

pub const Preset = struct {
    /// CLI / config id (e.g. `public-read-write`).
    id: []const u8,
    /// Short label for menus.
    label: []const u8,
    /// One-line description for interactive prompts.
    description: []const u8,
    bits: u32,
};

/// Frequently used BasicACL bitmasks from the NeoFS specification.
pub const private_acl: u32 = 0x1C8C8CCC;
pub const private_extended_acl: u32 = 0x0C8C8CCC;
pub const public_ro_acl: u32 = 0x1FBF8CFF;
pub const public_ro_extended_acl: u32 = 0x0FBF8CFF;
pub const public_rw_acl: u32 = 0x1FBFBFFF;
pub const public_rw_extended_acl: u32 = 0x0FBFBFFF;
pub const public_append_acl: u32 = 0x1FBF9FFF;
pub const public_append_extended_acl: u32 = 0x0FBF9FFF;

pub const presets = [_]Preset{
    .{
        .id = "private",
        .label = "Private",
        .description = "Owner-only access; container not extendable with EACL",
        .bits = private_acl,
    },
    .{
        .id = "eacl-private",
        .label = "Private + EACL",
        .description = "Owner-only; allows extended ACL rules",
        .bits = private_extended_acl,
    },
    .{
        .id = "public-read",
        .label = "Public read",
        .description = "Others can read objects; owner has full control",
        .bits = public_ro_acl,
    },
    .{
        .id = "eacl-public-read",
        .label = "Public read + EACL",
        .description = "Public read with extended ACL support",
        .bits = public_ro_extended_acl,
    },
    .{
        .id = "public-read-write",
        .label = "Public read-write",
        .description = "Others can read and write objects (default for demos)",
        .bits = public_rw_acl,
    },
    .{
        .id = "eacl-public-read-write",
        .label = "Public read-write + EACL",
        .description = "Public read-write with extended ACL support",
        .bits = public_rw_extended_acl,
    },
    .{
        .id = "public-append",
        .label = "Public append",
        .description = "Others can read and append; owner controls delete",
        .bits = public_append_acl,
    },
    .{
        .id = "eacl-public-append",
        .label = "Public append + EACL",
        .description = "Public append with extended ACL support",
        .bits = public_append_extended_acl,
    },
};

pub fn findById(id: []const u8) ?Preset {
    for (presets) |p| {
        if (std.mem.eql(u8, p.id, id)) return p;
    }
    return null;
}

pub fn defaultPreset() Preset {
    return presets[4]; // public-read-write
}
