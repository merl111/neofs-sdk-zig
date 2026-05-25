//! Basic ACL bitmask operations (aligned with neofs-sdk-go/container/acl).

const std = @import("std");

pub const Op = enum(u32) {
    object_get = 1,
    object_head = 2,
    object_put = 3,
    object_delete = 4,
    object_search = 5,
    object_range = 6,
    object_hash = 7,
};

pub const Role = enum(u32) {
    owner = 1,
    container = 2,
    inner_ring = 3,
    others = 4,
};

pub const Basic = struct {
    value: u32,

    pub fn fromBits(mask: u32) Basic {
        return .{ .value = mask };
    }

    pub fn bits(self: Basic) u32 {
        return self.value;
    }

    pub fn extendable(self: Basic) bool {
        return !isBitSet(self.value, bit_pos_final);
    }

    pub fn disableExtension(self: *Basic) void {
        setBit(&self.value, bit_pos_final);
    }

    pub fn sticky(self: Basic) bool {
        return isBitSet(self.value, bit_pos_sticky);
    }

    pub fn makeSticky(self: *Basic) void {
        setBit(&self.value, bit_pos_sticky);
    }

    pub fn allowBearerRules(self: *Basic, op: Op) void {
        setOpBit(&self.value, op, op_bit_bearer);
    }

    pub fn allowedBearerRules(self: Basic, op: Op) bool {
        return isOpBitSet(self.value, op, op_bit_bearer);
    }

    pub fn allowOp(self: *Basic, op: Op, role: Role) void {
        const bit_pos: u8 = switch (role) {
            .owner => op_bit_owner,
            .container => op_bit_container,
            .others => op_bit_others,
            else => return,
        };
        setOpBit(&self.value, op, bit_pos);
    }

    pub fn isOpAllowed(self: Basic, op: Op, role: Role) bool {
        return switch (role) {
            .inner_ring => switch (op) {
                .object_get, .object_head, .object_hash, .object_search => true,
                else => false,
            },
            .owner => isOpBitSet(self.value, op, op_bit_owner),
            .container => if (isReplicationOp(op)) true else isOpBitSet(self.value, op, op_bit_container),
            .others => isOpBitSet(self.value, op, op_bit_others),
        };
    }
};

const op_amount: u32 = 7;
const bits_per_op: u32 = 4;
const bit_pos_final: u32 = op_amount * bits_per_op;
const bit_pos_sticky: u32 = bit_pos_final + 1;

const op_bit_bearer: u8 = 0;
const op_bit_others: u8 = 1;
const op_bit_container: u8 = 2;
const op_bit_owner: u8 = 3;

fn isReplicationOp(op: Op) bool {
    return switch (op) {
        .object_get, .object_head, .object_put, .object_search, .object_hash => true,
        else => false,
    };
}

fn isBitSet(bits: u32, pos: u32) bool {
    return (bits & (@as(u32, 1) << @intCast(pos))) != 0;
}

fn setBit(bits: *u32, pos: u32) void {
    bits.* |= @as(u32, 1) << @intCast(pos);
}

fn opIndex(op: Op) u32 {
    return switch (op) {
        .object_get => 0,
        .object_head => 1,
        .object_put => 2,
        .object_delete => 3,
        .object_search => 4,
        .object_range => 5,
        .object_hash => 6,
    };
}

fn opBitPos(op: Op, role_bit: u8) u32 {
    return opIndex(op) * bits_per_op + role_bit;
}

fn isOpBitSet(bits: u32, op: Op, role_bit: u8) bool {
    return isBitSet(bits, opBitPos(op, role_bit));
}

fn setOpBit(bits: *u32, op: Op, role_bit: u8) void {
    setBit(bits, opBitPos(op, role_bit));
}

pub const private_acl: u32 = 0x1C8C8CCC;
pub const private_extended_acl: u32 = 0x0C8C8CCC;
pub const public_ro_acl: u32 = 0x1FBF8CFF;
pub const public_ro_extended_acl: u32 = 0x0FBF8CFF;
pub const public_rw_acl: u32 = 0x1FBFBFFF;
pub const public_rw_extended_acl: u32 = 0x0FBFBFFF;
pub const public_append_acl: u32 = 0x1FBF9FFF;
pub const public_append_extended_acl: u32 = 0x0FBF9FFF;

test {
    _ = @import("basic_test.zig");
}
