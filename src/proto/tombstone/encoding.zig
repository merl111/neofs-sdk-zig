pub const package_name = "tombstone";
pub const wire = @import("../../internal/proto/encoding.zig");

test {
    _ = @import("encoding_test.zig");
}
