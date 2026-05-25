pub const package_name = "audit";
pub const wire = @import("../../internal/proto/encoding.zig");

test {
    _ = @import("encoding_test.zig");
}
