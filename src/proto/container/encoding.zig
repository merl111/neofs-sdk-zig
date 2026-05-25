pub const package_name = "container";
pub const wire = @import("../../internal/proto/encoding.zig");

test {
    _ = @import("encoding_test.zig");
}
