const std = @import("std");

pub fn linkOpenSsl(compile: *std.Build.Step.Compile) void {
    compile.root_module.linkSystemLibrary("ssl", .{});
    compile.root_module.linkSystemLibrary("crypto", .{});
}
