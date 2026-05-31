const std = @import("std");
const build_compat = @import("build_compat.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const protobuf_dep = b.dependency("protobuf", .{
        .target = target,
        .optimize = optimize,
    });

    const sdk_mod = b.addModule("neofs_sdk", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    sdk_mod.addImport("protobuf", protobuf_dep.module("protobuf"));

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("protobuf", protobuf_dep.module("protobuf"));
    const tests = b.addTest(.{
        .root_module = test_mod,
    });
    tests.use_llvm = true;
    tests.root_module.link_libc = true;
    build_compat.linkOpenSsl(tests);
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    const unit_only = b.step("unit", "Alias for unit tests");
    unit_only.dependOn(test_step);

    const gen_step = b.step("gen-proto", "Generate Zig stubs from neofs-api");
    const gen_cmd = b.addSystemCommand(&[_][]const u8{"bash", "scripts/genapi.sh"});
    gen_step.dependOn(&gen_cmd.step);

    const vector_test_mod = b.createModule(.{
        .root_source_file = b.path("src/vector_tests_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    vector_test_mod.addImport("protobuf", protobuf_dep.module("protobuf"));
    const vector_tests = b.addTest(.{
        .root_module = vector_test_mod,
    });
    vector_tests.use_llvm = true;
    vector_tests.root_module.link_libc = true;
    build_compat.linkOpenSsl(vector_tests);
    const run_vector_tests = b.addRunArtifact(vector_tests);
    const vectors_step = b.step("vectors", "Run cross-language vector tests (HRW, tzhash, netmap JSON)");
    vectors_step.dependOn(&run_vector_tests.step);

    const integration_cmd = b.addSystemCommand(&[_][]const u8{"bash", "test/integration/run_aio.sh"});
    const integration_step = b.step("integration", "Run integration tests");
    integration_step.dependOn(&integration_cmd.step);

    if (b.option([]const u8, "example", "Run an example by name")) |example_name| {
        const examples = .{
            .{ "container_object_lifecycle", "examples/container_object_lifecycle.zig" },
            .{ "list_containers", "examples/list_containers.zig" },
            .{ "client_dial", "examples/client_dial.zig" },
            .{ "pool_usage", "examples/pool_usage.zig" },
            .{ "object_put_get", "examples/object_put_get.zig" },
            .{ "placement_policy", "examples/placement_policy.zig" },
            .{ "aio_lifecycle", "test/integration/lifecycle.zig" },
        };

        inline for (examples) |entry| {
            if (std.mem.eql(u8, example_name, entry.@"0")) {
                const exe = b.addExecutable(.{
                    .name = example_name,
                    .root_module = b.createModule(.{
                        .root_source_file = b.path(entry.@"1"),
                        .target = target,
                        .optimize = optimize,
                        .imports = &.{
                            .{ .name = "neofs_sdk", .module = sdk_mod },
                        },
                    }),
                });
                exe.root_module.link_libc = true;
                build_compat.linkOpenSsl(exe);
                const run_cmd = b.addRunArtifact(exe);
                b.step("run", "Run selected example").dependOn(&run_cmd.step);
                break;
            }
        }
    }
}
