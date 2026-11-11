const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const vaxis = b.dependency("vaxis", .{
        .target = target,
        .optimize = optimize,
    });

    const zigshark_mod = b.addModule("zigshark", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "vaxis", .module = vaxis.module("vaxis") },
        },
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zigshark", .module = zigshark_mod },
            .{ .name = "vaxis", .module = vaxis.module("vaxis") },
        },
    });

    const exe = b.addExecutable(.{
        .name = "zigshark",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run zigshark");
    run_step.dependOn(&run_cmd.step);

    const mod_tests = b.addTest(.{ .root_module = zigshark_mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{ .root_module = exe_mod });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const parsers_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/parsers_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_parsers_tests = b.addRunArtifact(parsers_tests);

    const suite_roots = [_][]const u8{
        "tests/cli_suite.zig",
        "tests/config_suite.zig",
        "tests/parse_suite.zig",
        "tests/model_suite.zig",
        "tests/ui_suite.zig",
    };
    var suite_steps: [suite_roots.len]*std.Build.Step = undefined;
    for (suite_roots, 0..) |path, index| {
        const suite_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "zigshark", .module = zigshark_mod },
                },
            }),
        });
        const run_suite_tests = b.addRunArtifact(suite_tests);
        suite_steps[index] = &run_suite_tests.step;
    }

    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration_tools.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zigshark", .module = zigshark_mod },
            },
        }),
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_parsers_tests.step);
    test_step.dependOn(&run_integration_tests.step);
    for (suite_steps) |step| test_step.dependOn(step);
}
