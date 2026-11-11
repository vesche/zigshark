const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;

const app_mod = @import("app.zig");
const config = @import("../config.zig");
const session_mod = @import("../model/session.zig");
const loader_mod = @import("../model/loader.zig");
const tools_mod = @import("../shark/tools.zig");
const cli = @import("../cli.zig");
const paths_mod = @import("../platform/paths.zig");

pub const RunOptions = struct {
    config: *config.Config,
    tools: *tools_mod.Tools,
    session: *session_mod.Session,
    loader: *loader_mod.CaptureLoader,
    paths: *paths_mod.Paths,
    cli: cli.Options,
};

pub fn runTui(init: std.process.Init, options: RunOptions) !void {
    const allocator = init.gpa;
    const io = init.io;

    // Prefer clean vxfw teardown over Zig's default SIGINT stack dump.
    const signals = @import("../platform/signals.zig");
    signals.install();

    var buffer: [4096]u8 = undefined;
    var fw: vxfw.App = try .init(io, allocator, init.environ_map, &buffer);
    defer fw.deinit();

    const model = try allocator.create(app_mod.AppModel);
    defer allocator.destroy(model);
    try model.init(allocator, io, options);
    defer model.deinit();

    try fw.run(model.widget(), .{});
}
