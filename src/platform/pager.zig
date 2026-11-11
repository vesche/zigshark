const std = @import("std");

pub fn pagerArgv(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map, config_pager: []const u8) ![]const []const u8 {
    const pager = if (config_pager.len != 0)
        config_pager
    else if (environ.get("PAGER")) |p|
        p
    else
        "less";

    const argv = try allocator.alloc([]const u8, 1);
    argv[0] = try allocator.dupe(u8, pager);
    return argv;
}

pub fn spawnPager(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8, input: []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    defer {
        child.kill(io) catch {};
    }
    if (child.stdin) |stdin| {
        try stdin.writeAll(io, input);
        stdin.close(io);
    }
    _ = try child.wait(io);
    _ = allocator;
}
