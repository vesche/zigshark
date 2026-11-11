const std = @import("std");

pub const TransferError = error{
    WormholeNotFound,
    WormholeFailed,
} || std.process.SpawnError || std.process.Child.WaitError;

pub fn wormholeAvailable(io: std.Io) bool {
    const result = std.process.run(std.heap.page_allocator, io, .{
        .argv = &.{ "wormhole", "--version" },
        .stdout_limit = .limited(512),
        .stderr_limit = .limited(512),
    }) catch return false;
    defer std.heap.page_allocator.free(result.stdout);
    defer std.heap.page_allocator.free(result.stderr);
    return result.term.success();
}

pub fn sendFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8) TransferError!void {
    if (!wormholeAvailable(io)) return error.WormholeNotFound;
    var child = try std.process.spawn(io, .{
        .argv = &.{ "wormhole", "send", path },
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    if (!term.success()) return error.WormholeFailed;
    _ = allocator;
}
