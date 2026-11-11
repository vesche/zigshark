const std = @import("std");
const process = @import("../../shark/process.zig");
const capinfo = @import("../../shark/capinfo.zig");

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    capinfos_exe: []const u8,
    path: []const u8,
) ![]u8 {
    var argv = try process.argvCapinfos(allocator, capinfos_exe, path);
    defer argv.deinit(allocator);

    var out = try process.runCapture(allocator, io, argv.slice());
    defer out.deinit(allocator);

    if (out.stdout.len == 0) {
        return try std.fmt.allocPrint(allocator, "capinfos failed for {s}\n{s}", .{ path, out.stderr });
    }

    var info = capinfo.parse(allocator, out.stdout) catch {
        return try allocator.dupe(u8, out.stdout);
    };
    defer info.deinit(allocator);
    // Parsed successfully; return the human-readable raw table.
    return try allocator.dupe(u8, out.stdout);
}
