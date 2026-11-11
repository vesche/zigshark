const std = @import("std");
const builtin = @import("builtin");

pub fn openUrl(allocator: std.mem.Allocator, io: std.Io, browse_command: []const u8, url: []const u8) !void {
    if (browse_command.len != 0) {
        _ = try std.process.spawn(io, .{
            .argv = &.{ browse_command, url },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        return;
    }
    const argv = switch (builtin.os.tag) {
        .macos => &[_][]const u8{ "open", url },
        .windows => &[_][]const u8{ "cmd", "/c", "start", "", url },
        else => &[_][]const u8{ "xdg-open", url },
    };
    _ = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    _ = allocator;
}
