const std = @import("std");
const builtin = @import("builtin");

pub const ClipboardBackend = enum {
    osc52,
    xsel,
    xclip,
    pbcopy,
    wl_copy,
    none,
};

pub fn detect(environ: *const std.process.Environ.Map, copy_command: []const u8) ClipboardBackend {
    if (copy_command.len != 0) return .none;
    const term = environ.get("TERM") orelse "";
    if (std.mem.indexOf(u8, term, "kitty") != null or std.mem.indexOf(u8, term, "alacritty") != null or
        std.mem.indexOf(u8, term, "foot") != null)
    {
        return .osc52;
    }
    if (environ.get("WAYLAND_DISPLAY") != null) return .wl_copy;
    if (builtin.os.tag == .macos) return .pbcopy;
    return .osc52;
}

pub fn copyExternal(
    allocator: std.mem.Allocator,
    io: std.Io,
    copy_command: []const u8,
    text: []const u8,
) !void {
    if (copy_command.len == 0) return;
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    var tokens = std.mem.tokenizeAny(u8, copy_command, " \t\r\n");
    while (tokens.next()) |token| try argv.append(allocator, token);
    if (argv.items.len == 0) return;
    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(io);
    if (child.stdin) |stdin| {
        try stdin.writeStreamingAll(io, text);
        stdin.close(io);
        child.stdin = null;
    }
    _ = try child.wait(io);
}
