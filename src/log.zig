const std = @import("std");

pub const Level = enum { err, warn, info, debug };

var log_path_owned: ?[]u8 = null;
var min_level: Level = .info;
var mirror_tty: bool = false;
var allocator_ref: ?std.mem.Allocator = null;
var io_ref: ?std.Io = null;
var mutex: std.Io.Mutex = .init;

pub fn init(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    allocator_ref = allocator;
    io_ref = io;
    if (log_path_owned) |old| allocator.free(old);
    log_path_owned = try allocator.dupe(u8, path);
}

pub fn deinit() void {
    if (allocator_ref) |a| {
        if (log_path_owned) |p| a.free(p);
    }
    log_path_owned = null;
    allocator_ref = null;
    io_ref = null;
}

pub fn setLevel(level: Level) void {
    min_level = level;
}

pub fn setMirrorTty(enabled: bool) void {
    mirror_tty = enabled;
}

pub fn log(
    comptime level: Level,
    comptime scope: []const u8,
    comptime format: []const u8,
    args: anytype,
) void {
    if (@backingInt(level) > @backingInt(min_level)) return;

    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, format, args) catch return;
    const scope_name = scope;
    const level_name = @tagName(level);

    var line_buf: [4300]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "[{s}] ({s}) {s}\n", .{ level_name, scope_name, msg }) catch return;

    const io = io_ref orelse return;
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);

    {
        if (log_path_owned) |path| {
            const cwd = std.Io.Dir.cwd();
            const file = cwd.createFile(io, path, .{ .truncate = false }) catch null;
            if (file) |f| {
                defer f.close(io);
                const offset = if (f.stat(io)) |stat| stat.size else |_| 0;
                _ = f.writePositionalAll(io, line, offset) catch {};
            }
        }
    }

    // The TUI owns the terminal. An error written here lands at the cursor and
    // tears the frame apart. `--log-tty` is the only way onto stderr.
    if (mirror_tty) {
        const stderr: std.Io.File = .stderr();
        _ = stderr.writeStreamingAll(io, line) catch {};
    }
}

pub fn err(comptime scope: []const u8, comptime format: []const u8, args: anytype) void {
    log(.err, scope, format, args);
}
pub fn warn(comptime scope: []const u8, comptime format: []const u8, args: anytype) void {
    log(.warn, scope, format, args);
}
pub fn info(comptime scope: []const u8, comptime format: []const u8, args: anytype) void {
    log(.info, scope, format, args);
}
pub fn debug(comptime scope: []const u8, comptime format: []const u8, args: anytype) void {
    log(.debug, scope, format, args);
}
