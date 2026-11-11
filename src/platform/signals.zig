const std = @import("std");
const builtin = @import("builtin");

var quit_flag: std.atomic.Value(bool) = .init(false);

pub fn quitRequested() bool {
    return quit_flag.load(.acquire);
}

pub fn requestQuit() void {
    quit_flag.store(true, .release);
}

/// Install SIGINT/SIGTERM handlers so Ctrl-C and kill restore via normal TUI teardown
/// instead of Zig's default signal dump. No-op on platforms without posix signals.
pub fn install() void {
    if (builtin.os.tag == .windows) return;
    const posix = std.posix;
    const action = posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &action, null);
    posix.sigaction(posix.SIG.TERM, &action, null);
}

fn handleSignal(_: std.posix.SIG) callconv(.c) void {
    quit_flag.store(true, .release);
}
