const std = @import("std");
const builtin = @import("builtin");
const vaxis = @import("vaxis");

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

/// Leave the alternate screen, stop the process, and restore the TUI on continue.
/// Ctrl-Z does not arrive as SIGTSTP because the terminal is in raw mode.
pub fn suspendJob() void {
    if (builtin.os.tag == .windows) return;
    const tty = &(vaxis.tty.global_tty orelse return);
    const fd = tty.fd.handle;
    writeRaw(fd, vaxis.ctlseqs.rmcup);
    restoreTermios(fd, tty.termios);
    const previous = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    var saved: std.posix.Sigaction = undefined;
    std.posix.sigaction(std.posix.SIG.TSTP, &previous, &saved);
    std.posix.raise(std.posix.SIG.TSTP) catch {};
    _ = vaxis.tty.Tty.makeRaw(fd) catch {};
    writeRaw(fd, vaxis.ctlseqs.smcup);
    std.posix.sigaction(std.posix.SIG.TSTP, &saved, null);
}

fn writeRaw(fd: std.posix.fd_t, bytes: []const u8) void {
    if (bytes.len == 0) return;
    _ = std.posix.system.write(fd, bytes.ptr, bytes.len);
}

fn restoreTermios(fd: std.posix.fd_t, termios: std.posix.termios) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.tcsetattr(fd, .FLUSH, &termios);
        return;
    }
    std.posix.tcsetattr(fd, .FLUSH, termios) catch {};
}
