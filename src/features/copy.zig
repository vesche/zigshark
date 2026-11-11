const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const clipboard_mod = @import("../platform/clipboard.zig");

pub fn copyText(
    allocator: std.mem.Allocator,
    io: std.Io,
    ctx: *vxfw.EventContext,
    copy_command: []const u8,
    text: []const u8,
) !void {
    if (copy_command.len != 0) {
        try clipboard_mod.copyExternal(allocator, io, copy_command, text);
        return;
    }
    try ctx.copyToClipboard(text);
}
