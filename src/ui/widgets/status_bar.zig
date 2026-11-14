const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const theme_mod = @import("../theme.zig");
const session_mod = @import("../../model/session.zig");
const text_util = @import("text_util.zig");

pub const StatusBar = struct {
    theme: theme_mod.Theme,
    packet_count: usize = 0,
    /// Unfiltered capture size, when a full load has been seen.
    packet_total: ?usize = null,
    selected_index: ?usize = null,
    selected_frame: ?u32 = null,
    loading: session_mod.LoadingState = .idle,
    filter: []const u8 = "",
    source: []const u8 = "",
    mode: []const u8 = "",
    pane: []const u8 = "list",
    hint: []const u8 = "",
    filter_error: []const u8 = "",
    expansion: []const u8 = "",
    tailing: bool = false,
    live: bool = false,
    expert_count: usize = 0,
    tls_keys: bool = false,
    names: bool = false,
    time_zero: ?u32 = null,

    pub fn format(self: *const StatusBar, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var writer: std.Io.Writer.Allocating = .init(allocator);
        errdefer writer.deinit();
        const out = &writer.writer;
        if (self.mode.len != 0) {
            try writeAll(out, std.mem.trim(u8, self.mode, " "));
            try writeAll(out, "  ");
        }
        if (self.selected_index) |index| {
            if (self.packet_total) |total| {
                if (total != self.packet_count) {
                    try print(out, "frame {d}/{d} of {d}", .{ index + 1, self.packet_count, total });
                } else {
                    try print(out, "frame {d}/{d}", .{ index + 1, self.packet_count });
                }
            } else {
                try print(out, "frame {d}/{d}", .{ index + 1, self.packet_count });
            }
        } else if (self.packet_total) |total| {
            if (total != self.packet_count) {
                try print(out, "frame -/{d} of {d}", .{ self.packet_count, total });
            } else {
                try print(out, "frame -/{d}", .{self.packet_count});
            }
        } else {
            try print(out, "frame -/{d}", .{self.packet_count});
        }
        if (self.filter.len != 0) try print(out, "  {s}", .{self.filter});
        const state = self.stateLabel();
        if (state.len != 0) try print(out, "  {s}", .{state});
        if (self.expert_count != 0) try print(out, "  expert {d}", .{self.expert_count});
        if (self.time_zero) |frame| try print(out, "  t0 {d}", .{frame});
        if (self.tls_keys) try writeAll(out, "  tls-keys");
        if (self.names) try writeAll(out, "  names");
        if (self.hint.len != 0) try print(out, "  {s}", .{self.hint});
        if (self.filter_error.len != 0) try print(out, "  {s}", .{self.filter_error});
        if (self.expansion.len != 0) try print(out, "  → {s}", .{self.expansion});
        return writer.toOwnedSlice();
    }

    fn stateLabel(self: *const StatusBar) []const u8 {
        if (self.live or self.loading == .capturing) return "capture";
        if (self.tailing) return "tail";
        return switch (self.loading) {
            .loading_list, .loading_detail => "loading",
            .error_state => "error",
            .idle, .capturing => "",
        };
    }

    pub fn widget(self: *StatusBar) vxfw.Widget {
        return .{
            .userdata = self,
            .drawFn = typeErasedDrawFn,
        };
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *StatusBar = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    pub fn draw(self: *StatusBar, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        var surf = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        const style: vaxis.Style = .{ .fg = self.theme.status_fg, .bg = self.theme.status_bg };
        text_util.fillBackground(&surf, style);
        const text = try self.format(ctx.arena);
        _ = text_util.writeText(&surf, ctx, 0, 0, text, style, size.width);
        return surf;
    }
};

fn writeAll(writer: *std.Io.Writer, bytes: []const u8) std.mem.Allocator.Error!void {
    writer.writeAll(bytes) catch return error.OutOfMemory;
}

fn print(writer: *std.Io.Writer, comptime fmt: []const u8, args: anytype) std.mem.Allocator.Error!void {
    writer.print(fmt, args) catch return error.OutOfMemory;
}

test "status line is frame position, filter, state, and hint" {
    const allocator = std.testing.allocator;
    const bar = StatusBar{
        .theme = theme_mod.dark(),
        .packet_count = 18,
        .selected_index = 2,
        .filter = "tcp.port == 443",
        .tailing = true,
        .hint = "= conv",
    };
    const text = try bar.format(allocator);
    defer allocator.free(text);
    try std.testing.expectEqualStrings("frame 3/18  tcp.port == 443  tail  = conv", text);

    const idle = StatusBar{ .theme = theme_mod.dark(), .packet_count = 0 };
    const empty = try idle.format(allocator);
    defer allocator.free(empty);
    try std.testing.expectEqualStrings("frame -/0", empty);
}
