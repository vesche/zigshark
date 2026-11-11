const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const theme_mod = @import("../theme.zig");
const session_mod = @import("../../model/session.zig");
const text_util = @import("text_util.zig");

pub const StatusBar = struct {
    theme: theme_mod.Theme,
    packet_count: usize = 0,
    selected_frame: ?u32 = null,
    loading: session_mod.LoadingState = .idle,
    filter: []const u8 = "",
    source: []const u8 = "",
    mode: []const u8 = "",

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
        if (size.height > 0) {
            var col: u16 = 0;
            while (col < size.width) : (col += 1) {
                surf.writeCell(col, 0, .{
                    .char = .{ .grapheme = " ", .width = 1 },
                    .style = style,
                });
            }
        }
        const frame_str = if (self.selected_frame) |f|
            try std.fmt.allocPrint(ctx.arena, "{d}", .{f})
        else
            "-";
        const load_str: []const u8 = switch (self.loading) {
            .idle => "",
            .loading_list => " loading list",
            .loading_detail => " loading detail",
            .capturing => " capturing",
            .error_state => " error",
        };
        const text = try std.fmt.allocPrint(ctx.arena, "{s} Packets: {d}  Frame: {s}{s}  Filter: {s}  │  {s}  │  Tab panes  ? help  : commands ", .{
            self.mode,
            self.packet_count,
            frame_str,
            load_str,
            if (self.filter.len != 0) self.filter else "(none)",
            self.source,
        });
        _ = text_util.writeText(&surf, ctx, 0, 0, text, style, size.width);
        return surf;
    }
};
