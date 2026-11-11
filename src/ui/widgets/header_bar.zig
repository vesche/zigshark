const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const theme_mod = @import("../theme.zig");
const text_util = @import("text_util.zig");

pub const HeaderBar = struct {
    pub const Menu = enum { analysis, view, help };

    theme: theme_mod.Theme,
    source: []const u8 = "",
    menu_start: u16 = 0,
    userdata: ?*anyopaque = null,
    onMenu: ?*const fn (?*anyopaque, Menu) void = null,

    pub fn widget(self: *HeaderBar) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = typeErasedEventHandler,
            .drawFn = typeErasedDrawFn,
        };
    }

    fn typeErasedEventHandler(
        ptr: *anyopaque,
        ctx: *vxfw.EventContext,
        event: vxfw.Event,
    ) anyerror!void {
        const self: *HeaderBar = @ptrCast(@alignCast(ptr));
        switch (event) {
            .mouse => |mouse| {
                if (mouse.row != 0 or mouse.col < 0) return;
                const col: u16 = @intCast(mouse.col);
                if (col < self.menu_start) return;
                try ctx.setMouseShape(.pointer);
                if (mouse.type == .press and mouse.button == .left) {
                    const relative = col - self.menu_start;
                    const menu: Menu = if (relative < 10)
                        .analysis
                    else if (relative < 16)
                        .view
                    else
                        .help;
                    if (self.onMenu) |callback| callback(self.userdata, menu);
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *HeaderBar = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    pub fn draw(self: *HeaderBar, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        var surface = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        if (size.height == 0) return surface;

        const style: vaxis.Style = .{
            .fg = self.theme.header_fg,
            .bg = self.theme.header_bg,
            .bold = true,
        };
        const brand: vaxis.Style = .{
            .fg = self.theme.accent,
            .bg = self.theme.header_bg,
            .bold = true,
        };
        var col: u16 = 0;
        while (col < size.width) : (col += 1) {
            surface.writeCell(col, 0, .{
                .char = .{ .grapheme = " ", .width = 1 },
                .style = style,
            });
        }

        const filename = std.fs.path.basename(self.source);
        var cursor = text_util.writeText(&surface, ctx, 0, 0, "zigshark", brand, size.width);
        cursor = text_util.writeText(&surface, ctx, cursor, 0, " 0.1.0", style, size.width);
        if (filename.len != 0) {
            cursor = text_util.writeText(&surface, ctx, cursor, 0, "  │  ", style, size.width);
            _ = text_util.writeText(&surface, ctx, cursor, 0, filename, style, size.width);
        }

        const menu = "[Analysis]  [Misc]";
        const menu_width: u16 = @intCast(@min(ctx.stringWidth(menu), size.width));
        if (size.width > menu_width + 2) {
            self.menu_start = size.width - menu_width;
            _ = text_util.writeText(&surface, ctx, self.menu_start, 0, menu, style, size.width);
        } else {
            self.menu_start = size.width;
        }
        return surface;
    }
};
