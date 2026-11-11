const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const theme_mod = @import("../theme.zig");
const text_util = @import("text_util.zig");

pub const menu_text = "[Analysis] [Misc] [Help]";

pub fn menuAt(width: u16, col: u16) ?HeaderBar.Menu {
    const total: u16 = @intCast(menu_text.len);
    if (width <= total + 2 or col >= width) return null;
    const start = width - total;
    if (col < start) return null;
    const relative = col - start;
    if (relative < 11) return .analysis;
    if (relative < 18) return .misc;
    return .help;
}

pub const HeaderBar = struct {
    pub const Menu = enum { analysis, misc, help };

    theme: theme_mod.Theme,
    source: []const u8 = "",
    menu_start: u16 = 0,
    last_width: u16 = 0,
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
                const menu = menuAt(self.last_width, col) orelse return;
                try ctx.setMouseShape(.pointer);
                if (mouse.type == .press and mouse.button == .left) {
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

        self.last_width = size.width;
        const menu_width: u16 = @intCast(@min(menu_text.len, size.width));
        if (size.width > menu_width + 2) {
            self.menu_start = size.width - menu_width;
            _ = text_util.writeText(&surface, ctx, self.menu_start, 0, menu_text, style, size.width);
        } else {
            self.menu_start = size.width;
        }
        return surface;
    }
};

test "header menus sit on the right edge" {
    try std.testing.expect(menuAt(40, 10) == null);
    const start: u16 = 80 - @as(u16, @intCast(menu_text.len));
    try std.testing.expectEqual(HeaderBar.Menu.analysis, menuAt(80, start).?);
    try std.testing.expectEqual(HeaderBar.Menu.misc, menuAt(80, start + 11).?);
    try std.testing.expectEqual(HeaderBar.Menu.help, menuAt(80, start + 18).?);
}
