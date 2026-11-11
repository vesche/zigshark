const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const theme_mod = @import("../theme.zig");
const text_util = @import("text_util.zig");

pub const Overlay = struct {
    title: []const u8,
    body: []const u8,
    theme: theme_mod.Theme,
    visible: bool = false,
    scroll_top: usize = 0,
    viewport_rows: usize = 1,

    pub fn widget(self: *Overlay) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = typeErasedEventHandler,
            .drawFn = typeErasedDrawFn,
        };
    }

    fn typeErasedEventHandler(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *Overlay = @ptrCast(@alignCast(ptr));
        if (!self.visible) return;
        switch (event) {
            .mouse => |mouse| {
                if (mouse.button == .wheel_down) {
                    self.scroll_top += 3;
                    return ctx.consumeAndRedraw();
                }
                if (mouse.button == .wheel_up) {
                    self.scroll_top -|= 3;
                    return ctx.consumeAndRedraw();
                }
            },
            .key_press => |key| {
                if (key.matches(vaxis.Key.escape, .{})) {
                    self.visible = false;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
                    self.scroll_top += 1;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
                    self.scroll_top -|= 1;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.page_down, .{})) {
                    self.scroll_top += self.viewport_rows;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.page_up, .{})) {
                    self.scroll_top -|= self.viewport_rows;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.home, .{})) {
                    self.scroll_top = 0;
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *Overlay = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    pub fn draw(self: *Overlay, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        if (!self.visible) {
            return .{
                .size = .{},
                .widget = self.widget(),
                .buffer = &.{},
                .children = &.{},
            };
        }
        if (size.width < 8 or size.height < 6) {
            return try vxfw.Surface.init(ctx.arena, self.widget(), size);
        }
        const w: u16 = @min(size.width - 4, 110);
        const h: u16 = @min(size.height - 4, 28);
        const row0: u16 = (size.height - h) / 2;
        const col0: u16 = (size.width - w) / 2;
        var surf = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        const border: vaxis.Style = .{ .fg = self.theme.pane_border, .bg = self.theme.bg };
        const title_style: vaxis.Style = .{ .fg = self.theme.header_fg, .bg = self.theme.header_bg, .bold = true };
        const text_style: vaxis.Style = .{ .fg = self.theme.fg, .bg = self.theme.bg };
        var r: u16 = 0;
        while (r < h) : (r += 1) {
            var c: u16 = 0;
            while (c < w) : (c += 1) {
                const abs_row = row0 + r;
                const abs_col = col0 + c;
                if (abs_row >= size.height or abs_col >= size.width) continue;
                const ch: u8 = if (r == 0 or r + 1 == h or c == 0 or c + 1 == w) '+' else ' ';
                text_util.writeAsciiChar(&surf, abs_col, abs_row, ch, border);
            }
        }
        _ = text_util.writeText(&surf, ctx, col0 + 2, row0, self.title, title_style, col0 + w - 1);
        self.viewport_rows = h -| 4;
        var body_row: u16 = row0 + 2;
        const body_width: usize = @max(@as(usize, 1), w -| 4);
        var visual_line: usize = 0;
        var lines = std.mem.splitScalar(u8, self.body, '\n');
        while (lines.next()) |line| {
            var offset: usize = 0;
            var emitted = false;
            while (offset < line.len or !emitted) {
                var end = @min(offset + body_width, line.len);
                while (end > offset and end < line.len and
                    (line[end] & 0xc0) == 0x80)
                {
                    end -= 1;
                }
                if (end == offset and offset < line.len) end = @min(offset + body_width, line.len);
                if (visual_line >= self.scroll_top and body_row < row0 + h - 2) {
                    _ = text_util.writeText(
                        &surf,
                        ctx,
                        col0 + 2,
                        body_row,
                        line[offset..end],
                        text_style,
                        col0 + w - 1,
                    );
                    body_row += 1;
                }
                visual_line += 1;
                emitted = true;
                offset = end;
            }
        }
        const max_scroll = visual_line -| self.viewport_rows;
        if (self.scroll_top > max_scroll) self.scroll_top = max_scroll;
        _ = text_util.writeText(
            &surf,
            ctx,
            col0 + 2,
            row0 + h - 1,
            "j/k scroll  PgUp/PgDn  Esc close",
            border,
            col0 + w - 1,
        );
        return surf;
    }
};
