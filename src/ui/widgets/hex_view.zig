const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const theme_mod = @import("../theme.zig");
const text_util = @import("text_util.zig");

pub const HexView = struct {
    raw: []const u8 = &.{},
    theme: theme_mod.Theme,
    scroll_top: usize = 0,
    highlight_pos: usize = 0,
    highlight_size: usize = 0,
    bytes_per_line: usize = 16,

    pub fn widget(self: *HexView) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = typeErasedEventHandler,
            .drawFn = typeErasedDrawFn,
        };
    }

    fn typeErasedEventHandler(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *HexView = @ptrCast(@alignCast(ptr));
        try self.handleEvent(ctx, event);
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *HexView = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    pub fn setHighlight(self: *HexView, pos: usize, size: usize) void {
        self.highlight_pos = pos;
        self.highlight_size = size;
    }

    pub fn formatSelection(self: *const HexView, allocator: std.mem.Allocator) ![]u8 {
        const start = if (self.highlight_size > 0)
            @min(self.highlight_pos, self.raw.len)
        else
            0;
        const end = if (self.highlight_size > 0)
            @min(start + self.highlight_size, self.raw.len)
        else
            self.raw.len;
        var writer: std.Io.Writer.Allocating = .init(allocator);
        defer writer.deinit();
        for (self.raw[start..end], 0..) |byte, i| {
            if (i != 0) try writer.writer.writeByte(' ');
            try writer.writer.print("{x:0>2}", .{byte});
        }
        return writer.toOwnedSlice();
    }

    pub fn handleEvent(self: *HexView, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        switch (event) {
            .mouse => |m| {
                if (m.button == .wheel_down) {
                    self.scroll_top +%= 1;
                    return ctx.consumeAndRedraw();
                }
                if (m.button == .wheel_up and self.scroll_top > 0) {
                    self.scroll_top -= 1;
                    return ctx.consumeAndRedraw();
                }
            },
            .key_press => |key| {
                if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
                    self.scroll_top +%= 1;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
                    if (self.scroll_top > 0) self.scroll_top -= 1;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.page_down, .{})) self.scroll_top +%= 5;
                if (key.matches(vaxis.Key.page_up, .{})) {
                    if (self.scroll_top > 5) self.scroll_top -= 5 else self.scroll_top = 0;
                }
                if (key.matches(vaxis.Key.page_down, .{}) or key.matches(vaxis.Key.page_up, .{})) {
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }
    }

    fn byteHighlighted(self: *const HexView, offset: usize) bool {
        if (self.highlight_size == 0) return false;
        return offset >= self.highlight_pos and offset < self.highlight_pos + self.highlight_size;
    }

    pub fn draw(self: *HexView, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        var surf = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        const normal: vaxis.Style = .{ .fg = self.theme.fg, .bg = self.theme.bg };
        // termshark highlights selected layer bytes with a white/light background.
        const hi: vaxis.Style = .{
            .fg = theme_mod.rgb(0, 0, 0),
            .bg = theme_mod.rgb(255, 255, 255),
        };
        var fill_row: u16 = 0;
        while (fill_row < size.height) : (fill_row += 1) {
            var fill_col: u16 = 0;
            while (fill_col < size.width) : (fill_col += 1) {
                surf.writeCell(fill_col, fill_row, .{
                    .char = .{ .grapheme = " ", .width = 1 },
                    .style = normal,
                });
            }
        }
        self.bytes_per_line = if (size.width >= 78) 16 else if (size.width >= 42) 8 else 4;
        const total_lines = if (self.bytes_per_line > 0)
            (self.raw.len + self.bytes_per_line - 1) / self.bytes_per_line
        else
            0;
        if (total_lines == 0) {
            self.scroll_top = 0;
        } else if (self.scroll_top >= total_lines) {
            self.scroll_top = total_lines - 1;
        }

        var screen_row: u16 = 0;
        var line = self.scroll_top;
        while (screen_row < size.height and line < total_lines) : ({
            screen_row += 1;
            line += 1;
        }) {
            const base = line * self.bytes_per_line;
            const prefix = try std.fmt.allocPrint(ctx.arena, "{x:0>4}  ", .{base});
            var col: u16 = text_util.writeText(&surf, ctx, 0, screen_row, prefix, normal, size.width);
            var i: usize = 0;
            while (i < self.bytes_per_line) : (i += 1) {
                const off = base + i;
                if (off < self.raw.len) {
                    const style = if (self.byteHighlighted(off)) hi else normal;
                    var pair: [2]u8 = undefined;
                    _ = std.fmt.bufPrint(&pair, "{x:0>2}", .{self.raw[off]}) catch continue;
                    for (pair) |ch| {
                        if (col >= size.width) break;
                        text_util.writeAsciiChar(&surf, col, screen_row, ch, style);
                        col += 1;
                    }
                    if (col < size.width) {
                        surf.writeCell(col, screen_row, .{ .char = .{ .grapheme = " ", .width = 1 }, .style = normal });
                        col += 1;
                    }
                }
            }
            if (col + 2 < size.width) {
                col += 2;
                i = 0;
                while (i < self.bytes_per_line) : (i += 1) {
                    const off = base + i;
                    if (off >= self.raw.len or col >= size.width) break;
                    const b = self.raw[off];
                    const ch: u8 = if (std.ascii.isPrint(b)) b else '.';
                    const style = if (self.byteHighlighted(off)) hi else normal;
                    text_util.writeAsciiChar(&surf, col, screen_row, ch, style);
                    col += 1;
                }
            }
        }
        return surf;
    }
};
