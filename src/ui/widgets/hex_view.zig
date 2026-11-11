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
    cursor: usize = 0,
    bytes_per_line: usize = 16,
    viewport_rows: usize = 1,
    last_width: u16 = 0,
    focused: bool = false,
    userdata: ?*anyopaque = null,
    onCursor: ?*const fn (?*anyopaque, usize) void = null,
    onFocus: ?*const fn (?*anyopaque) void = null,

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

    /// Move the byte cursor. `notify` reports the new offset so the protocol tree can jump.
    pub fn setCursor(self: *HexView, offset: usize, notify: bool) void {
        if (self.raw.len == 0) {
            self.cursor = 0;
            return;
        }
        self.cursor = @min(offset, self.raw.len - 1);
        self.ensureCursorVisible();
        if (notify) if (self.onCursor) |cb| cb(self.userdata, self.cursor);
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
        const bpl = @max(self.bytes_per_line, 1);
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
                if (m.type == .press and m.button == .left and m.row >= 0 and m.col >= 0) {
                    if (self.onFocus) |cb| cb(self.userdata);
                    try ctx.requestFocus(self.widget());
                    if (self.offsetAt(@intCast(m.col), @intCast(m.row))) |off| {
                        self.setCursor(off, true);
                    }
                    return ctx.consumeAndRedraw();
                }
            },
            .key_press => |key| {
                if (self.raw.len == 0) return;
                if (key.matches('l', .{}) or key.matches(vaxis.Key.right, .{})) {
                    self.setCursor(self.cursor + 1, true);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('h', .{}) or key.matches(vaxis.Key.left, .{})) {
                    if (self.cursor > 0) self.setCursor(self.cursor - 1, true);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
                    self.setCursor(self.cursor + bpl, true);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
                    self.setCursor(self.cursor -| bpl, true);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.page_down, .{})) {
                    self.setCursor(self.cursor + bpl * @max(self.viewport_rows, 1), true);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.page_up, .{})) {
                    self.setCursor(self.cursor -| (bpl * @max(self.viewport_rows, 1)), true);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.home, .{})) {
                    self.setCursor(0, true);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.end, .{})) {
                    self.setCursor(self.raw.len - 1, true);
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }
    }

    fn ensureCursorVisible(self: *HexView) void {
        const bpl = @max(self.bytes_per_line, 1);
        const line = self.cursor / bpl;
        const view = @max(self.viewport_rows, 1);
        if (line < self.scroll_top) self.scroll_top = line;
        if (line >= self.scroll_top + view) self.scroll_top = line + 1 - view;
    }

    pub fn offsetAt(self: *const HexView, col: u16, row: u16) ?usize {
        const lay = layoutFor(if (self.last_width == 0) 80 else self.last_width);
        const line = self.scroll_top + row;
        if (col >= lay.hex_col and col + 2 < lay.ascii_col) {
            const rel = col - lay.hex_col;
            const byte = rel / 3;
            if (byte >= lay.bytes_per_line) return null;
            const off = line * lay.bytes_per_line + byte;
            if (off >= self.raw.len) return null;
            return off;
        }
        if (col >= lay.ascii_col) {
            const byte: usize = col - lay.ascii_col;
            if (byte >= lay.bytes_per_line) return null;
            const off = line * lay.bytes_per_line + byte;
            if (off >= self.raw.len) return null;
            return off;
        }
        return null;
    }

    fn byteHighlighted(self: *const HexView, offset: usize) bool {
        if (self.highlight_size == 0) return false;
        return offset >= self.highlight_pos and offset < self.highlight_pos + self.highlight_size;
    }

    pub fn draw(self: *HexView, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        var surf = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        const normal: vaxis.Style = .{ .fg = self.theme.fg, .bg = self.theme.bg };
        const field: vaxis.Style = .{
            .fg = theme_mod.rgb(0, 0, 0),
            .bg = theme_mod.rgb(180, 210, 255),
        };
        const cursor_style: vaxis.Style = if (self.focused)
            .{ .fg = theme_mod.rgb(0, 0, 0), .bg = theme_mod.rgb(255, 255, 255) }
        else
            .{ .fg = self.theme.selected_fg, .bg = self.theme.selected_bg };
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
        self.last_width = size.width;
        self.viewport_rows = size.height;
        const lay = layoutFor(size.width);
        self.bytes_per_line = lay.bytes_per_line;
        self.ensureCursorVisible();
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
                    const style = self.byteStyle(off, normal, field, cursor_style);
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
                } else if (col + 3 <= size.width) {
                    col += 3;
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
                    const style = self.byteStyle(off, normal, field, cursor_style);
                    text_util.writeAsciiChar(&surf, col, screen_row, ch, style);
                    col += 1;
                }
            }
        }
        return surf;
    }

    fn byteStyle(self: *const HexView, offset: usize, normal: vaxis.Style, field: vaxis.Style, cursor_style: vaxis.Style) vaxis.Style {
        if (offset == self.cursor and self.raw.len > 0) return cursor_style;
        if (self.byteHighlighted(offset) and !self.highlightCoversAll()) return field;
        return normal;
    }

    fn highlightCoversAll(self: *const HexView) bool {
        return self.raw.len > 0 and self.highlight_pos == 0 and self.highlight_size >= self.raw.len;
    }
};

const HexLayout = struct {
    bytes_per_line: usize,
    hex_col: u16,
    ascii_col: u16,
};

fn layoutFor(width: u16) HexLayout {
    const bytes_per_line: usize = if (width >= 78) 16 else if (width >= 42) 8 else 4;
    const hex_col: u16 = 6;
    const ascii_col: u16 = hex_col + @as(u16, @intCast(bytes_per_line * 3)) + 2;
    return .{
        .bytes_per_line = bytes_per_line,
        .hex_col = hex_col,
        .ascii_col = ascii_col,
    };
}

test "hex click maps to the byte under the cursor" {
    var view = HexView{ .theme = theme_mod.dark(), .raw = "0123456789abcdefXXXX", .last_width = 80 };
    const lay = layoutFor(80);
    try std.testing.expectEqual(@as(usize, 16), lay.bytes_per_line);
    try std.testing.expectEqual(@as(?usize, 0), view.offsetAt(lay.hex_col, 0));
    try std.testing.expectEqual(@as(?usize, 1), view.offsetAt(lay.hex_col + 3, 0));
    try std.testing.expectEqual(@as(?usize, 12), view.offsetAt(lay.ascii_col + 12, 0));
}
