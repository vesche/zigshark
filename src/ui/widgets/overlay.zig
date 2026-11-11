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
    /// When set, j/k moves a row cursor and Enter is handled by the app.
    pick: bool = false,
    selected: usize = 0,
    line_count: usize = 0,
    frame_row: u16 = 0,
    frame_col: u16 = 0,
    frame_w: u16 = 0,
    frame_h: u16 = 0,
    body_row: u16 = 0,
    visual_sources: [96]usize = @splat(0),
    visual_count: usize = 0,
    userdata: ?*anyopaque = null,
    on_activate: ?*const fn (?*anyopaque) void = null,
    on_dismiss: ?*const fn (?*anyopaque) void = null,

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
                if (mouse.type == .motion or mouse.type == .drag) {
                    if (self.pick) if (self.hitRow(mouse.row, mouse.col)) |index| {
                        self.selected = index;
                        return ctx.consumeAndRedraw();
                    };
                    return;
                }
                if (mouse.type == .press and mouse.button == .left) {
                    if (self.hitRow(mouse.row, mouse.col)) |index| {
                        self.selected = index;
                        if (self.pick) if (self.on_activate) |activate| activate(self.userdata);
                        return ctx.consumeAndRedraw();
                    }
                    return ctx.consumeAndRedraw();
                }
            },
            .key_press => |key| {
                if (key.matches(vaxis.Key.escape, .{})) {
                    self.visible = false;
                    self.pick = false;
                    return ctx.consumeAndRedraw();
                }
                if (self.pick and (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{}))) {
                    if (self.line_count > 0 and self.selected + 1 < self.line_count) self.selected += 1;
                    self.revealSelected();
                    return ctx.consumeAndRedraw();
                }
                if (self.pick and (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{}))) {
                    self.selected -|= 1;
                    self.revealSelected();
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
        const screen = ctx.max.size();
        if (!self.visible) {
            return .{
                .size = .{},
                .widget = self.widget(),
                .buffer = &.{},
                .children = &.{},
            };
        }
        const max_w: u16 = @min(screen.width -| 4, 68);
        const max_h: u16 = @min(screen.height -| 4, 18);
        if (max_w < 16 or max_h < 5) {
            self.frame_w = 0;
            self.frame_h = 0;
            return .{
                .size = .{},
                .widget = self.widget(),
                .buffer = &.{},
                .children = &.{},
            };
        }
        var line_total: usize = 0;
        var widest: usize = self.title.len;
        var measure = std.mem.splitScalar(u8, self.body, '\n');
        while (measure.next()) |line| {
            line_total += 1;
            if (line.len > widest) widest = line.len;
        }
        if (line_total == 0) line_total = 1;
        const w: u16 = @intCast(@min(@max(widest + 4, 36), max_w));
        const h: u16 = @intCast(@min(line_total + 4, max_h));
        const row0: u16 = 0;
        const col0: u16 = 0;
        var surf = try vxfw.Surface.init(ctx.arena, self.widget(), .{ .width = w, .height = h });
        const panel_bg = self.theme.header_bg;
        const border: vaxis.Style = .{ .fg = self.theme.accent, .bg = panel_bg };
        const title_style: vaxis.Style = .{ .fg = self.theme.header_fg, .bg = self.theme.header_bg, .bold = true };
        const text_style: vaxis.Style = .{ .fg = self.theme.fg, .bg = panel_bg };
        const pick_style: vaxis.Style = .{ .fg = self.theme.selected_fg, .bg = self.theme.selected_bg };
        var r: u16 = 0;
        while (r < h) : (r += 1) {
            var c: u16 = 0;
            while (c < w) : (c += 1) {
                const glyph: []const u8 = if (r == 0 and c == 0)
                    "┌"
                else if (r == 0 and c + 1 == w)
                    "┐"
                else if (r + 1 == h and c == 0)
                    "└"
                else if (r + 1 == h and c + 1 == w)
                    "┘"
                else if (r == 0 or r + 1 == h)
                    "─"
                else if (c == 0 or c + 1 == w)
                    "│"
                else
                    " ";
                surf.writeCell(c, r, .{
                    .char = .{ .grapheme = glyph, .width = 1 },
                    .style = border,
                });
            }
        }
        _ = text_util.writeText(&surf, ctx, col0 + 2, row0, self.title, title_style, col0 + w - 1);
        self.viewport_rows = h -| 4;
        self.visual_count = 0;
        var body_row: u16 = row0 + 2;
        const body_width: usize = @max(@as(usize, 1), w -| 4);
        var visual_line: usize = 0;
        var source_index: usize = 0;
        var lines = std.mem.splitScalar(u8, self.body, '\n');
        while (lines.next()) |line| {
            const line_style = if (self.pick and source_index == self.selected) pick_style else text_style;
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
                self.noteVisual(source_index);
                if (visual_line >= self.scroll_top and body_row < row0 + h - 2) {
                    _ = text_util.writeText(
                        &surf,
                        ctx,
                        col0 + 2,
                        body_row,
                        line[offset..end],
                        line_style,
                        col0 + w - 1,
                    );
                    body_row += 1;
                }
                visual_line += 1;
                emitted = true;
                offset = end;
            }
            source_index += 1;
        }
        self.line_count = source_index;
        if (self.line_count > 0 and self.selected >= self.line_count) self.selected = self.line_count - 1;
        const max_scroll = visual_line -| self.viewport_rows;
        if (self.scroll_top > max_scroll) self.scroll_top = max_scroll;
        self.frame_row = row0;
        self.frame_col = col0;
        self.frame_w = w;
        self.frame_h = h;
        self.body_row = row0 + 2;
        _ = text_util.writeText(
            &surf,
            ctx,
            col0 + 2,
            row0 + h - 1,
            if (self.pick) "j/k select  Enter apply  Esc close" else "j/k scroll  PgUp/PgDn  Esc close",
            border,
            col0 + w - 1,
        );
        return surf;
    }

    fn revealSelected(self: *Overlay) void {
        if (self.selected < self.scroll_top) self.scroll_top = self.selected;
        const view = @max(self.viewport_rows, 1);
        if (self.selected >= self.scroll_top + view) self.scroll_top = self.selected + 1 - view;
    }

    fn noteVisual(self: *Overlay, source_index: usize) void {
        if (self.visual_count >= self.visual_sources.len) return;
        self.visual_sources[self.visual_count] = source_index;
        self.visual_count += 1;
    }

    /// Row inside the frame maps to a source line. Null means the point is not on a body line.
    pub fn hitRow(self: *const Overlay, row: i16, col: i16) ?usize {
        if (!self.visible or self.frame_h == 0 or row < 0 or col < 0) return null;
        const point_row: u16 = @intCast(row);
        const point_col: u16 = @intCast(col);
        if (point_row < self.frame_row or point_row >= self.frame_row + self.frame_h) return null;
        if (point_col < self.frame_col or point_col >= self.frame_col + self.frame_w) return null;
        if (point_row < self.body_row) return null;
        const visual = self.scroll_top + @as(usize, point_row - self.body_row);
        if (visual >= self.visual_count) return null;
        return self.visual_sources[visual];
    }
};

pub const Dropdown = struct {
    body: []const u8 = "",
    theme: theme_mod.Theme = undefined,
    selected: usize = 0,
    line_count: usize = 0,
    userdata: ?*anyopaque = null,
    on_activate: ?*const fn (?*anyopaque, usize) void = null,

    pub fn measure(body: []const u8) struct { width: u16, height: u16, lines: usize } {
        var lines: usize = 0;
        var widest: usize = 0;
        var iter = std.mem.splitScalar(u8, body, '\n');
        while (iter.next()) |line| {
            if (line.len == 0 and lines > 0 and iter.rest().len == 0) break;
            lines += 1;
            if (line.len > widest) widest = line.len;
        }
        if (lines == 0) lines = 1;
        const width: u16 = @intCast(@min(@max(widest + 2, 18), 42));
        const height: u16 = @intCast(@min(lines, 16));
        return .{ .width = width, .height = height, .lines = lines };
    }

    pub fn indexAt(local_row: i16, height: u16, lines: usize) ?usize {
        if (local_row < 0) return null;
        const index: usize = @intCast(local_row);
        if (index >= height or index >= lines) return null;
        return index;
    }

    pub fn widget(self: *Dropdown) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = typeErasedEventHandler,
            .drawFn = typeErasedDrawFn,
        };
    }

    fn typeErasedEventHandler(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *Dropdown = @ptrCast(@alignCast(ptr));
        switch (event) {
            .mouse => |mouse| {
                const index = indexAt(mouse.row, 16, self.line_count) orelse return;
                self.selected = index;
                if (mouse.type == .press and mouse.button == .left) {
                    if (self.on_activate) |activate| activate(self.userdata, index);
                }
                return ctx.consumeAndRedraw();
            },
            .key_press => |key| {
                if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
                    if (self.line_count > 0 and self.selected + 1 < self.line_count) self.selected += 1;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
                    self.selected -|= 1;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.enter, .{})) {
                    if (self.on_activate) |activate| activate(self.userdata, self.selected);
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *Dropdown = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    pub fn draw(self: *Dropdown, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        var surf = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        const plain: vaxis.Style = .{ .fg = self.theme.fg, .bg = self.theme.header_bg };
        const picked: vaxis.Style = .{ .fg = self.theme.selected_fg, .bg = self.theme.selected_bg };
        var row: u16 = 0;
        while (row < size.height) : (row += 1) {
            var col: u16 = 0;
            while (col < size.width) : (col += 1) {
                surf.writeCell(col, row, .{
                    .char = .{ .grapheme = " ", .width = 1 },
                    .style = plain,
                });
            }
        }
        var index: usize = 0;
        var lines = std.mem.splitScalar(u8, self.body, '\n');
        while (lines.next()) |line| : (index += 1) {
            if (index >= size.height) break;
            const style = if (index == self.selected) picked else plain;
            _ = text_util.writeText(&surf, ctx, 1, @intCast(index), line, style, size.width);
        }
        return surf;
    }
};

test "a dropdown row is the pointer's local row" {
    try std.testing.expectEqual(@as(?usize, 0), Dropdown.indexAt(0, 3, 3));
    try std.testing.expectEqual(@as(?usize, 2), Dropdown.indexAt(2, 3, 3));
    try std.testing.expect(Dropdown.indexAt(3, 3, 3) == null);
    try std.testing.expect(Dropdown.indexAt(-1, 3, 3) == null);
    const measured = Dropdown.measure("Filter field\nStreams");
    try std.testing.expectEqual(@as(usize, 2), measured.lines);
    try std.testing.expect(measured.width >= 18);
    try std.testing.expectEqual(@as(u16, 2), measured.height);
}
