const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const packet = @import("../../model/packet.zig");
const theme_mod = @import("../theme.zig");
const text_util = @import("text_util.zig");

pub const PacketTable = struct {
    rows: []const packet.PacketSummary = &.{},
    headers: []const []const u8 = &.{},
    theme: theme_mod.Theme,
    packet_colors: bool = true,
    selected: usize = 0,
    scroll_top: usize = 0,
    viewport_rows: usize = 1,
    last_width: u16 = 0,
    sort_column: usize = 0,
    sort_ascending: bool = true,
    pending_g: bool = false,
    focused: bool = false,
    userdata: ?*anyopaque = null,
    onSelect: ?*const fn (?*anyopaque, usize) void = null,
    onSort: ?*const fn (?*anyopaque, usize, bool) void = null,
    onFocus: ?*const fn (?*anyopaque) void = null,

    pub fn widget(self: *PacketTable) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = typeErasedEventHandler,
            .drawFn = typeErasedDrawFn,
        };
    }

    fn typeErasedEventHandler(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *PacketTable = @ptrCast(@alignCast(ptr));
        try self.handleEvent(ctx, event);
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *PacketTable = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    fn clampSelection(self: *PacketTable) void {
        if (self.rows.len == 0) {
            self.selected = 0;
            return;
        }
        if (self.selected >= self.rows.len) self.selected = self.rows.len - 1;
    }

    fn ensureVisible(self: *PacketTable, viewport_rows: usize) void {
        if (viewport_rows == 0) return;
        if (self.selected < self.scroll_top) self.scroll_top = self.selected;
        if (self.selected >= self.scroll_top + viewport_rows) {
            self.scroll_top = self.selected + 1 - viewport_rows;
        }
        const max_top = self.rows.len -| viewport_rows;
        if (self.scroll_top > max_top) self.scroll_top = max_top;
    }

    fn selectIndex(self: *PacketTable, idx: usize) void {
        if (self.rows.len == 0) return;
        const clamped = @min(idx, self.rows.len - 1);
        if (clamped == self.selected) return;
        self.selected = clamped;
        if (self.onSelect) |cb| cb(self.userdata, clamped);
    }

    pub fn formatSelected(self: *const PacketTable, allocator: std.mem.Allocator) ![]u8 {
        if (self.selected >= self.rows.len) return allocator.dupe(u8, "");
        const row = self.rows[self.selected];
        var writer: std.Io.Writer.Allocating = .init(allocator);
        defer writer.deinit();
        for (Semantic.all, 0..) |semantic, i| {
            if (i != 0) try writer.writer.writeByte('\t');
            try writer.writer.writeAll(cellFor(row, semantic));
        }
        return writer.toOwnedSlice();
    }

    pub fn handleEvent(self: *PacketTable, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        self.clampSelection();
        switch (event) {
            .mouse => |m| {
                if (m.type == .press and m.button == .left) {
                    if (self.onFocus) |cb| cb(self.userdata);
                    try ctx.requestFocus(self.widget());
                }
                if (m.button == .left and m.row >= 0 and m.col >= 0) {
                    const row: usize = @intCast(m.row);
                    if (row == 0) {
                        if (columnAt(self.headers, self.last_width, @intCast(m.col))) |column| {
                            if (column == self.sort_column) {
                                self.sort_ascending = !self.sort_ascending;
                            } else {
                                self.sort_column = column;
                                self.sort_ascending = true;
                            }
                            if (self.onSort) |callback| callback(self.userdata, self.sort_column, self.sort_ascending);
                            return ctx.consumeAndRedraw();
                        }
                    } else {
                        const idx = self.scroll_top + row - 1;
                        if (idx < self.rows.len) {
                            self.selectIndex(idx);
                            return ctx.consumeAndRedraw();
                        }
                    }
                }
                if (m.button == .wheel_up and self.scroll_top > 0) {
                    self.scroll_top -= 1;
                    return ctx.consumeAndRedraw();
                }
                if (m.button == .wheel_down) {
                    const max_top = self.rows.len -| self.viewport_rows;
                    if (self.scroll_top < max_top) {
                        self.scroll_top += 1;
                        return ctx.consumeAndRedraw();
                    }
                }
            },
            .key_press => |key| {
                const visible = @max(self.viewport_rows, 1);
                if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
                    self.selectIndex(self.selected + 1);
                    self.ensureVisible(visible);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
                    if (self.selected > 0) self.selectIndex(self.selected - 1);
                    self.ensureVisible(visible);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.page_down, .{})) {
                    self.selectIndex(self.selected + visible);
                    self.ensureVisible(visible);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.page_up, .{})) {
                    if (self.selected > visible) self.selectIndex(self.selected - visible) else self.selectIndex(0);
                    self.ensureVisible(visible);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.home, .{}) or (key.matches('g', .{}) and self.pending_g)) {
                    self.selectIndex(0);
                    self.scroll_top = 0;
                    self.pending_g = false;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('g', .{})) {
                    self.pending_g = true;
                    return ctx.consumeEvent();
                }
                if (key.matches(vaxis.Key.end, .{}) or key.matches('G', .{ .shift = true })) {
                    if (self.rows.len > 0) self.selectIndex(self.rows.len - 1);
                    self.ensureVisible(visible);
                    self.pending_g = false;
                    return ctx.consumeAndRedraw();
                }
                self.pending_g = false;
            },
            else => {},
        }
    }

    pub fn draw(self: *PacketTable, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        var surf = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        if (size.width == 0 or size.height == 0) return surf;

        self.last_width = size.width;
        var column_buf: [12]Column = undefined;
        const columns = if (self.headers.len > 0)
            layoutHeaders(self.headers, size.width, &column_buf)
        else
            fillColumns(column_buf[0..7], size.width);
        const header_style: vaxis.Style = .{ .fg = self.theme.header_fg, .bg = self.theme.header_bg, .bold = true };
        const normal: vaxis.Style = .{ .fg = self.theme.fg, .bg = self.theme.bg };
        const selected_style: vaxis.Style = if (self.focused)
            .{ .fg = self.theme.selected_fg, .bg = self.theme.selected_bg }
        else
            .{ .fg = self.theme.fg, .bg = theme_mod.rgb(0, 50, 90) };

        fillRow(&surf, 0, size.width, header_style);
        const header_line = try formatRow(ctx.arena, columns, null);
        _ = text_util.writeText(&surf, ctx, 0, 0, header_line, header_style, size.width);

        const body_h = size.height -| 1;
        self.viewport_rows = body_h;
        self.ensureVisible(body_h);

        var line: u16 = 1;
        var idx = self.scroll_top;
        while (line < size.height and idx < self.rows.len) : ({
            line += 1;
            idx += 1;
        }) {
            const row = self.rows[idx];
            var style = normal;
            if (idx == self.selected) {
                style = selected_style;
            } else if (self.packet_colors) {
                style = theme_mod.protocolStyle(self.theme, protocolCell(self.headers, row));
                if (row.fg_color) |c| style.fg = theme_mod.fromPacketColor(c);
                if (row.bg_color) |c| style.bg = theme_mod.fromPacketColor(c);
            } else if (idx % 2 == 1) {
                // Subtle zebra striping when packet colors are off.
                style = .{ .fg = self.theme.fg, .bg = theme_mod.rgb(18, 18, 28) };
            }
            fillRow(&surf, line, size.width, style);
            const text = try formatRow(ctx.arena, columns, row);
            _ = text_util.writeText(&surf, ctx, 0, line, text, style, size.width);
        }
        return surf;
    }
};

const Semantic = enum {
    number,
    time,
    source,
    destination,
    protocol,
    length,
    info,

    pub const all = [_]Semantic{ .number, .time, .source, .destination, .protocol, .length, .info };
};

const Column = struct {
    semantic: Semantic,
    title: []const u8,
    width: u16,
    index: usize = 0,
    from_header: bool = false,
};

fn fillColumns(buf: []Column, total_width: u16) []const Column {
    if (total_width < 70) {
        buf[0] = .{ .semantic = .number, .title = "No.", .width = 5 };
        buf[1] = .{ .semantic = .time, .title = "Time", .width = 10 };
        buf[2] = .{ .semantic = .protocol, .title = "Proto", .width = 9 };
        buf[3] = .{ .semantic = .length, .title = "Len", .width = 6 };
        buf[4] = .{ .semantic = .info, .title = "Info", .width = @max(total_width -| 33, 8) };
        return buf[0..5];
    }
    const fixed: u16 = 5 + 11 + 18 + 18 + 9 + 6;
    const gaps: u16 = 6;
    const info_w: u16 = if (total_width > fixed + gaps) total_width - fixed - gaps else 8;
    buf[0] = .{ .semantic = .number, .title = "No.", .width = 5 };
    buf[1] = .{ .semantic = .time, .title = "Time", .width = 11 };
    buf[2] = .{ .semantic = .source, .title = "Source", .width = 18 };
    buf[3] = .{ .semantic = .destination, .title = "Dest", .width = 18 };
    buf[4] = .{ .semantic = .protocol, .title = "Proto", .width = 9 };
    buf[5] = .{ .semantic = .length, .title = "Len", .width = 6 };
    buf[6] = .{ .semantic = .info, .title = "Info", .width = @max(info_w, 4) };
    return buf[0..7];
}

pub fn columnAt(headers: []const []const u8, width: u16, clicked: u16) ?usize {
    var buf: [12]Column = undefined;
    const columns = if (headers.len > 0) layoutHeaders(headers, width, &buf) else fillColumns(buf[0..7], width);
    var col: u16 = 0;
    for (columns) |column| {
        if (column.width == 0) continue;
        const end = col + column.width;
        if (clicked >= col and clicked < end + 1) return if (headers.len > 0) column.index else @intFromEnum(column.semantic);
        col = end + 1;
    }
    return null;
}

fn layoutHeaders(headers: []const []const u8, total_width: u16, buf: *[12]Column) []const Column {
    const count = @min(headers.len, buf.len);
    if (count == 0) return buf[0..0];
    var used: u16 = 0;
    for (headers[0..count], 0..) |title, index| {
        const numeric = isNumericTitle(title);
        const width: u16 = if (index + 1 == count) 0 else if (numeric) 8 else 16;
        buf[index] = .{
            .semantic = .info,
            .title = title,
            .width = width,
            .index = index,
            .from_header = true,
        };
        if (index + 1 != count) used += width + 1;
    }
    buf[count - 1].width = if (total_width > used) total_width - used else 8;
    return buf[0..count];
}

fn isNumericTitle(title: []const u8) bool {
    return std.ascii.eqlIgnoreCase(title, "No.") or
        std.ascii.eqlIgnoreCase(title, "Len") or
        std.ascii.eqlIgnoreCase(title, "Length") or
        std.mem.indexOf(u8, title, "Bytes") != null;
}

fn protocolCell(headers: []const []const u8, row: packet.PacketSummary) []const u8 {
    if (headers.len == 0) return cellFor(row, .protocol);
    for (headers, 0..) |header, index| {
        if (std.ascii.findIgnoreCase(header, "proto") != null and index < row.columns.len) {
            return row.columns[index];
        }
    }
    return if (row.columns.len > 4) row.columns[4] else "";
}

fn fillRow(surface: *vxfw.Surface, row: u16, width: u16, style: vaxis.Style) void {
    var col: u16 = 0;
    while (col < width) : (col += 1) {
        surface.writeCell(col, row, .{
            .char = .{ .grapheme = " ", .width = 1 },
            .style = style,
        });
    }
}

fn cellFor(row: packet.PacketSummary, semantic: Semantic) []const u8 {
    const has_delta = row.columns.len >= 8;
    const index: usize = switch (semantic) {
        .number => 0,
        .time => 1,
        .source => if (has_delta) 3 else 2,
        .destination => if (has_delta) 4 else 3,
        .protocol => if (has_delta) 5 else 4,
        .length => if (has_delta) 6 else 5,
        .info => if (has_delta) 7 else 6,
    };
    return if (index < row.columns.len) row.columns[index] else "";
}

fn formatRow(arena: std.mem.Allocator, columns: []const Column, row: ?packet.PacketSummary) ![]const u8 {
    var list: std.ArrayList(u8) = .empty;
    for (columns, 0..) |column, i| {
        if (column.width == 0) continue;
        if (i != 0) try list.append(arena, ' ');
        const raw = if (row) |packet_row|
            if (column.from_header)
                if (column.index < packet_row.columns.len) packet_row.columns[column.index] else ""
            else
                cellFor(packet_row, column.semantic)
        else
            column.title;
        const clipped = clipAscii(raw, column.width);
        const right = column.semantic == .number or column.semantic == .length or (column.from_header and isNumericTitle(column.title));
        if (right and clipped.len < column.width) {
            var pad: usize = 0;
            while (pad < column.width - clipped.len) : (pad += 1) try list.append(arena, ' ');
            try list.appendSlice(arena, clipped);
        } else {
            try list.appendSlice(arena, clipped);
            var pad: usize = clipped.len;
            while (pad < column.width) : (pad += 1) try list.append(arena, ' ');
        }
    }
    return try list.toOwnedSlice(arena);
}

fn clipAscii(text: []const u8, width: u16) []const u8 {
    if (width == 0) return "";
    if (text.len <= width) return text;
    return text[0..width];
}

test "header layout uses psml titles" {
    var buf: [12]Column = undefined;
    const headers = [_][]const u8{ "No.", "Time", "Delta", "Info" };
    const cols = layoutHeaders(&headers, 80, &buf);
    try std.testing.expectEqual(@as(usize, 4), cols.len);
    try std.testing.expectEqualStrings("Delta", cols[2].title);
    try std.testing.expect(cols[3].width > cols[0].width);
}

test "format row pads columns" {
    const allocator = std.testing.allocator;
    var buf: [7]Column = undefined;
    const cols = fillColumns(&buf, 120);
    const line = try formatRow(allocator, cols, null);
    defer allocator.free(line);
    try std.testing.expect(std.mem.indexOf(u8, line, "No.") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "Source") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "No.Time") == null);
}
