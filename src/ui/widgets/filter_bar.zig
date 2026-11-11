const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const theme_mod = @import("../theme.zig");
const text_util = @import("text_util.zig");

pub const FilterState = enum { neutral, ok, bad };

pub fn fieldText(alloc: std.mem.Allocator, field: *vxfw.TextField) ![]const u8 {
    const first = field.buf.firstHalf();
    const second = field.buf.secondHalf();
    const out = try alloc.alloc(u8, first.len + second.len);
    @memcpy(out[0..first.len], first);
    @memcpy(out[first.len..], second);
    return out;
}

pub const FilterBar = struct {
    field: vxfw.TextField,
    theme: theme_mod.Theme,
    label: []const u8 = "Filter:",
    state: FilterState = .neutral,
    userdata: ?*anyopaque = null,
    onSubmit: ?*const fn (?*anyopaque, []const u8) anyerror!void = null,
    onRecent: ?*const fn (?*anyopaque) anyerror!void = null,
    apply_col: u16 = 0,
    recent_col: u16 = 0,

    pub fn init(alloc: std.mem.Allocator, theme: theme_mod.Theme) FilterBar {
        return .{
            .field = vxfw.TextField.init(alloc),
            .theme = theme,
        };
    }

    pub fn deinit(self: *FilterBar) void {
        self.field.deinit();
    }

    pub fn widget(self: *FilterBar) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = typeErasedEventHandler,
            .drawFn = typeErasedDrawFn,
        };
    }

    fn typeErasedEventHandler(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *FilterBar = @ptrCast(@alignCast(ptr));
        switch (event) {
            .mouse => |mouse| {
                if (mouse.type == .press and mouse.button == .left and mouse.row == 0 and mouse.col >= 0) {
                    const col: u16 = @intCast(mouse.col);
                    if (col >= self.recent_col and self.recent_col > 0) {
                        if (self.onRecent) |callback| try callback(self.userdata);
                        return ctx.consumeAndRedraw();
                    }
                    if (col >= self.apply_col and self.apply_col > 0) {
                        const text = try fieldText(ctx.alloc, &self.field);
                        defer ctx.alloc.free(text);
                        if (self.onSubmit) |callback| try callback(self.userdata, text);
                        return ctx.consumeAndRedraw();
                    }
                }
            },
            .key_press => |key| {
                if (key.matches(vaxis.Key.enter, .{})) {
                    const text = try fieldText(ctx.alloc, &self.field);
                    defer ctx.alloc.free(text);
                    if (self.onSubmit) |cb| try cb(self.userdata, text);
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }
        try self.field.widget().handleEvent(ctx, event);
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *FilterBar = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    pub fn setText(self: *FilterBar, text: []const u8) !void {
        self.field.clearRetainingCapacity();
        try self.field.insertSliceAtCursor(text);
    }

    /// Caller owns returned slice.
    pub fn copyText(self: *FilterBar, allocator: std.mem.Allocator) ![]const u8 {
        return fieldText(allocator, &self.field);
    }

    pub fn draw(self: *FilterBar, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        var surf = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        const fg = switch (self.state) {
            .neutral => self.theme.filter_fg,
            .ok => self.theme.filter_ok_fg,
            .bad => self.theme.filter_bad_fg,
        };
        const row_bg = self.theme.filter_bg;
        var fill_col: u16 = 0;
        while (fill_col < size.width) : (fill_col += 1) {
            surf.writeCell(fill_col, 0, .{
                .char = .{ .grapheme = " ", .width = 1 },
                .style = .{ .fg = fg, .bg = row_bg },
            });
        }
        self.field.style = .{ .fg = fg, .bg = row_bg };
        const label_style: vaxis.Style = .{ .fg = self.theme.filter_fg, .bg = row_bg, .bold = true };
        const col = text_util.writeText(&surf, ctx, 0, 0, self.label, label_style, size.width);
        const buttons = "<Apply>  <Recent>";
        const button_width: u16 = @intCast(@min(ctx.stringWidth(buttons), size.width));
        const buttons_col = if (size.width > button_width) size.width - button_width else size.width;
        self.apply_col = buttons_col;
        self.recent_col = @min(size.width, buttons_col + 9);
        if (buttons_col < size.width) {
            _ = text_util.writeText(
                &surf,
                ctx,
                buttons_col,
                0,
                buttons,
                label_style,
                size.width,
            );
        }
        const child_ctx = ctx.withConstraints(.{}, .{
            .width = buttons_col -| col,
            .height = size.height,
        });
        const field_surf = try self.field.draw(child_ctx);
        const children = try ctx.arena.alloc(vxfw.SubSurface, 1);
        children[0] = .{ .origin = .{ .row = 0, .col = col }, .surface = field_surf };
        surf.children = children;
        return surf;
    }
};
