const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;

pub const HSplit = struct {
    top: vxfw.Widget,
    bottom: vxfw.Widget,
    ratio: f32 = 0.5,
    dragging: bool = false,
    divider_style: vaxis.Style = .{},
    last_height: u16 = 0,
    divider_row: u16 = 0,

    pub fn widget(self: *HSplit) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = typeErasedEventHandler,
            .drawFn = typeErasedDrawFn,
        };
    }

    fn typeErasedEventHandler(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *HSplit = @ptrCast(@alignCast(ptr));
        switch (event) {
            .mouse => |mouse| {
                if (mouse.type == .press and mouse.button == .left and mouse.row >= 0 and
                    @as(u16, @intCast(mouse.row)) == self.divider_row)
                {
                    self.dragging = true;
                    try ctx.setMouseShape(.@"ns-resize");
                    return ctx.consumeAndRedraw();
                }
                if (mouse.type == .release) {
                    self.dragging = false;
                } else if (self.dragging and (mouse.type == .drag or mouse.type == .motion) and
                    mouse.row >= 0 and self.last_height > 1)
                {
                    self.ratio = std.math.clamp(
                        @as(f32, @floatFromInt(mouse.row)) /
                            @as(f32, @floatFromInt(self.last_height - 1)),
                        0.1,
                        0.9,
                    );
                    return ctx.consumeAndRedraw();
                }
            },
            .key_press => |key| {
                if (key.matches('+', .{}) or key.matches('=', .{})) {
                    self.ratio = @min(0.9, self.ratio + 0.05);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('-', .{}) or key.matches('_', .{})) {
                    self.ratio = @max(0.1, self.ratio - 0.05);
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *HSplit = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    pub fn draw(self: *HSplit, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        const divider_h: u16 = if (size.height >= 3) 1 else 0;
        const available = size.height -| divider_h;
        const calculated: u16 = @intFromFloat(@as(f32, @floatFromInt(available)) * self.ratio);
        const top_h = if (available <= 1) available else std.math.clamp(calculated, 1, available - 1);
        const bot_h = available -| top_h;
        self.last_height = size.height;
        self.divider_row = top_h;
        const top_ctx = ctx.withConstraints(.{}, .{ .width = size.width, .height = top_h });
        const bot_ctx = ctx.withConstraints(.{}, .{ .width = size.width, .height = bot_h });
        const top_surf = try self.top.draw(top_ctx);
        const bot_surf = try self.bottom.draw(bot_ctx);
        const children = try ctx.arena.alloc(vxfw.SubSurface, 2);
        children[0] = .{ .origin = .{ .row = 0, .col = 0 }, .surface = top_surf };
        children[1] = .{ .origin = .{ .row = top_h + divider_h, .col = 0 }, .surface = bot_surf };
        var surface = try vxfw.Surface.initWithChildren(ctx.arena, self.widget(), size, children);
        if (divider_h == 1) {
            var col: u16 = 0;
            while (col < size.width) : (col += 1) {
                surface.writeCell(col, top_h, .{
                    .char = .{ .grapheme = "─", .width = 1 },
                    .style = self.divider_style,
                });
            }
        }
        return surface;
    }
};
