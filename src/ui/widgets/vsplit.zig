const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;

pub const VSplit = struct {
    left: vxfw.Widget,
    right: vxfw.Widget,
    ratio: f32 = 0.5,
    divider_style: vaxis.Style = .{},
    dragging: bool = false,
    last_width: u16 = 0,
    divider_col: u16 = 0,

    pub fn widget(self: *VSplit) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = typeErasedEventHandler,
            .drawFn = typeErasedDrawFn,
        };
    }

    fn typeErasedEventHandler(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *VSplit = @ptrCast(@alignCast(ptr));
        switch (event) {
            .mouse => |mouse| {
                if (mouse.type == .press and mouse.button == .left and mouse.col >= 0 and
                    @as(u16, @intCast(mouse.col)) == self.divider_col)
                {
                    self.dragging = true;
                    try ctx.setMouseShape(.@"ew-resize");
                    return ctx.consumeAndRedraw();
                }
                if (mouse.type == .release) {
                    self.dragging = false;
                } else if (self.dragging and (mouse.type == .drag or mouse.type == .motion) and
                    mouse.col >= 0 and self.last_width > 1)
                {
                    self.ratio = std.math.clamp(
                        @as(f32, @floatFromInt(mouse.col)) /
                            @as(f32, @floatFromInt(self.last_width - 1)),
                        0.1,
                        0.9,
                    );
                    return ctx.consumeAndRedraw();
                }
            },
            .key_press => |key| {
                if (key.matches('>', .{}) or key.matches('.', .{ .shift = true })) {
                    self.ratio = @min(0.9, self.ratio + 0.05);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('<', .{}) or key.matches(',', .{ .shift = true })) {
                    self.ratio = @max(0.1, self.ratio - 0.05);
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *VSplit = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    pub fn draw(self: *VSplit, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        const divider_w: u16 = if (size.width >= 3) 1 else 0;
        const available = size.width -| divider_w;
        const calculated: u16 = @intFromFloat(@as(f32, @floatFromInt(available)) * self.ratio);
        const left_w = if (available <= 1) available else std.math.clamp(calculated, 1, available - 1);
        const right_w = available -| left_w;
        self.last_width = size.width;
        self.divider_col = left_w;
        const left_ctx = ctx.withConstraints(.{}, .{ .width = left_w, .height = size.height });
        const right_ctx = ctx.withConstraints(.{}, .{ .width = right_w, .height = size.height });
        const left_surf = try self.left.draw(left_ctx);
        const right_surf = try self.right.draw(right_ctx);
        const children = try ctx.arena.alloc(vxfw.SubSurface, 2);
        children[0] = .{ .origin = .{ .row = 0, .col = 0 }, .surface = left_surf };
        children[1] = .{ .origin = .{ .row = 0, .col = left_w + divider_w }, .surface = right_surf };
        var surface = try vxfw.Surface.initWithChildren(ctx.arena, self.widget(), size, children);
        if (divider_w == 1) {
            var row: u16 = 0;
            while (row < size.height) : (row += 1) {
                surface.writeCell(left_w, row, .{
                    .char = .{ .grapheme = "│", .width = 1 },
                    .style = self.divider_style,
                });
            }
        }
        return surface;
    }
};
