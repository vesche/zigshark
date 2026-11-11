const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const theme_mod = @import("../theme.zig");
const filter_bar = @import("filter_bar.zig");
const text_util = @import("text_util.zig");

pub const CommandDef = struct {
    name: []const u8,
    description: []const u8,
};

pub const defaultCommands = [_]CommandDef{
    .{ .name = "quit", .description = "Exit zigshark" },
    .{ .name = "help", .description = "Show key bindings" },
    .{ .name = "filter", .description = "Focus display filter" },
    .{ .name = "goto", .description = "Select a frame by number" },
    .{ .name = "decode-as", .description = "Add a tshark decode-as rule" },
    .{ .name = "timestamp", .description = "Set tshark timestamp format" },
    .{ .name = "search", .description = "Search packet list" },
    .{ .name = "search-regex", .description = "Search with . * + ? [] ^ $" },
    .{ .name = "search-hex", .description = "Search packet bytes as hexadecimal" },
    .{ .name = "search-filter", .description = "Find packets with a display filter" },
    .{ .name = "clear-filter", .description = "Clear display filter" },
    .{ .name = "clear-packets", .description = "Clear the packet list" },
    .{ .name = "load", .description = "Load a capture file" },
    .{ .name = "streams", .description = "Follow the current TCP/UDP stream" },
    .{ .name = "convs", .description = "List conversations; Enter filters" },
    .{ .name = "capinfo", .description = "Capture file info" },
    .{ .name = "columns", .description = "default, delta, absolute, or a tshark format" },
    .{ .name = "tail", .description = "Follow a growing capture" },
    .{ .name = "config", .description = "Show active configuration" },
    .{ .name = "logs", .description = "Show log file location" },
    .{ .name = "theme", .description = "Toggle theme" },
    .{ .name = "recents", .description = "Recent files" },
    .{ .name = "recent", .description = "Open a numbered recent file" },
    .{ .name = "recent-filter", .description = "Apply a numbered recent filter" },
    .{ .name = "marks", .description = "List marks" },
    .{ .name = "set", .description = "List or change any config setting" },
    .{ .name = "profile", .description = "Switch profile" },
    .{ .name = "wormhole", .description = "Send file via wormhole" },
    .{ .name = "no-theme", .description = "Disable packet colors" },
};

pub fn fuzzyMatch(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    var ni: usize = 0;
    for (haystack) |c| {
        if (std.ascii.toLower(c) == std.ascii.toLower(needle[ni])) {
            ni += 1;
            if (ni == needle.len) return true;
        }
    }
    return false;
}

pub fn parseCommandLine(input: []const u8) struct { cmd: []const u8, args: []const u8 } {
    var trimmed = std.mem.trim(u8, input, " \t");
    while (trimmed.len > 0 and trimmed[0] == ':') {
        trimmed = std.mem.trim(u8, trimmed[1..], " \t");
    }
    if (trimmed.len == 0) return .{ .cmd = "", .args = "" };
    if (std.mem.indexOfScalar(u8, trimmed, ' ')) |sp| {
        return .{ .cmd = trimmed[0..sp], .args = std.mem.trim(u8, trimmed[sp + 1 ..], " \t") };
    }
    return .{ .cmd = trimmed, .args = "" };
}

pub const CommandPalette = struct {
    field: vxfw.TextField,
    theme: theme_mod.Theme,
    visible: bool = false,
    selected: usize = 0,
    commands: []const CommandDef = &defaultCommands,
    userdata: ?*anyopaque = null,
    onRun: ?*const fn (?*anyopaque, []const u8, []const u8) anyerror!void = null,

    pub fn init(alloc: std.mem.Allocator, theme: theme_mod.Theme) CommandPalette {
        return .{
            .field = vxfw.TextField.init(alloc),
            .theme = theme,
        };
    }

    pub fn deinit(self: *CommandPalette) void {
        self.field.deinit();
    }

    pub fn setText(self: *CommandPalette, text: []const u8) !void {
        self.field.clearRetainingCapacity();
        try self.field.insertSliceAtCursor(text);
    }

    pub fn widget(self: *CommandPalette) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = typeErasedEventHandler,
            .drawFn = typeErasedDrawFn,
        };
    }

    fn matching(self: *CommandPalette, arena: std.mem.Allocator) ![]usize {
        const raw = filter_bar.fieldText(arena, &self.field) catch return error.OutOfMemory;
        defer arena.free(raw);
        const needle = std.mem.trim(u8, raw, " \t");
        const parsed = parseCommandLine(needle);
        const q = if (std.mem.startsWith(u8, parsed.cmd, "")) parsed.cmd else needle;
        var list: std.ArrayList(usize) = .empty;
        for (self.commands, 0..) |cmd, i| {
            if (fuzzyMatch(cmd.name, q) or fuzzyMatch(cmd.description, q))
                try list.append(arena, i);
        }
        return try list.toOwnedSlice(arena);
    }

    fn typeErasedEventHandler(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *CommandPalette = @ptrCast(@alignCast(ptr));
        if (!self.visible) return;
        switch (event) {
            .key_press => |key| {
                if (key.matches(vaxis.Key.escape, .{})) {
                    self.visible = false;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.enter, .{})) {
                    const line = try filter_bar.fieldText(ctx.alloc, &self.field);
                    defer ctx.alloc.free(line);
                    const parsed = parseCommandLine(line);
                    if (parsed.cmd.len != 0) {
                        if (self.onRun) |cb| try cb(self.userdata, parsed.cmd, parsed.args);
                        self.visible = false;
                    }
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
                    self.selected +%= 1;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
                    if (self.selected > 0) self.selected -= 1;
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }
        try self.field.widget().handleEvent(ctx, event);
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *CommandPalette = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    pub fn draw(self: *CommandPalette, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        if (!self.visible) {
            return .{ .size = .{}, .widget = self.widget(), .buffer = &.{}, .children = &.{} };
        }
        var surf = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        const style: vaxis.Style = .{ .fg = self.theme.fg, .bg = self.theme.bg };
        surf.writeCell(0, 0, .{ .char = .{ .grapheme = ":", .width = 1 }, .style = style });
        self.field.style = style;
        const field_ctx = ctx.withConstraints(.{}, .{ .width = size.width -| 1, .height = 1 });
        const field_surf = try self.field.draw(field_ctx);
        const matches = try self.matching(ctx.arena);
        if (self.selected >= matches.len and matches.len > 0) self.selected = matches.len - 1;
        var row: u16 = 1;
        for (matches, 0..) |idx, mi| {
            if (row >= size.height) break;
            const cmd = self.commands[idx];
            const sel = mi == self.selected;
            const row_style: vaxis.Style = if (sel)
                .{ .fg = self.theme.selected_fg, .bg = self.theme.selected_bg }
            else
                style;
            const line = try std.fmt.allocPrint(ctx.arena, "  {s} — {s}", .{ cmd.name, cmd.description });
            _ = text_util.writeText(&surf, ctx, 0, row, line, row_style, size.width);
            row += 1;
        }
        const children = try ctx.arena.alloc(vxfw.SubSurface, 1);
        children[0] = .{ .origin = .{ .row = 0, .col = 1 }, .surface = field_surf };
        surf.children = children;
        return surf;
    }
};

test "fuzzy match" {
    try std.testing.expect(fuzzyMatch("clear-filter", "clf"));
    try std.testing.expect(!fuzzyMatch("quit", "zzz"));
}

test "parse command line" {
    const p = parseCommandLine("load /tmp/x.pcap");
    try std.testing.expectEqualStrings("load", p.cmd);
    try std.testing.expectEqualStrings("/tmp/x.pcap", p.args);
    const with_colon = parseCommandLine(":streams tcp 0");
    try std.testing.expectEqualStrings("streams", with_colon.cmd);
    try std.testing.expectEqualStrings("tcp 0", with_colon.args);
}
