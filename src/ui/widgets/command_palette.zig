const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const theme_mod = @import("../theme.zig");
const filter_bar = @import("filter_bar.zig");
const text_util = @import("text_util.zig");

pub const CommandDef = struct {
    name: []const u8,
    description: []const u8,
    usage: []const u8,
};

pub const defaultCommands = [_]CommandDef{
    .{ .name = "quit", .description = "Exit zigshark", .usage = ":quit" },
    .{ .name = "help", .description = "Show key bindings", .usage = ":help" },
    .{ .name = "filter", .description = "Apply a display filter", .usage = ":filter [expression]" },
    .{ .name = "goto", .description = "Select a frame by number", .usage = ":goto <frame>" },
    .{ .name = "decode-as", .description = "Decode the selected packet, or add a raw rule", .usage = ":decode-as [layer==selector,protocol]" },
    .{ .name = "hierarchy", .description = "Protocol hierarchy; Enter filters", .usage = ":hierarchy" },
    .{ .name = "endpoints", .description = "Loudest addresses; Enter filters", .usage = ":endpoints [tcp|udp|ip|ipv6|eth]" },
    .{ .name = "iograph", .description = "Packets per interval", .usage = ":iograph [seconds]" },
    .{ .name = "dns", .description = "DNS names; Enter filters", .usage = ":dns" },
    .{ .name = "http", .description = "HTTP requests and responses; Enter filters", .usage = ":http" },
    .{ .name = "compare", .description = "Frames whose identity differs from another file", .usage = ":compare <file.pcap>" },
    .{ .name = "color", .description = "Add or delete a coloring rule", .usage = ":color [name filter|#fg|#bg|delete name]" },
    .{ .name = "comment", .description = "Read or write this frame's pcapng comment", .usage = ":comment [text]" },
    .{ .name = "lua", .description = "Run a tshark Lua script on this capture", .usage = ":lua <script.lua>" },
    .{ .name = "export", .description = "Write packets, one packet, json, csv, or objects", .usage = ":export packets|packet|json|csv <path> | objects http|smb <dir>" },
    .{ .name = "timestamp", .description = "Set tshark timestamp format", .usage = ":timestamp a|ad|adoy|d|dd|e|r|u|ud|udoy" },
    .{ .name = "search", .description = "Search packet list", .usage = ":search <text>" },
    .{ .name = "search-regex", .description = "Search with . * + ? [] ^ $", .usage = ":search-regex <pattern>" },
    .{ .name = "search-hex", .description = "Search packet bytes as hexadecimal", .usage = ":search-hex <hex bytes>" },
    .{ .name = "search-filter", .description = "Find packets with a display filter", .usage = ":search-filter <display filter>" },
    .{ .name = "clear-filter", .description = "Clear display filter", .usage = ":clear-filter" },
    .{ .name = "clear-packets", .description = "Clear the packet list", .usage = ":clear-packets" },
    .{ .name = "load", .description = "Load a capture file", .usage = ":load <path>" },
    .{ .name = "streams", .description = "Follow the current TCP/UDP stream", .usage = ":streams [tcp|udp] [index] [ascii|hex|raw]" },
    .{ .name = "convs", .description = "List conversations; Enter filters", .usage = ":convs [tcp|udp|ip|ipv6|eth]" },
    .{ .name = "capinfo", .description = "Capture file info", .usage = ":capinfo" },
    .{ .name = "columns", .description = "Choose the packet-list columns", .usage = ":columns [default|delta|absolute|set <format>|add <field>|drop <field>]" },
    .{ .name = "expert", .description = "Expert info on the open packet", .usage = ":expert" },
    .{ .name = "time-ref", .description = "Set or clear time zero on the selected frame", .usage = ":time-ref" },
    .{ .name = "tail", .description = "Follow a growing capture", .usage = ":tail" },
    .{ .name = "stop", .description = "Stop the live capture and keep the saved file", .usage = ":stop" },
    .{ .name = "config", .description = "Show active configuration", .usage = ":config" },
    .{ .name = "logs", .description = "Show log file location", .usage = ":logs" },
    .{ .name = "theme", .description = "Toggle or load a theme", .usage = ":theme [list|<name>]" },
    .{ .name = "recents", .description = "Recent files", .usage = ":recents" },
    .{ .name = "recent", .description = "Open a numbered recent file", .usage = ":recent <number>" },
    .{ .name = "recent-filter", .description = "Apply a numbered recent filter", .usage = ":recent-filter <number>" },
    .{ .name = "filters", .description = "Apply a saved filter", .usage = ":filters [name|save <name>|delete <name>]" },
    .{ .name = "marks", .description = "List marks", .usage = ":marks" },
    .{ .name = "mark", .description = "Mark this frame with a note", .usage = ":mark <label> [note]" },
    .{ .name = "related", .description = "Jump to a related packet", .usage = ":related [conv|addr|pair] [next|prev]" },
    .{ .name = "back", .description = "Restore the previous display filter", .usage = ":back" },
    .{ .name = "set", .description = "List or change any config setting", .usage = ":set [<key> <value>]" },
    .{ .name = "profile", .description = "Switch profile", .usage = ":profile [list|create|use|delete] <name>" },
    .{ .name = "wormhole", .description = "Send file via wormhole", .usage = ":wormhole [file]" },
    .{ .name = "no-theme", .description = "Use the built-in theme", .usage = ":no-theme" },
};

pub fn commandUsage(name: []const u8) []const u8 {
    for (defaultCommands) |cmd| {
        if (std.mem.eql(u8, cmd.name, name)) return cmd.usage;
    }
    return "";
}

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
        const parsed = parseCommandLine(std.mem.trim(u8, raw, " \t"));
        const q = parsed.cmd;
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
        const style: vaxis.Style = .{ .fg = self.theme.fg, .bg = self.theme.header_bg };
        var row_fill: u16 = 0;
        while (row_fill < size.height) : (row_fill += 1) {
            var col_fill: u16 = 0;
            while (col_fill < size.width) : (col_fill += 1) {
                surf.writeCell(col_fill, row_fill, .{
                    .char = .{ .grapheme = " ", .width = 1 },
                    .style = style,
                });
            }
        }
        surf.writeCell(0, 0, .{ .char = .{ .grapheme = ":", .width = 1 }, .style = style });
        self.field.style = style;
        const field_ctx = ctx.withConstraints(.{}, .{ .width = size.width -| 1, .height = 1 });
        var field_surf = try self.field.draw(field_ctx);
        if (field_surf.cursor) |cursor| {
            const mark_at: usize = @min(cursor.col, field_surf.size.width -| 1);
            var cell = field_surf.readCell(mark_at, 0);
            cell.style.fg = self.theme.selected_fg;
            cell.style.bg = self.theme.selected_bg;
            if (cell.char.grapheme.len == 0) cell.char = .{ .grapheme = " ", .width = 1 };
            field_surf.writeCell(@intCast(mark_at), 0, cell);
            surf.cursor = .{
                .col = 1 + @as(u16, @intCast(mark_at)),
                .row = 0,
                .shape = .block,
            };
        }
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
            if (sel and cmd.usage.len != 0 and row < size.height) {
                const usage_style: vaxis.Style = .{
                    .fg = self.theme.accent,
                    .bg = self.theme.selected_bg,
                };
                _ = text_util.writeText(&surf, ctx, 0, row, cmd.usage, usage_style, size.width);
                row += 1;
            }
        }
        const children = try ctx.arena.alloc(vxfw.SubSurface, 1);
        children[0] = .{ .origin = .{ .row = 0, .col = 1 }, .surface = field_surf };
        surf.children = children;
        return surf;
    }
};

test "palette needle is the parsed command" {
    const allocator = std.testing.allocator;
    var palette = CommandPalette.init(allocator, theme_mod.dark());
    defer palette.deinit();
    try palette.setText(":fil extra");
    const matches = try palette.matching(allocator);
    defer allocator.free(matches);
    var saw_filter = false;
    var saw_quit = false;
    for (matches) |index| {
        if (std.mem.eql(u8, palette.commands[index].name, "filter")) saw_filter = true;
        if (std.mem.eql(u8, palette.commands[index].name, "quit")) saw_quit = true;
    }
    try std.testing.expect(saw_filter);
    try std.testing.expect(!saw_quit);

    try palette.setText("");
    const all = try palette.matching(allocator);
    defer allocator.free(all);
    try std.testing.expectEqual(palette.commands.len, all.len);
}

test "fuzzy match" {
    try std.testing.expect(fuzzyMatch("clear-filter", "clf"));
    try std.testing.expect(!fuzzyMatch("quit", "zzz"));
}

test "selected commands show their arguments" {
    try std.testing.expectEqualStrings(":streams [tcp|udp] [index] [ascii|hex|raw]", commandUsage("streams"));
    try std.testing.expect(std.mem.indexOf(u8, commandUsage("columns"), "set <format>") != null);
    try std.testing.expectEqualStrings(":decode-as [layer==selector,protocol]", commandUsage("decode-as"));
}

test "parse command line" {
    const p = parseCommandLine("load /tmp/x.pcap");
    try std.testing.expectEqualStrings("load", p.cmd);
    try std.testing.expectEqualStrings("/tmp/x.pcap", p.args);
    const with_colon = parseCommandLine(":streams tcp 0");
    try std.testing.expectEqualStrings("streams", with_colon.cmd);
    try std.testing.expectEqualStrings("tcp 0", with_colon.args);
}
