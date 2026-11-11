const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const packet = @import("../../model/packet.zig");
const search_mod = @import("../../model/search.zig");
const theme_mod = @import("../theme.zig");
const text_util = @import("text_util.zig");

const FlatNode = struct {
    label: []const u8,
    name: []const u8,
    title: []const u8,
    show: []const u8,
    depth: u8,
    expandable: bool,
    expanded: bool,
    node_index: usize,
    pos: usize,
    size: usize,
};

pub const TreeColumns = struct {
    marker_at: u16,
    name_at: u16,
    name_width: u16,
    value_at: u16,
};

/// Columns for one tree row. The label uses every column after the marker and
/// is clipped at the pane edge, not at a fixed name width.
pub fn treeColumns(width: u16, depth: u8) TreeColumns {
    const indent: u16 = @as(u16, depth) * 2;
    const marker_w: u16 = 4;
    const name_at = indent + marker_w;
    const name_width = width -| name_at;
    return .{
        .marker_at = indent,
        .name_at = name_at,
        .name_width = name_width,
        .value_at = width,
    };
}

pub fn visibleLabel(label: []const u8, budget: u16) []const u8 {
    if (label.len <= budget) return label;
    if (budget == 0) return "";
    return label[0..budget];
}

pub const ProtocolTree = struct {
    root: ?*const packet.DetailNode = null,
    theme: theme_mod.Theme,
    selected: usize = 0,
    scroll_top: usize = 0,
    viewport_rows: usize = 1,
    expanded: std.AutoHashMap(usize, void),
    flat: std.ArrayList(FlatNode) = .empty,
    allocator: std.mem.Allocator,
    focused: bool = false,
    userdata: ?*anyopaque = null,
    onSelect: ?*const fn (?*anyopaque, usize, usize) void = null,
    onFocus: ?*const fn (?*anyopaque) void = null,
    /// When set, incremented once per `selectCovering` call.
    cover_probe: ?*usize = null,

    pub fn init(allocator: std.mem.Allocator, theme: theme_mod.Theme) ProtocolTree {
        return .{
            .theme = theme,
            .expanded = std.AutoHashMap(usize, void).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ProtocolTree) void {
        self.flat.deinit(self.allocator);
        self.expanded.deinit();
    }

    pub fn setRoot(self: *ProtocolTree, root: ?*const packet.DetailNode) void {
        self.root = root;
        self.selected = 0;
        self.scroll_top = 0;
        self.expanded.clearRetainingCapacity();
        // Top-level protos (Frame/Ethernet/IP/…) are listed collapsed with [+],
        // matching termshark's initial detail pane.
        self.rebuildFlat();
        self.notifySelect();
    }

    pub fn selectedHighlight(self: *const ProtocolTree) struct { pos: usize, size: usize } {
        if (self.selected >= self.flat.items.len) return .{ .pos = 0, .size = 0 };
        const n = self.flat.items[self.selected];
        return .{ .pos = n.pos, .size = n.size };
    }

    pub fn selectedField(self: *const ProtocolTree) ?struct { name: []const u8, show: []const u8 } {
        if (self.selected >= self.flat.items.len) return null;
        const node = self.flat.items[self.selected];
        if (node.name.len == 0) return null;
        return .{ .name = node.name, .show = node.show };
    }

    pub fn selectedText(self: *const ProtocolTree) []const u8 {
        if (self.selected >= self.flat.items.len) return "";
        return self.flat.items[self.selected].label;
    }

    pub fn formatSubtree(self: *const ProtocolTree, allocator: std.mem.Allocator) ![]u8 {
        if (self.selected >= self.flat.items.len) return allocator.dupe(u8, "");
        const depth = self.flat.items[self.selected].depth;
        var writer: std.Io.Writer.Allocating = .init(allocator);
        errdefer writer.deinit();
        var index = self.selected;
        while (index < self.flat.items.len) : (index += 1) {
            const node = self.flat.items[index];
            if (index != self.selected and node.depth <= depth) break;
            if (index != self.selected) try writer.writer.writeByte('\n');
            var pad: u8 = 0;
            while (pad < node.depth) : (pad += 1) try writer.writer.writeAll("  ");
            try writer.writer.writeAll(node.label);
        }
        return writer.toOwnedSlice();
    }

    pub fn findText(self: *ProtocolTree, needle: []const u8, forward: bool) bool {
        return self.findPattern(needle, false, forward);
    }

    pub fn findPattern(self: *ProtocolTree, needle: []const u8, regex: bool, forward: bool) bool {
        if (needle.len == 0 or self.flat.items.len == 0) return false;
        var step: usize = 0;
        while (step < self.flat.items.len) : (step += 1) {
            const index = if (forward)
                (self.selected + 1 + step) % self.flat.items.len
            else
                (self.selected + self.flat.items.len - 1 - step) % self.flat.items.len;
            const label = self.flat.items[index].label;
            const hit = if (regex)
                search_mod.regexFind(label, needle) != null
            else
                containsIgnoreCase(label, needle);
            if (hit) {
                self.selected = index;
                self.ensureVisible();
                self.notifySelect();
                return true;
            }
        }
        return false;
    }

    fn rebuildFlat(self: *ProtocolTree) void {
        self.flat.clearRetainingCapacity();
        const root = self.root orelse return;
        if (std.mem.eql(u8, root.name, "__packet_root")) {
            for (root.children) |*child| self.visit(child, 0);
        } else {
            self.visit(root, 0);
        }
        if (self.flat.items.len == 0) {
            self.selected = 0;
        } else if (self.selected >= self.flat.items.len) {
            self.selected = self.flat.items.len - 1;
        }
        self.ensureVisible();
    }

    fn fieldTitle(node: *const packet.DetailNode) []const u8 {
        if (std.mem.indexOfScalar(u8, node.showname, ':')) |colon| {
            const title = std.mem.trim(u8, node.showname[0..colon], " \t");
            if (title.len != 0) return title;
        }
        if (node.showname.len != 0) return node.showname;
        return node.name;
    }

    fn visit(self: *ProtocolTree, node: *const packet.DetailNode, depth: u8) void {
        const idx = @intFromPtr(node);
        const expandable = node.children.len > 0;
        const expanded = expandable and self.expanded.contains(idx);
        const label = if (node.showname.len != 0) node.showname else if (node.show.len != 0) node.show else node.name;
        self.flat.append(self.allocator, .{
            .label = label,
            .name = node.name,
            .title = fieldTitle(node),
            .show = node.show,
            .depth = depth,
            .expandable = expandable,
            .expanded = expanded,
            .node_index = idx,
            .pos = node.pos,
            .size = node.size,
        }) catch {};
        if (expandable and expanded) {
            for (node.children) |*child| {
                self.visit(child, depth + 1);
            }
        }
    }

    fn ensureVisible(self: *ProtocolTree) void {
        if (self.selected < self.scroll_top) self.scroll_top = self.selected;
        if (self.viewport_rows == 0) return;
        if (self.selected >= self.scroll_top + self.viewport_rows) {
            self.scroll_top = self.selected + 1 - self.viewport_rows;
        }
        const max_top = self.flat.items.len -| self.viewport_rows;
        if (self.scroll_top > max_top) self.scroll_top = max_top;
    }

    pub fn widget(self: *ProtocolTree) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = typeErasedEventHandler,
            .drawFn = typeErasedDrawFn,
        };
    }

    fn typeErasedEventHandler(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *ProtocolTree = @ptrCast(@alignCast(ptr));
        try self.handleEvent(ctx, event);
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *ProtocolTree = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    /// Expand every ancestor of the tightest field covering `offset` and select it.
    /// This is the termshark hex-cursor → protocol-tree jump.
    pub fn selectCovering(self: *ProtocolTree, offset: usize) void {
        if (self.cover_probe) |probe| probe.* += 1;
        const root = self.root orelse return;
        var current: *const packet.DetailNode = root;
        var target: ?*const packet.DetailNode = null;
        var guard: u8 = 0;
        while (guard < 64) : (guard += 1) {
            var best: ?*const packet.DetailNode = null;
            for (current.children) |*child| {
                if (child.size == 0) continue;
                if (offset < child.pos or offset >= child.pos + child.size) continue;
                if (best) |prev| {
                    if (child.size < prev.size or child.size == prev.size) best = child;
                } else best = child;
            }
            if (best) |chosen| {
                if (chosen.children.len > 0) self.expanded.put(@intFromPtr(chosen), {}) catch {};
                target = chosen;
                current = chosen;
            } else break;
        }
        const chosen = target orelse return;
        self.rebuildFlat();
        self.selectNode(@intFromPtr(chosen));
        self.scrollIntoMiddle();
        self.notifySelect();
    }

    pub fn handleEvent(self: *ProtocolTree, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        switch (event) {
            .mouse => |mouse| {
                if (mouse.button == .wheel_down and self.flat.items.len > self.viewport_rows) {
                    self.scroll_top = @min(self.scroll_top + 3, self.flat.items.len - self.viewport_rows);
                    return ctx.consumeAndRedraw();
                }
                if (mouse.button == .wheel_up) {
                    self.scroll_top -|= 3;
                    return ctx.consumeAndRedraw();
                }
                if (mouse.type == .press and mouse.button == .left and mouse.row >= 0 and mouse.col >= 0) {
                    self.noteFocus();
                    try ctx.requestFocus(self.widget());
                    const row: usize = @intCast(mouse.row);
                    const index = self.scroll_top + row;
                    if (index >= self.flat.items.len) return ctx.consumeAndRedraw();
                    const col: u16 = @intCast(mouse.col);
                    const node = self.flat.items[index];
                    const marker_col: u16 = @as(u16, node.depth) * 2;
                    const on_marker = node.expandable and col >= marker_col and col < marker_col + 3;
                    self.selected = index;
                    if (on_marker) {
                        self.toggleSelected();
                    } else {
                        self.notifySelect();
                    }
                    return ctx.consumeAndRedraw();
                }
            },
            .key_press => |key| {
                if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
                    if (self.flat.items.len > 0 and self.selected + 1 < self.flat.items.len) {
                        self.selected += 1;
                        self.ensureVisible();
                        self.notifySelect();
                        return ctx.consumeAndRedraw();
                    }
                }
                if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
                    if (self.selected > 0) {
                        self.selected -= 1;
                        self.ensureVisible();
                        self.notifySelect();
                        return ctx.consumeAndRedraw();
                    }
                }
                if (key.matches(vaxis.Key.page_down, .{})) {
                    if (self.flat.items.len > 0) {
                        self.selected = @min(self.selected + self.viewport_rows, self.flat.items.len - 1);
                        self.ensureVisible();
                        self.notifySelect();
                    }
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.page_up, .{})) {
                    self.selected -|= self.viewport_rows;
                    self.ensureVisible();
                    self.notifySelect();
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.home, .{}) or key.matches('g', .{})) {
                    self.selected = 0;
                    self.ensureVisible();
                    self.notifySelect();
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.end, .{}) or key.matches('G', .{ .shift = true })) {
                    if (self.flat.items.len > 0) self.selected = self.flat.items.len - 1;
                    self.ensureVisible();
                    self.notifySelect();
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.enter, .{}) or key.matches(' ', .{})) {
                    self.toggleSelected();
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.right, .{}) or key.matches('l', .{}) or key.matches('+', .{}) or key.matches('=', .{})) {
                    self.expandSelected();
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.left, .{}) or key.matches('h', .{}) or key.matches('-', .{}) or key.matches('_', .{ .shift = true })) {
                    self.collapseSelected();
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }
    }

    fn noteFocus(self: *ProtocolTree) void {
        if (self.onFocus) |cb| cb(self.userdata);
    }

    fn selectNode(self: *ProtocolTree, node_index: usize) void {
        for (self.flat.items, 0..) |n, i| {
            if (n.node_index == node_index) {
                self.selected = i;
                return;
            }
        }
    }

    fn toggleSelected(self: *ProtocolTree) void {
        if (self.selected >= self.flat.items.len) return;
        const n = self.flat.items[self.selected];
        if (!n.expandable) return;
        if (self.expanded.contains(n.node_index)) {
            _ = self.expanded.remove(n.node_index);
        } else {
            self.expanded.put(n.node_index, {}) catch {};
        }
        const keep = n.node_index;
        self.rebuildFlat();
        self.selectNode(keep);
        self.ensureVisible();
        self.notifySelect();
    }

    fn expandSelected(self: *ProtocolTree) void {
        if (self.selected >= self.flat.items.len) return;
        const n = self.flat.items[self.selected];
        if (n.expandable and !n.expanded) {
            self.expanded.put(n.node_index, {}) catch {};
            const keep = n.node_index;
            self.rebuildFlat();
            self.selectNode(keep);
            self.ensureVisible();
            self.notifySelect();
            return;
        }
        if (n.expanded and self.selected + 1 < self.flat.items.len) {
            self.selected += 1;
            self.ensureVisible();
            self.notifySelect();
        }
    }

    fn collapseSelected(self: *ProtocolTree) void {
        if (self.selected >= self.flat.items.len) return;
        const n = self.flat.items[self.selected];
        if (n.expandable and n.expanded) {
            _ = self.expanded.remove(n.node_index);
            const keep = n.node_index;
            self.rebuildFlat();
            self.selectNode(keep);
            self.ensureVisible();
            self.notifySelect();
            return;
        }
        if (n.depth > 0) {
            var i = self.selected;
            while (i > 0) {
                i -= 1;
                if (self.flat.items[i].depth < n.depth) {
                    self.selected = i;
                    self.ensureVisible();
                    self.notifySelect();
                    return;
                }
            }
        }
    }

    fn scrollIntoMiddle(self: *ProtocolTree) void {
        if (self.viewport_rows <= 1) {
            self.ensureVisible();
            return;
        }
        const half = self.viewport_rows / 2;
        self.scroll_top = if (self.selected > half) self.selected - half else 0;
        self.ensureVisible();
    }

    fn notifySelect(self: *ProtocolTree) void {
        if (self.onSelect) |cb| {
            if (self.selected < self.flat.items.len) {
                const n = self.flat.items[self.selected];
                cb(self.userdata, n.pos, n.size);
            }
        }
    }

    pub fn draw(self: *ProtocolTree, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        var surf = try vxfw.Surface.init(ctx.arena, self.widget(), size);
        const normal: vaxis.Style = .{ .fg = self.theme.fg, .bg = self.theme.bg };
        const sel = theme_mod.selectionStyle(self.theme, self.focused);
        const marker_fg = self.theme.accent;
        self.viewport_rows = size.height;
        self.ensureVisible();
        var row: u16 = 0;
        var i = self.scroll_top;
        while (i < self.flat.items.len) : (i += 1) {
            if (row >= size.height) break;
            const n = self.flat.items[i];
            const style = if (i == self.selected) sel else normal;
            var fill_col: u16 = 0;
            while (fill_col < size.width) : (fill_col += 1) {
                surf.writeCell(fill_col, row, .{
                    .char = .{ .grapheme = " ", .width = 1 },
                    .style = style,
                });
            }
            const columns = treeColumns(size.width, n.depth);
            const marker = if (n.expandable)
                if (n.expanded) "[-] " else "[+] "
            else
                "    ";
            const marker_style: vaxis.Style = .{ .fg = marker_fg, .bg = style.bg, .bold = n.expandable };
            _ = text_util.writeText(&surf, ctx, columns.marker_at, row, marker, marker_style, columns.name_at);
            _ = text_util.writeText(&surf, ctx, columns.name_at, row, n.label, style, size.width);
            row += 1;
        }
        return surf;
    }
};

test "wide tree rows keep the full protocol name" {
    const ip = "Internet Protocol Version 4, Src: 192.168.86.246, Dst: 52.20.230.126";
    const tcp = "Transmission Control Protocol, Src Port: 42184, Dst Port: 443";
    const wide = treeColumns(120, 0);
    try std.testing.expect(wide.name_width >= ip.len);
    try std.testing.expectEqualStrings(ip, visibleLabel(ip, wide.name_width));
    try std.testing.expectEqualStrings(tcp, visibleLabel(tcp, wide.name_width));

    const narrow = treeColumns(24, 0);
    const shown = visibleLabel(ip, narrow.name_width);
    try std.testing.expect(shown.len < ip.len);
    try std.testing.expect(shown.len > 8);
    try std.testing.expect(std.mem.startsWith(u8, ip, shown));
}

test "hex offset selects the tightest field and expands ancestors" {
    const allocator = std.testing.allocator;
    const eth_type = packet.DetailNode{
        .name = "eth.type",
        .showname = "Type: IPv4",
        .show = "0x0800",
        .pos = 12,
        .size = 2,
        .children = &.{},
    };
    const dst = packet.DetailNode{
        .name = "eth.dst",
        .showname = "Destination",
        .show = "",
        .pos = 0,
        .size = 6,
        .children = &.{},
    };
    var eth_kids = [_]packet.DetailNode{ dst, eth_type };
    const eth = packet.DetailNode{
        .name = "eth",
        .showname = "Ethernet II",
        .show = "",
        .pos = 0,
        .size = 14,
        .children = &eth_kids,
    };
    var root_kids = [_]packet.DetailNode{eth};
    var root = packet.DetailNode{
        .name = "__packet_root",
        .showname = "",
        .show = "",
        .pos = 0,
        .size = 0,
        .children = &root_kids,
    };

    var tree = ProtocolTree.init(allocator, theme_mod.dark());
    defer tree.deinit();
    tree.viewport_rows = 8;
    tree.setRoot(&root);
    tree.selectCovering(12);
    try std.testing.expectEqualStrings("Type: IPv4", tree.selectedText());
    const field = tree.selectedField() orelse return error.MissingField;
    try std.testing.expectEqualStrings("eth.type", field.name);
    try std.testing.expectEqualStrings("0x0800", field.show);
    try std.testing.expect(tree.flat.items.len >= 3);
    try std.testing.expect(tree.flat.items[0].expanded);
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var offset: usize = 0;
    while (offset + needle.len <= haystack.len) : (offset += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[offset .. offset + needle.len], needle)) return true;
    }
    return false;
}
