const std = @import("std");
const zigshark = @import("zigshark");
const packet = zigshark.model.packet;
const theme = zigshark.ui.theme;
const hex_view = zigshark.ui.widgets.hex_view;
const tree_mod = zigshark.ui.widgets.protocol_tree;
const table_mod = zigshark.ui.widgets.packet_table;
const palette = zigshark.ui.widgets.command_palette;

fn readFixture(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .unlimited);
}

test "theme file overrides colors and ignores junk" {
    const base = theme.dark();
    const parsed = theme.parseToml(
        \\# comment
        \\[colors]
        \\fg = "#010203"
        \\accent = not-a-color
        \\selected-bg = "#aabbcc"
        \\
    , base);
    try std.testing.expect(parsed.fg.eql(theme.rgb(1, 2, 3)));
    try std.testing.expect(parsed.selected_bg.eql(theme.rgb(0xaa, 0xbb, 0xcc)));
    try std.testing.expect(parsed.accent.eql(base.accent));
    try std.testing.expect(!theme.protocolStyle(parsed, "UDP").bg.eql(parsed.bg));
    try std.testing.expect(!theme.protocolStyle(parsed, "ARP").bg.eql(parsed.bg));
    try std.testing.expect(theme.protocolStyle(parsed, "unknown").bg.eql(parsed.bg));
}

test "hex hit testing rejects the gutter and maps the ascii column" {
    var view = hex_view.HexView{
        .theme = theme.dark(),
        .raw = "0123456789abcdefXYZ",
        .last_width = 80,
    };
    try std.testing.expect(view.offsetAt(0, 0) == null);
    // Byte 8 sits one column further right because of the gap after byte 7.
    try std.testing.expectEqual(@as(?usize, 15), view.offsetAt(6 + 15 * 3 + 1, 0));
    try std.testing.expect(view.offsetAt(6 + 8 * 3, 0) == null);
    try std.testing.expect(view.offsetAt(200, 1) == null);
    view.scroll_top = 1;
    try std.testing.expectEqual(@as(?usize, 16), view.offsetAt(6, 0));
}

test "protocol tree jumps to ethertype and copies the visible subtree" {
    const allocator = std.testing.allocator;
    const xml = try readFixture(allocator, "tests/fixtures/1.pdml");
    defer allocator.free(xml);
    var detail = try packet.parsePdmlPacket(allocator, xml, 1);
    defer detail.deinit(allocator);

    var tree = tree_mod.ProtocolTree.init(allocator, theme.dark());
    defer tree.deinit();
    tree.viewport_rows = 12;
    tree.setRoot(&detail.root);
    const collapsed = tree.flat.items.len;
    tree.selectCovering(12);
    try std.testing.expect(std.mem.indexOf(u8, tree.selectedText(), "IPv4") != null);
    try std.testing.expect(tree.flat.items.len > collapsed);

    const copied = try tree.formatSubtree(allocator);
    defer allocator.free(copied);
    try std.testing.expect(std.mem.indexOf(u8, copied, "IPv4") != null);

    tree.selectCovering(10_000);
    try std.testing.expect(std.mem.indexOf(u8, tree.selectedText(), "IPv4") != null);

    try std.testing.expect(tree.findPattern("Destination", false, true));
    try std.testing.expect(std.mem.indexOf(u8, tree.selectedText(), "Destination") != null);
    try std.testing.expect(tree.findPattern("IPv4", true, false));
}

test "narrow packet list drops addresses and a click past the end misses" {
    const no_headers = [_][]const u8{};
    try std.testing.expectEqual(@as(?usize, 0), table_mod.columnAt(&no_headers, 60, 0));
    // After No. and Time, the next narrow column is protocol, not source.
    try std.testing.expectEqual(@as(?usize, 4), table_mod.columnAt(&no_headers, 60, 17));
    try std.testing.expect(table_mod.columnAt(&no_headers, 60, 62) == null);

    const headers = [_][]const u8{ "No.", "Time", "Source", "Info" };
    try std.testing.expect(table_mod.columnAt(&headers, 40, 1000) == null);
}

test "header columns report the clicked index" {
    const headers = [_][]const u8{ "No.", "Time", "Protocol", "Info" };
    try std.testing.expectEqual(@as(?usize, 0), table_mod.columnAt(&headers, 100, 1));
    try std.testing.expectEqual(@as(?usize, 2), table_mod.columnAt(&headers, 100, 8 + 1 + 16 + 1));
    try std.testing.expect(table_mod.columnAt(&headers, 20, 19) != null);
}

test "command palette parses empty input and fuzzy order" {
    const empty = palette.parseCommandLine("   ");
    try std.testing.expectEqualStrings("", empty.cmd);
    try std.testing.expectEqualStrings("", empty.args);
    const only = palette.parseCommandLine(":columns");
    try std.testing.expectEqualStrings("columns", only.cmd);
    try std.testing.expect(palette.fuzzyMatch("search-regex", "srx"));
    try std.testing.expect(!palette.fuzzyMatch("search-regex", "zzz"));
}
