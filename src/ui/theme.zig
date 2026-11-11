const std = @import("std");
const vaxis = @import("vaxis");
const packet = @import("../model/packet.zig");

pub const Theme = struct {
    fg: vaxis.Cell.Color,
    bg: vaxis.Cell.Color,
    selected_fg: vaxis.Cell.Color,
    selected_bg: vaxis.Cell.Color,
    header_fg: vaxis.Cell.Color,
    header_bg: vaxis.Cell.Color,
    status_fg: vaxis.Cell.Color,
    status_bg: vaxis.Cell.Color,
    filter_fg: vaxis.Cell.Color,
    filter_bg: vaxis.Cell.Color,
    filter_ok_fg: vaxis.Cell.Color,
    filter_bad_fg: vaxis.Cell.Color,
    pane_border: vaxis.Cell.Color,
    pane_title_fg: vaxis.Cell.Color,
    pane_title_bg: vaxis.Cell.Color,
    accent: vaxis.Cell.Color,
};

pub fn rgb(r: u8, g: u8, b: u8) vaxis.Cell.Color {
    return .{ .rgb = .{ r, g, b } };
}

pub fn fromPacketColor(c: packet.Color) vaxis.Cell.Color {
    return rgb(c.r, c.g, c.b);
}

/// Close to classic termshark / Wireshark TUI dark look.
pub fn dark() Theme {
    return .{
        .fg = rgb(230, 230, 230),
        .bg = rgb(0, 0, 0),
        .selected_fg = rgb(255, 255, 255),
        .selected_bg = rgb(0, 90, 180),
        .header_fg = rgb(255, 255, 255),
        .header_bg = rgb(0, 70, 140),
        .status_fg = rgb(220, 220, 220),
        .status_bg = rgb(50, 50, 50),
        .filter_fg = rgb(255, 255, 255),
        .filter_bg = rgb(0, 90, 180),
        .filter_ok_fg = rgb(160, 255, 160),
        .filter_bad_fg = rgb(255, 140, 140),
        .pane_border = rgb(120, 120, 120),
        .pane_title_fg = rgb(255, 255, 255),
        .pane_title_bg = rgb(70, 70, 70),
        .accent = rgb(220, 60, 60),
    };
}

pub fn light() Theme {
    return .{
        .fg = rgb(20, 20, 20),
        .bg = rgb(255, 255, 255),
        .selected_fg = rgb(255, 255, 255),
        .selected_bg = rgb(0, 100, 180),
        .header_fg = rgb(255, 255, 255),
        .header_bg = rgb(0, 90, 160),
        .status_fg = rgb(30, 30, 30),
        .status_bg = rgb(220, 220, 220),
        .filter_fg = rgb(255, 255, 255),
        .filter_bg = rgb(0, 100, 180),
        .filter_ok_fg = rgb(0, 120, 0),
        .filter_bad_fg = rgb(180, 0, 0),
        .pane_border = rgb(140, 140, 140),
        .pane_title_fg = rgb(30, 30, 30),
        .pane_title_bg = rgb(210, 210, 210),
        .accent = rgb(180, 40, 40),
    };
}

pub fn resolve(dark_mode: bool) Theme {
    return if (dark_mode) dark() else light();
}

/// Focused selection is the bright theme color. Unfocused selection is a warm
/// neutral so it stays readable and does not match a protocol tint.
pub fn selectionStyle(theme: Theme, focused: bool) vaxis.Style {
    if (focused) return .{ .fg = theme.selected_fg, .bg = theme.selected_bg };
    return .{ .fg = theme.fg, .bg = rgb(72, 64, 58) };
}

pub fn parseToml(input: []const u8, base: Theme) Theme {
    var theme = base;
    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == '[') continue;
        const separator = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..separator], " \t");
        const raw_value = std.mem.trim(u8, line[separator + 1 ..], " \t\"");
        const color = parseHexColor(raw_value) orelse continue;
        if (std.mem.eql(u8, key, "fg")) theme.fg = color else if (std.mem.eql(u8, key, "bg")) theme.bg = color else if (std.mem.eql(u8, key, "selected-fg")) theme.selected_fg = color else if (std.mem.eql(u8, key, "selected-bg")) theme.selected_bg = color else if (std.mem.eql(u8, key, "header-fg")) theme.header_fg = color else if (std.mem.eql(u8, key, "header-bg")) theme.header_bg = color else if (std.mem.eql(u8, key, "status-fg")) theme.status_fg = color else if (std.mem.eql(u8, key, "status-bg")) theme.status_bg = color else if (std.mem.eql(u8, key, "filter-fg")) theme.filter_fg = color else if (std.mem.eql(u8, key, "filter-bg")) theme.filter_bg = color else if (std.mem.eql(u8, key, "filter-ok-fg")) theme.filter_ok_fg = color else if (std.mem.eql(u8, key, "filter-bad-fg")) theme.filter_bad_fg = color else if (std.mem.eql(u8, key, "pane-border")) theme.pane_border = color else if (std.mem.eql(u8, key, "accent")) theme.accent = color;
    }
    return theme;
}

fn parseHexColor(value: []const u8) ?vaxis.Cell.Color {
    if (value.len != 7 or value[0] != '#') return null;
    return rgb(
        std.fmt.parseInt(u8, value[1..3], 16) catch return null,
        std.fmt.parseInt(u8, value[3..5], 16) catch return null,
        std.fmt.parseInt(u8, value[5..7], 16) catch return null,
    );
}

fn ciStarts(hay: []const u8, needle: []const u8) bool {
    if (needle.len > hay.len) return false;
    for (hay[0..needle.len], needle) |a, b| {
        if (std.ascii.toLower(a) != std.ascii.toLower(b)) return false;
    }
    return true;
}

fn ciIndex(hay: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > hay.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (ciStarts(hay[i..], needle)) return true;
    }
    return false;
}

pub fn protocolStyle(theme: Theme, protocol: []const u8) vaxis.Style {
    const lower = std.mem.trim(u8, protocol, " \t");
    // Subtle row tinting similar to Wireshark coloring rules.
    if (ciStarts(lower, "tcp")) return .{ .fg = theme.fg, .bg = rgb(20, 30, 50) };
    if (ciStarts(lower, "udp")) return .{ .fg = theme.fg, .bg = rgb(20, 40, 30) };
    if (ciIndex(lower, "tls") or ciIndex(lower, "ssl")) return .{ .fg = theme.fg, .bg = rgb(40, 20, 45) };
    if (ciIndex(lower, "http")) return .{ .fg = theme.fg, .bg = rgb(45, 35, 15) };
    if (ciStarts(lower, "arp")) return .{ .fg = theme.fg, .bg = rgb(45, 40, 10) };
    if (ciIndex(lower, "dns") or ciIndex(lower, "ssdp")) return .{ .fg = theme.fg, .bg = rgb(15, 40, 40) };
    return .{ .fg = theme.fg, .bg = theme.bg };
}

test "theme resolve dark and light" {
    const d = dark();
    const l = light();
    try std.testing.expect(d.bg.eql(l.bg) == false);
}

test "unfocused selection is not a protocol tint" {
    const theme = dark();
    const dim = selectionStyle(theme, false);
    const bright = selectionStyle(theme, true);
    try std.testing.expect(bright.bg.eql(theme.selected_bg));
    try std.testing.expect(!dim.bg.eql(bright.bg));
    try std.testing.expect(!dim.bg.eql(protocolStyle(theme, "TCP").bg));
    try std.testing.expect(!dim.bg.eql(protocolStyle(theme, "UDP").bg));
    try std.testing.expect(!dim.bg.eql(protocolStyle(theme, "TLS").bg));
    try std.testing.expect(!dim.bg.eql(protocolStyle(theme, "ARP").bg));
    try std.testing.expect(!dim.bg.eql(theme.bg));
}

test "protocol style tcp" {
    const t = dark();
    const s = protocolStyle(t, "TCP");
    try std.testing.expect(!s.bg.eql(t.bg));
}
