const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;

/// Write UTF-8 text into a surface. Grapheme slices point into `text` (must outlive the frame)
/// or into static replacement bytes.
///
/// Control bytes are not written through. A tab in a cell is sent to the terminal as a tab,
/// and the cursor jumps to the next stop while the renderer only advances one column.
pub fn writeText(
    surf: *vxfw.Surface,
    ctx: vxfw.DrawContext,
    col0: u16,
    row: u16,
    text: []const u8,
    style: vaxis.Style,
    max_width: u16,
) u16 {
    var col: u16 = col0;
    var iter = ctx.graphemeIterator(text);
    while (iter.next()) |g| {
        if (col >= max_width) break;
        const shown = terminalGrapheme(g.bytes(text)) orelse continue;
        const measured = ctx.stringWidth(shown);
        if (measured == 0 or measured > 8) continue;
        const width: u8 = @intCast(measured);
        if (col + width > max_width) break;
        surf.writeCell(col, row, .{
            .char = .{ .grapheme = shown, .width = width },
            .style = style,
        });
        col += width;
    }
    return col;
}

/// A grapheme safe to put in a terminal cell. A tab becomes one space. Any other
/// C0 or DEL byte is omitted so it cannot be written as itself.
pub fn terminalGrapheme(bytes: []const u8) ?[]const u8 {
    if (bytes.len == 0) return null;
    for (bytes) |byte| {
        if (byte == '\t') return " ";
        if (byte < 0x20 or byte == 0x7f) return null;
    }
    return bytes;
}

/// Paint every cell. Unwritten cells stay at the terminal default, which is black.
pub fn fillBackground(surf: *vxfw.Surface, style: vaxis.Style) void {
    const cell: vaxis.Cell = .{
        .char = .{ .grapheme = " ", .width = 1 },
        .style = style,
    };
    var row: u16 = 0;
    while (row < surf.size.height) : (row += 1) {
        var col: u16 = 0;
        while (col < surf.size.width) : (col += 1) {
            surf.writeCell(col, row, cell);
        }
    }
}

pub fn writeAsciiChar(
    surf: *vxfw.Surface,
    col: u16,
    row: u16,
    ch: u8,
    style: vaxis.Style,
) void {
    // Stable static storage for printable ASCII glyphs used as single-cell graphemes.
    const table = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    if (ch < 0x20 or ch > 0x7e) {
        surf.writeCell(col, row, .{ .char = .{ .grapheme = ".", .width = 1 }, .style = style });
        return;
    }
    const idx = ch - 0x20;
    surf.writeCell(col, row, .{ .char = .{ .grapheme = table[idx .. idx + 1], .width = 1 }, .style = style });
}

test "control characters are not sent to the terminal as themselves" {
    try std.testing.expectEqualStrings(" ", terminalGrapheme("\t").?);
    try std.testing.expect(terminalGrapheme("\x1b") == null);
    try std.testing.expect(terminalGrapheme("\r") == null);
    try std.testing.expect(terminalGrapheme("\x7f") == null);
    try std.testing.expectEqualStrings("6lowpan", terminalGrapheme("6lowpan").?);
}
