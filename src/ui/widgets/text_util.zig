const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;

/// Write UTF-8 text into a surface. Grapheme slices point into `text` (must outlive the frame)
/// or into arena-copied bytes when needed.
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
        const bytes = g.bytes(text);
        const width: u8 = @intCast(@max(@as(usize, 1), ctx.stringWidth(bytes)));
        if (col + width > max_width) break;
        surf.writeCell(col, row, .{
            .char = .{ .grapheme = bytes, .width = width },
            .style = style,
        });
        col += width;
    }
    return col;
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
