const std = @import("std");
const xml = @import("../xml_util.zig");

pub const Packet = struct {
    frame_number: u32,
    columns: [][]u8,
    fg: ?[]u8 = null,
    bg: ?[]u8 = null,

    pub fn deinit(self: *Packet, allocator: std.mem.Allocator) void {
        for (self.columns) |col| allocator.free(col);
        allocator.free(self.columns);
        if (self.fg) |f| allocator.free(f);
        if (self.bg) |b| allocator.free(b);
    }
};

pub const Document = struct {
    headers: [][]u8,
    packets: []Packet,

    pub fn deinit(self: *Document, allocator: std.mem.Allocator) void {
        for (self.headers) |h| allocator.free(h);
        allocator.free(self.headers);
        for (self.packets) |*pkt| pkt.deinit(allocator);
        allocator.free(self.packets);
    }
};

pub fn parse(allocator: std.mem.Allocator, input: []const u8) !Document {
    var headers: std.ArrayList([]u8) = .empty;
    errdefer {
        for (headers.items) |h| allocator.free(h);
        headers.deinit(allocator);
    }

    var pos: usize = 0;
    if (xml.findTagOpen(input, pos, "structure")) |sopen| {
        const te = xml.openingTagEnd(input, sopen) orelse return xml.ParseError.MalformedTag;
        pos = te.end;
        const struct_close = xml.findCloseTag(input, pos, "structure") orelse return xml.ParseError.UnexpectedEnd;
        while (xml.findTagOpen(input, pos, "section")) |sec_open| {
            if (sec_open >= struct_close) break;
            const text = (try xml.findTagContent(allocator, input, sec_open, "section")) orelse continue;
            try headers.append(allocator, text);
            pos = xml.findCloseTag(input, sec_open, "section") orelse pos + 1;
        }
    }

    var packets: std.ArrayList(Packet) = .empty;
    errdefer {
        for (packets.items) |*p| p.deinit(allocator);
        packets.deinit(allocator);
    }

    pos = 0;
    while (xml.findTagOpen(input, pos, "packet")) |popen| {
        const tag_slice = xml.openingTagSlice(input, popen) orelse return xml.ParseError.MalformedTag;
        const te = xml.openingTagEnd(input, popen) orelse return xml.ParseError.MalformedTag;

        var pkt: Packet = .{
            .frame_number = 0,
            .columns = &.{},
        };

        if (xml.getAttribute(tag_slice, "foreground") orelse xml.getAttribute(tag_slice, "fgcolor")) |fg| {
            pkt.fg = try allocator.dupe(u8, fg);
        }
        if (xml.getAttribute(tag_slice, "background") orelse xml.getAttribute(tag_slice, "bgcolor")) |bg| {
            pkt.bg = try allocator.dupe(u8, bg);
        }

        var cols: std.ArrayList([]u8) = .empty;
        errdefer {
            for (cols.items) |c| allocator.free(c);
            cols.deinit(allocator);
        }

        var sec_pos = te.end;
        const close = xml.findCloseTag(input, te.end, "packet") orelse return xml.ParseError.UnexpectedEnd;
        while (xml.findTagOpen(input, sec_pos, "section")) |so| {
            if (so >= close) break;
            const raw = (try xml.findTagContent(allocator, input, so, "section")) orelse break;
            const decoded = try xml.decodeEscapedBytes(allocator, raw);
            allocator.free(raw);
            try cols.append(allocator, decoded);
            sec_pos = xml.findCloseTag(input, so, "section") orelse break;
        }

        if (cols.items.len > 0) {
            pkt.frame_number = std.fmt.parseInt(u32, cols.items[0], 10) catch 0;
        }
        pkt.columns = try cols.toOwnedSlice(allocator);
        try packets.append(allocator, pkt);
        pos = close;
    }

    return .{
        .headers = try headers.toOwnedSlice(allocator),
        .packets = try packets.toOwnedSlice(allocator),
    };
}

pub const Available = struct {
    headers: [][]u8,
    packets: []Packet,
    /// Bytes at the front of `input` that will not be needed again.
    consumed: usize,

    pub fn deinit(self: *Available, allocator: std.mem.Allocator) void {
        for (self.headers) |header| allocator.free(header);
        if (self.headers.len != 0) allocator.free(self.headers);
        for (self.packets) |*pkt| pkt.deinit(allocator);
        if (self.packets.len != 0) allocator.free(self.packets);
    }
};

/// Parse complete `<structure>` and `<packet>` elements. An unfinished tag
/// stays unconsumed so the caller can append more tshark output.
pub fn parseAvailable(allocator: std.mem.Allocator, input: []const u8) !Available {
    var consumed: usize = 0;
    var headers: [][]u8 = &.{};
    errdefer {
        for (headers) |header| allocator.free(header);
        if (headers.len != 0) allocator.free(headers);
    }

    if (xml.findTagOpen(input, 0, "structure")) |sopen| {
        const packet_at = xml.findTagOpen(input, 0, "packet") orelse input.len;
        if (sopen < packet_at) {
            const te = xml.openingTagEnd(input, sopen) orelse return .{
                .headers = headers,
                .packets = &.{},
                .consumed = 0,
            };
            const struct_close = xml.findCloseTag(input, te.end, "structure") orelse return .{
                .headers = headers,
                .packets = &.{},
                .consumed = 0,
            };
            var built: std.ArrayList([]u8) = .empty;
            errdefer {
                for (built.items) |header| allocator.free(header);
                built.deinit(allocator);
            }
            var pos = te.end;
            while (xml.findTagOpen(input, pos, "section")) |sec_open| {
                if (sec_open >= struct_close) break;
                const text = (try xml.findTagContent(allocator, input, sec_open, "section")) orelse break;
                try built.append(allocator, text);
                pos = xml.findCloseTag(input, sec_open, "section") orelse break;
            }
            headers = try built.toOwnedSlice(allocator);
            consumed = struct_close;
        }
    }

    var packets: std.ArrayList(Packet) = .empty;
    errdefer {
        for (packets.items) |*pkt| pkt.deinit(allocator);
        packets.deinit(allocator);
    }

    var pos = consumed;
    while (xml.findTagOpen(input, pos, "packet")) |popen| {
        const parsed = try parseOnePacket(allocator, input, popen) orelse break;
        try packets.append(allocator, parsed.packet);
        pos = parsed.next;
        consumed = parsed.next;
    }

    return .{
        .headers = headers,
        .packets = try packets.toOwnedSlice(allocator),
        .consumed = consumed,
    };
}

const OnePacket = struct {
    packet: Packet,
    next: usize,
};

fn parseOnePacket(allocator: std.mem.Allocator, input: []const u8, popen: usize) !?OnePacket {
    const tag_slice = xml.openingTagSlice(input, popen) orelse return null;
    const te = xml.openingTagEnd(input, popen) orelse return null;
    const close = xml.findCloseTag(input, te.end, "packet") orelse return null;

    var pkt: Packet = .{
        .frame_number = 0,
        .columns = &.{},
    };
    errdefer pkt.deinit(allocator);

    if (xml.getAttribute(tag_slice, "foreground") orelse xml.getAttribute(tag_slice, "fgcolor")) |fg| {
        pkt.fg = try allocator.dupe(u8, fg);
    }
    if (xml.getAttribute(tag_slice, "background") orelse xml.getAttribute(tag_slice, "bgcolor")) |bg| {
        pkt.bg = try allocator.dupe(u8, bg);
    }

    var cols: std.ArrayList([]u8) = .empty;
    errdefer {
        for (cols.items) |column| allocator.free(column);
        cols.deinit(allocator);
    }

    var sec_pos = te.end;
    while (xml.findTagOpen(input, sec_pos, "section")) |so| {
        if (so >= close) break;
        const raw = (try xml.findTagContent(allocator, input, so, "section")) orelse break;
        const decoded = try xml.decodeEscapedBytes(allocator, raw);
        allocator.free(raw);
        try cols.append(allocator, decoded);
        sec_pos = xml.findCloseTag(input, so, "section") orelse break;
    }

    if (cols.items.len > 0) {
        pkt.frame_number = std.fmt.parseInt(u32, cols.items[0], 10) catch 0;
    }
    pkt.columns = try cols.toOwnedSlice(allocator);
    return .{ .packet = pkt, .next = close };
}

fn readFixture(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const io = std.testing.io;
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited);
}

test "parse psml fixture headers and packets" {
    const alloc = std.testing.allocator;
    const fixture = try readFixture(alloc, "tests/fixtures/1.psml");
    defer alloc.free(fixture);
    var doc = try parse(alloc, fixture);
    defer doc.deinit(alloc);

    try std.testing.expect(doc.headers.len == 7);
    try std.testing.expectEqualStrings("No.", doc.headers[0]);
    try std.testing.expectEqual(@as(usize, 18), doc.packets.len);
    try std.testing.expectEqual(@as(u32, 1), doc.packets[0].frame_number);
    try std.testing.expectEqualStrings("TLSv1.2", doc.packets[0].columns[4]);
    try std.testing.expectEqualStrings("129", doc.packets[0].columns[5]);
}

test "packet colors and entity in section" {
    const alloc = std.testing.allocator;
    const xml_input =
        \\<psml><structure><section>No.</section></structure>
        \\<packet fgcolor="#aabbcc" bgcolor="#112233">
        \\<section>1</section>
        \\<section>Don&#x27;t fragment</section>
        \\</packet></psml>
    ;
    var doc = try parse(alloc, xml_input);
    defer doc.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), doc.packets.len);
    try std.testing.expectEqualStrings("#aabbcc", doc.packets[0].fg.?);
    try std.testing.expectEqualStrings("#112233", doc.packets[0].bg.?);
    try std.testing.expectEqualStrings("Don't fragment", doc.packets[0].columns[1]);
}

test "available parse keeps an unfinished packet" {
    const alloc = std.testing.allocator;
    const partial =
        \\<psml><structure><section>No.</section></structure>
        \\<packet><section>1</sec
    ;
    var first = try parseAvailable(alloc, partial);
    defer first.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), first.headers.len);
    try std.testing.expectEqual(@as(usize, 0), first.packets.len);
    try std.testing.expect(first.consumed > 0);
    try std.testing.expect(first.consumed < partial.len);

    const rest = try std.fmt.allocPrint(alloc, "{s}tion></packet><packet><section>2</section></packet>", .{partial[first.consumed..]});
    defer alloc.free(rest);
    var second = try parseAvailable(alloc, rest);
    defer second.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), second.packets.len);
    try std.testing.expectEqual(@as(u32, 1), second.packets[0].frame_number);
    try std.testing.expectEqual(@as(u32, 2), second.packets[1].frame_number);
}

test "an extra psml attribute does not fail the parse" {
    const alloc = std.testing.allocator;
    const xml_input =
        \\<psml><structure><section>No.</section></structure>
        \\<packet foreground='#aabbcc' unparsed='yes' extra='kept'>
        \\<section>7</section>
        \\</packet></psml>
    ;
    var doc = try parse(alloc, xml_input);
    defer doc.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), doc.packets.len);
    try std.testing.expectEqual(@as(u32, 7), doc.packets[0].frame_number);
    try std.testing.expectEqualStrings("#aabbcc", doc.packets[0].fg.?);
}

test "modern tshark color attribute names" {
    const alloc = std.testing.allocator;
    const xml_input =
        \\<psml><structure><section>No.</section></structure>
        \\<packet foreground='#aabbcc' background='#112233'>
        \\<section>1</section>
        \\</packet></psml>
    ;
    var doc = try parse(alloc, xml_input);
    defer doc.deinit(alloc);
    try std.testing.expectEqualStrings("#aabbcc", doc.packets[0].fg.?);
    try std.testing.expectEqualStrings("#112233", doc.packets[0].bg.?);
}
