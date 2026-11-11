const std = @import("std");

pub const ParseError = error{
    UnexpectedEnd,
    MalformedTag,
    MalformedEntity,
    InvalidNumber,
};

/// Skip ASCII whitespace starting at `pos`; returns new index.
pub fn skipWs(input: []const u8, pos: usize) usize {
    var i = pos;
    while (i < input.len and std.ascii.isWhitespace(input[i])) : (i += 1) {}
    return i;
}

/// Find the next `<tag` (case-sensitive) at or after `start`.
pub fn findTagOpen(input: []const u8, start: usize, tag: []const u8) ?usize {
    var i = start;
    while (i < input.len) {
        if (input[i] == '<' and i + 1 + tag.len <= input.len and std.mem.eql(u8, input[i + 1 .. i + 1 + tag.len], tag)) {
            const next = i + 1 + tag.len;
            if (next >= input.len or input[next] == ' ' or input[next] == '>' or input[next] == '/' or input[next] == '\t' or input[next] == '\n' or input[next] == '\r')
                return i;
        }
        i += 1;
    }
    return null;
}

/// End of opening tag (`>` or `/>`), starting at `<`.
pub fn openingTagEnd(input: []const u8, tag_start: usize) ?struct { end: usize, self_closing: bool } {
    var i = tag_start + 1;
    var in_quote: u8 = 0;
    while (i < input.len) : (i += 1) {
        const c = input[i];
        if (in_quote != 0) {
            if (c == in_quote) in_quote = 0;
            continue;
        }
        switch (c) {
            '"', '\'' => in_quote = c,
            '>' => return .{ .end = i + 1, .self_closing = false },
            '/' => {
                if (i + 1 < input.len and input[i + 1] == '>') {
                    return .{ .end = i + 2, .self_closing = true };
                }
            },
            else => {},
        }
    }
    return null;
}

/// Slice of the opening tag from `<` through `>`.
pub fn openingTagSlice(input: []const u8, tag_start: usize) ?[]const u8 {
    const te = openingTagEnd(input, tag_start) orelse return null;
    return input[tag_start..te.end];
}

/// Attribute value inside an opening tag slice (quotes stripped; not entity-unescaped).
pub fn getAttribute(tag_slice: []const u8, attr_name: []const u8) ?[]const u8 {
    const search = tryFindAttrName(tag_slice, attr_name) orelse return null;
    var i = search + attr_name.len;
    while (i < tag_slice.len and std.ascii.isWhitespace(tag_slice[i])) : (i += 1) {}
    if (i >= tag_slice.len or tag_slice[i] != '=') return null;
    i += 1;
    i = skipWs(tag_slice, i);
    if (i >= tag_slice.len) return null;
    const quote = tag_slice[i];
    if (quote != '"' and quote != '\'') return null;
    i += 1;
    const val_start = i;
    while (i < tag_slice.len and tag_slice[i] != quote) : (i += 1) {}
    if (i >= tag_slice.len) return null;
    return tag_slice[val_start..i];
}

fn tryFindAttrName(tag_slice: []const u8, attr_name: []const u8) ?usize {
    var i: usize = 1;
    // Skip the element name (e.g. "packet" in "<packet ...>").
    while (i < tag_slice.len and !std.ascii.isWhitespace(tag_slice[i]) and tag_slice[i] != '>' and tag_slice[i] != '/') : (i += 1) {}
    while (i < tag_slice.len) {
        i = skipWs(tag_slice, i);
        if (i >= tag_slice.len or tag_slice[i] == '>' or tag_slice[i] == '/') break;
        const name_start = i;
        while (i < tag_slice.len and !std.ascii.isWhitespace(tag_slice[i]) and tag_slice[i] != '=' and tag_slice[i] != '>' and tag_slice[i] != '/') : (i += 1) {}
        const name = tag_slice[name_start..i];
        if (std.mem.eql(u8, name, attr_name)) return name_start;
        if (i < tag_slice.len and tag_slice[i] == '=') {
            i += 1;
            i = skipWs(tag_slice, i);
            if (i < tag_slice.len and (tag_slice[i] == '"' or tag_slice[i] == '\'')) {
                const q = tag_slice[i];
                i += 1;
                while (i < tag_slice.len and tag_slice[i] != q) : (i += 1) {}
                if (i < tag_slice.len) i += 1;
            }
        }
    }
    return null;
}

/// Find `</tag>` after `content_start`.
pub fn findCloseTag(input: []const u8, content_start: usize, tag: []const u8) ?usize {
    var needle_buf: [96]u8 = undefined;
    const needle = std.fmt.bufPrint(&needle_buf, "</{s}>", .{tag}) catch return null;
    const idx = std.mem.indexOfPos(u8, input, content_start, needle) orelse return null;
    return idx + needle.len;
}

/// Text content of the first `<tag>...</tag>` after `start` (entity-unescaped).
pub fn findTagContent(allocator: std.mem.Allocator, input: []const u8, start: usize, tag: []const u8) !?[]u8 {
    const open = findTagOpen(input, start, tag) orelse return null;
    const te = openingTagEnd(input, open) orelse return error.MalformedTag;
    if (te.self_closing) return try allocator.dupe(u8, "");
    const content_start = te.end;
    const close_start = std.mem.indexOfPos(u8, input, content_start, "</") orelse return error.UnexpectedEnd;
    const raw = std.mem.trim(u8, input[content_start..close_start], " \t\r\n");
    return try unescapeEntities(allocator, raw);
}

pub fn unescapeEntities(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] != '&') {
            try out.append(allocator, input[i]);
            i += 1;
            continue;
        }
        const semi = std.mem.indexOfScalar(u8, input[i..], ';') orelse return error.MalformedEntity;
        const entity = input[i .. i + semi + 1];
        i += semi + 1;

        if (std.mem.eql(u8, entity, "&amp;")) try out.append(allocator, '&')
        else if (std.mem.eql(u8, entity, "&lt;")) try out.append(allocator, '<')
        else if (std.mem.eql(u8, entity, "&gt;")) try out.append(allocator, '>')
        else if (std.mem.eql(u8, entity, "&quot;")) try out.append(allocator, '"')
        else if (std.mem.eql(u8, entity, "&apos;")) try out.append(allocator, '\'')
        else if (entity.len > 3 and entity[1] == '#') {
            const num_slice = entity[2 .. entity.len - 1];
            const codepoint: u21 = if (num_slice.len > 1 and (num_slice[0] == 'x' or num_slice[0] == 'X'))
                try std.fmt.parseInt(u21, num_slice[1..], 16)
            else
                try std.fmt.parseInt(u21, num_slice, 10);
            var buf: [4]u8 = undefined;
            const len = std.unicode.utf8Encode(codepoint, &buf) catch return error.MalformedEntity;
            try out.appendSlice(allocator, buf[0..len]);
        } else {
            try out.appendSlice(allocator, entity);
        }
    }
    return try out.toOwnedSlice(allocator);
}

/// Decode `\xNN` byte sequences in tshark text columns (PSML).
pub fn decodeEscapedBytes(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < input.len) {
        if (i + 3 < input.len and input[i] == '\\' and input[i + 1] == 'x') {
            const hex = input[i + 2 .. i + 4];
            const byte = try std.fmt.parseInt(u8, hex, 16);
            try out.append(allocator, byte);
            i += 4;
        } else {
            try out.append(allocator, input[i]);
            i += 1;
        }
    }
    return try out.toOwnedSlice(allocator);
}

pub fn parseU32Attr(attr: ?[]const u8) ?u32 {
    const a = attr orelse return null;
    return std.fmt.parseInt(u32, a, 10) catch null;
}

test "unescape numeric and named entities" {
    const alloc = std.testing.allocator;
    const out = try unescapeEntities(alloc, "Don&#x27;t &amp; go");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("Don't & go", out);
}

test "getAttribute and findTagContent" {
    const alloc = std.testing.allocator;
    const xml = "<packet fgcolor=\"#ff0000\" bgcolor=\"#00ff00\"><section>x</section></packet>";
    const open = findTagOpen(xml, 0, "packet").?;
    const tag = openingTagSlice(xml, open).?;
    try std.testing.expectEqualStrings("#ff0000", getAttribute(tag, "fgcolor").?);
    const text = (try findTagContent(alloc, xml, 0, "section")) orelse return error.TestExpectedEqual;
    defer alloc.free(text);
    try std.testing.expectEqualStrings("x", text);
}
