const std = @import("std");
const packet = @import("../model/packet.zig");

pub const Severity = enum { err, warning, note, chat, comment, other };

pub const Item = struct {
    severity: Severity,
    group: []u8,
    message: []u8,
    /// Index of this `_ws.expert` node in tree order, before severity sorting.
    occurrence: usize,

    pub fn deinit(self: *Item, allocator: std.mem.Allocator) void {
        allocator.free(self.group);
        allocator.free(self.message);
    }
};

pub fn count(root: *const packet.DetailNode) usize {
    var total: usize = 0;
    walkCount(root, &total);
    return total;
}

pub fn collect(allocator: std.mem.Allocator, root: *const packet.DetailNode) ![]Item {
    var items: std.ArrayList(Item) = .empty;
    errdefer {
        for (items.items) |*item| item.deinit(allocator);
        items.deinit(allocator);
    }
    var occurrence: usize = 0;
    try walkCollect(allocator, root, &items, &occurrence);
    std.mem.sort(Item, items.items, {}, struct {
        fn less(_: void, a: Item, b: Item) bool {
            const ar = @backingInt(a.severity);
            const br = @backingInt(b.severity);
            if (ar != br) return ar < br;
            return a.occurrence < b.occurrence;
        }
    }.less);
    return items.toOwnedSlice(allocator);
}

pub fn label(severity: Severity) []const u8 {
    return switch (severity) {
        .err => "error",
        .warning => "warning",
        .note => "note",
        .chat => "chat",
        .comment => "comment",
        .other => "expert",
    };
}

pub const FileRow = struct {
    severity: Severity,
    summary: []u8,

    pub fn deinit(self: *FileRow, allocator: std.mem.Allocator) void {
        allocator.free(self.summary);
    }
};

/// Rows from `tshark -z expert`. The stat groups by severity and does not
/// include frame numbers; the summary is what a later lookup selects.
pub fn parseFile(allocator: std.mem.Allocator, text: []const u8) ![]FileRow {
    var rows: std.ArrayList(FileRow) = .empty;
    errdefer {
        for (rows.items) |*row| row.deinit(allocator);
        rows.deinit(allocator);
    }
    var severity: Severity = .other;
    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0) continue;
        if (sectionSeverity(line)) |next| {
            severity = next;
            continue;
        }
        const summary = summaryFromStatLine(line) orelse continue;
        try rows.append(allocator, .{
            .severity = severity,
            .summary = try allocator.dupe(u8, summary),
        });
    }
    return rows.toOwnedSlice(allocator);
}

fn sectionSeverity(line: []const u8) ?Severity {
    const name = std.mem.sliceTo(line, ' ');
    if (std.mem.eql(u8, name, "Errors")) return .err;
    if (std.mem.eql(u8, name, "Warns")) return .warning;
    if (std.mem.eql(u8, name, "Notes")) return .note;
    if (std.mem.eql(u8, name, "Chats")) return .chat;
    if (std.mem.eql(u8, name, "Comments")) return .comment;
    return null;
}

fn summaryFromStatLine(line: []const u8) ?[]const u8 {
    if (line.len == 0 or !std.ascii.isDigit(line[0])) return null;
    var index: usize = 0;
    while (index < line.len and std.ascii.isDigit(line[index])) index += 1;
    while (index < line.len and line[index] == ' ') index += 1;
    const rest = line[index..];
    if (rest.len == 0) return null;
    var parts: [3][]const u8 = .{ "", "", "" };
    const columns = splitWideColumns(rest, &parts);
    const summary = switch (columns) {
        0 => return null,
        1 => parts[0],
        2 => parts[1],
        else => parts[2],
    };
    if (summary.len == 0) return null;
    return summary;
}

fn splitWideColumns(line: []const u8, out: *[3][]const u8) usize {
    var columns: usize = 0;
    var index: usize = 0;
    while (index < line.len and columns < 3) {
        while (index < line.len and line[index] == ' ') index += 1;
        if (index >= line.len) break;
        if (columns == 2) {
            out[2] = std.mem.trim(u8, line[index..], " ");
            return 3;
        }
        const start = index;
        while (index < line.len) {
            if (line[index] == ' ' and index + 1 < line.len and line[index + 1] == ' ') break;
            index += 1;
        }
        out[columns] = std.mem.trim(u8, line[start..index], " ");
        columns += 1;
    }
    return columns;
}

fn walkCount(node: *const packet.DetailNode, total: *usize) void {
    if (std.mem.eql(u8, node.name, "_ws.expert")) total.* += 1;
    for (node.children) |*child| walkCount(child, total);
}

fn walkCollect(
    allocator: std.mem.Allocator,
    node: *const packet.DetailNode,
    items: *std.ArrayList(Item),
    occurrence: *usize,
) !void {
    if (std.mem.eql(u8, node.name, "_ws.expert")) {
        const item = try itemFrom(allocator, node, occurrence.*);
        occurrence.* += 1;
        try items.append(allocator, item);
    }
    for (node.children) |*child| try walkCollect(allocator, child, items, occurrence);
}

fn itemFrom(allocator: std.mem.Allocator, node: *const packet.DetailNode, occurrence: usize) !Item {
    var severity_text: []const u8 = "";
    var group_text: []const u8 = "";
    var message_text: []const u8 = "";
    if (parseBanner(node.showname)) |banner| {
        severity_text = banner.severity;
        group_text = banner.group;
        message_text = banner.message;
    }
    for (node.children) |*child| {
        if (std.mem.eql(u8, child.name, "_ws.expert.severity")) {
            severity_text = afterColon(child.showname);
        } else if (std.mem.eql(u8, child.name, "_ws.expert.group")) {
            group_text = afterColon(child.showname);
        } else if (std.mem.eql(u8, child.name, "_ws.expert.message")) {
            const show = std.mem.trim(u8, child.show, " \t\r\n");
            message_text = if (show.len != 0) show else afterColon(child.showname);
        }
    }
    if (message_text.len == 0) message_text = node.showname;
    const message = try oneLine(allocator, message_text);
    errdefer allocator.free(message);
    return .{
        .severity = severityFrom(severity_text),
        .group = try allocator.dupe(u8, std.mem.trim(u8, group_text, " \t")),
        .message = message,
        .occurrence = occurrence,
    };
}

const Banner = struct { severity: []const u8, group: []const u8, message: []const u8 };

fn parseBanner(showname: []const u8) ?Banner {
    const prefix = "Expert Info (";
    if (!std.mem.startsWith(u8, showname, prefix)) return null;
    const rest = showname[prefix.len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
    const close = std.mem.indexOfScalar(u8, rest, ')') orelse return null;
    if (close <= slash) return null;
    var message = std.mem.trim(u8, rest[close + 1 ..], " \t");
    if (std.mem.startsWith(u8, message, ":")) message = std.mem.trim(u8, message[1..], " \t");
    return .{
        .severity = std.mem.trim(u8, rest[0..slash], " \t"),
        .group = std.mem.trim(u8, rest[slash + 1 .. close], " \t"),
        .message = message,
    };
}

fn afterColon(text: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, text, ':')) |colon| {
        return std.mem.trim(u8, text[colon + 1 ..], " \t");
    }
    return std.mem.trim(u8, text, " \t");
}

fn severityFrom(text: []const u8) Severity {
    if (std.ascii.eqlIgnoreCase(text, "error")) return .err;
    if (std.ascii.eqlIgnoreCase(text, "warning") or std.ascii.eqlIgnoreCase(text, "warn")) return .warning;
    if (std.ascii.eqlIgnoreCase(text, "note")) return .note;
    if (std.ascii.eqlIgnoreCase(text, "chat")) return .chat;
    return .other;
}

fn oneLine(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    const out = try allocator.alloc(u8, trimmed.len);
    var length: usize = 0;
    var space = false;
    for (trimmed) |char| {
        if (char == '\r' or char == '\n' or char == '\t') {
            space = length != 0;
            continue;
        }
        if (char == ' ') {
            space = length != 0;
            continue;
        }
        if (space) {
            out[length] = ' ';
            length += 1;
            space = false;
        }
        out[length] = char;
        length += 1;
    }
    if (length == out.len) return out;
    const fitted = try allocator.realloc(out, length);
    return fitted;
}

fn sampleNode(name: []const u8, showname: []const u8, show: []const u8, children: []const packet.DetailNode) packet.DetailNode {
    return .{
        .name = name,
        .showname = showname,
        .show = show,
        .pos = 0,
        .size = 0,
        .children = @constCast(children),
    };
}

test "expert items keep tree order inside a severity and sort errors first" {
    const allocator = std.testing.allocator;
    const chat = sampleNode("_ws.expert", "Expert Info (Chat/Sequence): M-SEARCH * HTTP/1.1\r\n", "", &.{});
    const warning = sampleNode("_ws.expert", "Expert Info (Warning/Malformed): bad checksum", "", &.{});
    const children = [_]packet.DetailNode{ chat, warning };
    const root = sampleNode("frame", "Frame", "", &children);
    try std.testing.expectEqual(@as(usize, 2), count(&root));
    const items = try collect(allocator, &root);
    defer {
        for (items) |*item| {
            var copy = item.*;
            copy.deinit(allocator);
        }
        allocator.free(items);
    }
    try std.testing.expectEqual(Severity.warning, items[0].severity);
    try std.testing.expectEqualStrings("Malformed", items[0].group);
    try std.testing.expectEqualStrings("bad checksum", items[0].message);
    try std.testing.expectEqual(@as(usize, 1), items[0].occurrence);
    try std.testing.expectEqual(Severity.chat, items[1].severity);
    try std.testing.expectEqualStrings("M-SEARCH * HTTP/1.1", items[1].message);
    try std.testing.expectEqual(@as(usize, 0), items[1].occurrence);
}

test "file expert stat keeps severity and summary" {
    const allocator = std.testing.allocator;
    const malformed = std.fmt.allocPrint(allocator, "{d: >12} {s: >10} {s: >18}  {s}", .{
        1,
        "Malformed",
        "TCP",
        "Bad checksum",
    }) catch unreachable;
    defer allocator.free(malformed);
    const bug = std.fmt.allocPrint(allocator, "{d: >12} {s: >10} {s: >18}  {s}", .{
        2,
        "Dissector bug",
        "HTTP",
        "Bad header",
    }) catch unreachable;
    defer allocator.free(bug);
    const text = std.fmt.allocPrint(allocator,
        \\
        \\Errors (1)
        \\=============
        \\   Frequency      Group           Protocol  Summary
        \\{s}
        \\
        \\Warns (2)
        \\=============
        \\   Frequency      Group           Protocol  Summary
        \\{s}
        \\
    , .{ malformed, bug }) catch unreachable;
    defer allocator.free(text);
    const rows = try parseFile(allocator, text);
    defer {
        for (rows) |*row| {
            var copy = row.*;
            copy.deinit(allocator);
        }
        allocator.free(rows);
    }
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqual(Severity.err, rows[0].severity);
    try std.testing.expectEqualStrings("Bad checksum", rows[0].summary);
    try std.testing.expectEqual(Severity.warning, rows[1].severity);
    try std.testing.expectEqualStrings("Bad header", rows[1].summary);
}

test "a severity child overrides the expert banner" {
    const allocator = std.testing.allocator;
    const severity = sampleNode("_ws.expert.severity", "Severity level: Error", "16777216", &.{});
    const children = [_]packet.DetailNode{severity};
    const expert = sampleNode("_ws.expert", "Expert Info (Chat/Sequence): hello", "", &children);
    const root_children = [_]packet.DetailNode{expert};
    const root = sampleNode("frame", "", "", &root_children);
    const items = try collect(allocator, &root);
    defer {
        for (items) |*item| {
            var copy = item.*;
            copy.deinit(allocator);
        }
        allocator.free(items);
    }
    try std.testing.expectEqual(Severity.err, items[0].severity);
    try std.testing.expectEqualStrings("hello", items[0].message);
}
