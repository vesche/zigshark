const std = @import("std");
const pdml = @import("../shark/pdml.zig");
const psml = @import("../shark/psml.zig");

pub const Color = struct {
    r: u8,
    g: u8,
    b: u8,
};

pub const HighlightRange = struct {
    offset: usize,
    length: usize,
};

pub const Selection = struct {
    frame: u32,
    field_path: ?[]const u8 = null,
    byte_range: ?HighlightRange = null,
};

pub const PacketSummary = struct {
    frame: u32,
    columns: [][]const u8,
    owns_columns: bool = true,
    fg_color: ?Color = null,
    bg_color: ?Color = null,

    pub fn deinit(self: *PacketSummary, allocator: std.mem.Allocator) void {
        if (!self.owns_columns) return;
        for (self.columns) |c| allocator.free(c);
        allocator.free(self.columns);
    }
};

pub const DetailNode = struct {
    name: []const u8,
    showname: []const u8,
    show: []const u8,
    pos: usize,
    size: usize,
    children: []DetailNode,

    pub fn deinit(self: *DetailNode, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.showname);
        allocator.free(self.show);
        for (self.children) |*c| c.deinit(allocator);
        allocator.free(self.children);
    }
};

pub const PacketDetail = struct {
    frame: u32,
    root: DetailNode,

    pub fn deinit(self: *PacketDetail, allocator: std.mem.Allocator) void {
        self.root.deinit(allocator);
    }
};

pub const PacketBytes = struct {
    frame: u32,
    raw: []u8,
    hexdump_lines: [][]const u8,

    pub fn deinit(self: *PacketBytes, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
        for (self.hexdump_lines) |l| allocator.free(l);
        allocator.free(self.hexdump_lines);
    }
};

pub const DetailBundle = struct {
    pdml: PacketDetail,
    bytes: PacketBytes,

    pub fn deinit(self: *DetailBundle, allocator: std.mem.Allocator) void {
        self.pdml.deinit(allocator);
        self.bytes.deinit(allocator);
    }

    pub fn clone(self: DetailBundle, allocator: std.mem.Allocator) !DetailBundle {
        return .{
            .pdml = try cloneDetail(allocator, self.pdml),
            .bytes = try cloneBytes(allocator, self.bytes),
        };
    }
};

fn cloneDetail(allocator: std.mem.Allocator, detail: PacketDetail) !PacketDetail {
    return .{
        .frame = detail.frame,
        .root = try cloneNode(allocator, detail.root),
    };
}

fn cloneNode(allocator: std.mem.Allocator, node: DetailNode) !DetailNode {
    const children = try allocator.alloc(DetailNode, node.children.len);
    for (node.children, 0..) |c, i| children[i] = try cloneNode(allocator, c);
    return .{
        .name = try allocator.dupe(u8, node.name),
        .showname = try allocator.dupe(u8, node.showname),
        .show = try allocator.dupe(u8, node.show),
        .pos = node.pos,
        .size = node.size,
        .children = children,
    };
}

fn cloneBytes(allocator: std.mem.Allocator, bytes: PacketBytes) !PacketBytes {
    const lines = try allocator.alloc([]const u8, bytes.hexdump_lines.len);
    for (bytes.hexdump_lines, 0..) |l, i| lines[i] = try allocator.dupe(u8, l);
    return .{
        .frame = bytes.frame,
        .raw = try allocator.dupe(u8, bytes.raw),
        .hexdump_lines = lines,
    };
}

pub const PsmlTable = struct {
    headers: [][]u8 = &.{},
    packets: []PacketSummary = &.{},
    /// A later chunk of the same tshark run. The caller appends instead of replacing.
    append: bool = false,
    /// Which `requestPsml` produced this table. Zero means the caller did not tag it.
    generation: u64 = 0,

    pub fn deinit(self: *PsmlTable, allocator: std.mem.Allocator) void {
        for (self.headers) |header| allocator.free(header);
        if (self.headers.len != 0) allocator.free(self.headers);
        for (self.packets) |*summary| summary.deinit(allocator);
        if (self.packets.len != 0) allocator.free(self.packets);
    }
};

/// Parse PSML (packet list) output into summaries and column titles.
/// Drop summaries at or before `frame`, freeing them. The returned slice is a new allocation.
pub fn retainFramesAfter(allocator: std.mem.Allocator, packets: []PacketSummary, frame: u32) ![]PacketSummary {
    var keep: usize = 0;
    for (packets) |summary| {
        if (summary.frame > frame) keep += 1;
    }
    if (keep == packets.len) return packets;
    const kept = try allocator.alloc(PacketSummary, keep);
    var index: usize = 0;
    for (packets) |*summary| {
        if (summary.frame > frame) {
            kept[index] = summary.*;
            index += 1;
        } else {
            summary.deinit(allocator);
        }
    }
    allocator.free(packets);
    return kept;
}

pub fn parsePsml(allocator: std.mem.Allocator, xml: []const u8) !PsmlTable {
    var document = try psml.parse(allocator, xml);
    const headers = document.headers;
    document.headers = &.{};
    errdefer {
        for (headers) |header| allocator.free(header);
        if (headers.len != 0) allocator.free(headers);
    }
    defer document.deinit(allocator);

    const summaries = try allocator.alloc(PacketSummary, document.packets.len);
    var initialized: usize = 0;
    errdefer {
        for (summaries[0..initialized]) |*summary| summary.deinit(allocator);
        allocator.free(summaries);
    }

    for (document.packets, 0..) |*source, i| {
        const columns = try allocator.alloc([]const u8, source.columns.len);
        for (source.columns, 0..) |column, column_index| {
            columns[column_index] = column;
        }
        allocator.free(source.columns);
        source.columns = &.{};

        summaries[i] = .{
            .frame = source.frame_number,
            .columns = columns,
            .fg_color = parseColor(source.fg),
            .bg_color = parseColor(source.bg),
        };
        initialized += 1;
    }
    return .{
        .headers = headers,
        .packets = summaries,
    };
}

pub fn summaryFromPsml(allocator: std.mem.Allocator, source: *psml.Packet) !PacketSummary {
    const columns = try allocator.alloc([]const u8, source.columns.len);
    errdefer allocator.free(columns);
    for (source.columns, 0..) |column, column_index| columns[column_index] = column;
    allocator.free(source.columns);
    source.columns = &.{};
    const summary = PacketSummary{
        .frame = source.frame_number,
        .columns = columns,
        .fg_color = parseColor(source.fg),
        .bg_color = parseColor(source.bg),
    };
    if (source.fg) |color| allocator.free(color);
    if (source.bg) |color| allocator.free(color);
    source.fg = null;
    source.bg = null;
    return summary;
}

fn parseColor(value: ?[]const u8) ?Color {
    const text = value orelse return null;
    if (text.len != 7 or text[0] != '#') return null;
    return .{
        .r = std.fmt.parseInt(u8, text[1..3], 16) catch return null,
        .g = std.fmt.parseInt(u8, text[3..5], 16) catch return null,
        .b = std.fmt.parseInt(u8, text[5..7], 16) catch return null,
    };
}

/// Parse one PDML packet while preserving the protocol/field hierarchy.
pub fn parsePdmlPacket(allocator: std.mem.Allocator, xml: []const u8, frame: u32) !PacketDetail {
    var parsed = try pdml.parseSinglePacket(allocator, xml);
    defer parsed.deinit(allocator);
    return packetDetailFromPdml(allocator, &parsed, frame);
}

pub fn parsePdmlPackets(allocator: std.mem.Allocator, xml: []const u8) ![]PacketDetail {
    const parsed = try pdml.parse(allocator, xml);
    defer pdml.deinitPackets(allocator, parsed);
    const details = try allocator.alloc(PacketDetail, parsed.len);
    var initialized: usize = 0;
    errdefer {
        for (details[0..initialized]) |*detail| detail.deinit(allocator);
        allocator.free(details);
    }
    for (parsed) |*source| {
        details[initialized] = try packetDetailFromPdml(allocator, source, source.frame_number);
        initialized += 1;
    }
    return details;
}

fn packetDetailFromPdml(allocator: std.mem.Allocator, parsed: *const pdml.PacketDetail, frame: u32) !PacketDetail {
    var visible_count: usize = 0;
    for (parsed.nodes) |*node| {
        if (!shouldOmitPdml(node)) visible_count += 1;
    }
    const children = try allocator.alloc(DetailNode, visible_count);
    var initialized: usize = 0;
    errdefer {
        for (children[0..initialized]) |*node| node.deinit(allocator);
        allocator.free(children);
    }
    for (parsed.nodes) |*node| {
        if (shouldOmitPdml(node)) continue;
        children[initialized] = try convertPdmlNode(allocator, node);
        initialized += 1;
    }
    const root = DetailNode{
        .name = try allocator.dupe(u8, "__packet_root"),
        .showname = try allocator.dupe(u8, ""),
        .show = try allocator.dupe(u8, ""),
        .pos = 0,
        .size = 0,
        .children = children,
    };
    return .{
        .frame = if (parsed.frame_number != 0) parsed.frame_number else frame,
        .root = root,
    };
}

fn shouldOmitPdml(node: *const pdml.Node) bool {
    if (node.hide) return true;
    const name = node.name orelse return false;
    return std.mem.eql(u8, name, "geninfo") or std.mem.eql(u8, name, "fake-field-wrapper");
}

fn convertPdmlNode(allocator: std.mem.Allocator, source: *const pdml.Node) !DetailNode {
    var visible: usize = 0;
    for (source.children) |*child| {
        if (!shouldOmitPdml(child)) visible += 1;
    }
    const children = try allocator.alloc(DetailNode, visible);
    var initialized: usize = 0;
    errdefer {
        for (children[0..initialized]) |*node| node.deinit(allocator);
        allocator.free(children);
    }
    for (source.children) |*child| {
        if (shouldOmitPdml(child)) continue;
        children[initialized] = try convertPdmlNode(allocator, child);
        initialized += 1;
    }
    return .{
        .name = try allocator.dupe(u8, source.name orelse if (source.is_proto) "proto" else "field"),
        .showname = try allocator.dupe(u8, source.showname orelse ""),
        .show = try allocator.dupe(u8, source.show orelse source.value orelse ""),
        .pos = source.pos orelse 0,
        .size = source.size orelse 0,
        .children = children,
    };
}

fn appendDumpBytes(allocator: std.mem.Allocator, raw: *std.ArrayList(u8), line: []const u8) !void {
    var parts = std.mem.tokenizeAny(u8, line, " \t");
    const offset = parts.next() orelse return;
    if (offset.len < 4) return;
    for (offset) |char| if (!std.ascii.isHex(char)) return;
    while (parts.next()) |token| {
        if (token.len != 2) break;
        if (!std.ascii.isHex(token[0]) or !std.ascii.isHex(token[1])) break;
        const byte = std.fmt.parseInt(u8, token, 16) catch break;
        try raw.append(allocator, byte);
    }
}

pub fn parseHexdump(allocator: std.mem.Allocator, text: []const u8, frame: u32) !PacketBytes {
    var lines_list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (lines_list.items) |l| allocator.free(l);
        lines_list.deinit(allocator);
    }
    var raw: std.ArrayList(u8) = .empty;
    errdefer raw.deinit(allocator);

    var packet_start = true;
    var line_iter = std.mem.splitScalar(u8, text, '\n');
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) {
            if (!packet_start and raw.items.len > 0) break;
            continue;
        }
        if (std.mem.startsWith(u8, line, "0000")) {
            if (!packet_start and raw.items.len > 0) break;
            packet_start = false;
        }
        try lines_list.append(allocator, try allocator.dupe(u8, line));
        try appendDumpBytes(allocator, &raw, line);
    }

    return .{
        .frame = frame,
        .raw = try raw.toOwnedSlice(allocator),
        .hexdump_lines = try lines_list.toOwnedSlice(allocator),
    };
}

pub fn parseHexdumpPackets(allocator: std.mem.Allocator, text: []const u8) ![]PacketBytes {
    var packets: std.ArrayList(PacketBytes) = .empty;
    errdefer {
        for (packets.items) |*bytes| bytes.deinit(allocator);
        packets.deinit(allocator);
    }

    var lines_list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (lines_list.items) |line| allocator.free(line);
        lines_list.deinit(allocator);
    }
    var raw: std.ArrayList(u8) = .empty;
    errdefer raw.deinit(allocator);

    var line_iter = std.mem.splitScalar(u8, text, '\n');
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        const new_packet = line.len == 0 or (std.mem.startsWith(u8, line, "0000") and raw.items.len > 0);
        if (new_packet and raw.items.len > 0) {
            try packets.append(allocator, .{
                .frame = 0,
                .raw = try raw.toOwnedSlice(allocator),
                .hexdump_lines = try lines_list.toOwnedSlice(allocator),
            });
            lines_list = .empty;
            raw = .empty;
        }
        if (line.len == 0) continue;
        try lines_list.append(allocator, try allocator.dupe(u8, line));
        try appendDumpBytes(allocator, &raw, line);
    }
    if (raw.items.len > 0 or lines_list.items.len > 0) {
        try packets.append(allocator, .{
            .frame = 0,
            .raw = try raw.toOwnedSlice(allocator),
            .hexdump_lines = try lines_list.toOwnedSlice(allocator),
        });
    } else {
        lines_list.deinit(allocator);
        raw.deinit(allocator);
    }
    return try packets.toOwnedSlice(allocator);
}

test "retain frames after a cutoff" {
    const allocator = std.testing.allocator;
    var first = [_][]const u8{"1"};
    var second = [_][]const u8{"2"};
    var third = [_][]const u8{"3"};
    const packets = try allocator.alloc(PacketSummary, 3);
    packets[0] = .{ .frame = 1, .columns = &first, .owns_columns = false };
    packets[1] = .{ .frame = 2, .columns = &second, .owns_columns = false };
    packets[2] = .{ .frame = 4, .columns = &third, .owns_columns = false };
    const kept = try retainFramesAfter(allocator, packets, 2);
    defer allocator.free(kept);
    try std.testing.expectEqual(@as(usize, 1), kept.len);
    try std.testing.expectEqual(@as(u32, 4), kept[0].frame);
}

test "parse psml fixture" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const cwd = std.Io.Dir.cwd();
    const xml = try cwd.readFileAlloc(io, "tests/fixtures/1.psml", allocator, .unlimited);
    defer allocator.free(xml);

    var table = try parsePsml(allocator, xml);
    defer table.deinit(allocator);
    try std.testing.expect(table.packets.len > 0);
    try std.testing.expect(table.headers.len >= 7);
    try std.testing.expectEqual(@as(u32, 1), table.packets[0].frame);
}

test "parse modern PSML packet colors" {
    const allocator = std.testing.allocator;
    const document =
        \\<psml><structure><section>No.</section></structure>
        \\<packet foreground='#12272e' background='#e7e6ff'>
        \\<section>42</section><section>TCP</section>
        \\</packet></psml>
    ;
    var table = try parsePsml(allocator, document);
    defer table.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 42), table.packets[0].frame);
    try std.testing.expectEqual(Color{ .r = 0x12, .g = 0x27, .b = 0x2e }, table.packets[0].fg_color.?);
    try std.testing.expectEqual(Color{ .r = 0xe7, .g = 0xe6, .b = 0xff }, table.packets[0].bg_color.?);
}

test "parse hexdump first packet" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const cwd = std.Io.Dir.cwd();
    const text = try cwd.readFileAlloc(io, "tests/fixtures/1.hexdump", allocator, .unlimited);
    defer allocator.free(text);

    var bytes = try parseHexdump(allocator, text, 1);
    defer bytes.deinit(allocator);
    try std.testing.expect(bytes.raw.len > 0);
    try std.testing.expect(bytes.hexdump_lines.len > 0);
}
