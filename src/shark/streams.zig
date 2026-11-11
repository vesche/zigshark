const std = @import("std");

pub const Direction = enum { client, server };

pub const Chunk = struct {
    direction: Direction,
    data: []u8,

    pub fn deinit(self: *Chunk, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

pub const StreamFollow = struct {
    filter: []u8,
    node0: []u8,
    node1: []u8,
    chunks: []Chunk,

    pub fn deinit(self: *StreamFollow, allocator: std.mem.Allocator) void {
        allocator.free(self.filter);
        allocator.free(self.node0);
        allocator.free(self.node1);
        for (self.chunks) |*c| c.deinit(allocator);
        allocator.free(self.chunks);
    }
};

pub const ParseError = error{
    InvalidStream,
    InvalidHex,
};

pub fn parse(allocator: std.mem.Allocator, text: []const u8) !StreamFollow {
    var filter: []const u8 = "";
    var node0: []const u8 = "";
    var node1: []const u8 = "";

    var chunks: std.ArrayList(Chunk) = .empty;
    errdefer {
        for (chunks.items) |*c| c.deinit(allocator);
        chunks.deinit(allocator);
    }

    var pending_dir: ?Direction = null;
    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0) continue;

        if (std.mem.startsWith(u8, line, "Filter:")) {
            filter = std.mem.trim(u8, line["Filter:".len..], " \t");
            continue;
        }
        if (std.mem.startsWith(u8, line, "Node 0:")) {
            node0 = std.mem.trim(u8, line["Node 0:".len..], " \t");
            continue;
        }
        if (std.mem.startsWith(u8, line, "Node 1:")) {
            node1 = std.mem.trim(u8, line["Node 1:".len..], " \t");
            continue;
        }
        if (std.mem.startsWith(u8, line, "=")) continue;
        if (std.mem.startsWith(u8, line, "Follow:")) continue;

        if (line.len == 1 and line[0] == '0') {
            pending_dir = .client;
            continue;
        }
        if (line.len == 1 and line[0] == '1') {
            pending_dir = .server;
            continue;
        }

        if (pending_dir) |dir| {
            if (isHexDataLine(line)) {
                const data = try decodeHexLine(allocator, line);
                try chunks.append(allocator, .{ .direction = dir, .data = data });
                pending_dir = null;
            }
        }
    }

    return .{
        .filter = try allocator.dupe(u8, filter),
        .node0 = try allocator.dupe(u8, node0),
        .node1 = try allocator.dupe(u8, node1),
        .chunks = try chunks.toOwnedSlice(allocator),
    };
}

fn isHexDataLine(line: []const u8) bool {
    var parts = std.mem.tokenizeAny(u8, line, " \t");
    const first = parts.next() orelse return false;
    if (first.len < 4) return false;
    for (first) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

fn decodeHexLine(allocator: std.mem.Allocator, line: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var parts = std.mem.tokenizeAny(u8, line, " \t");
    _ = parts.next(); // offset
    while (parts.next()) |tok| {
        if (tok.len != 2) break;
        const byte = std.fmt.parseInt(u8, tok, 16) catch return ParseError.InvalidHex;
        try out.append(allocator, byte);
    }
    return try out.toOwnedSlice(allocator);
}

const sample =
    \\===============================================================================
    \\Follow: tcp,raw
    \\Filter: tcp.stream eq 0
    \\Node 0: 192.168.1.1:12345
    \\Node 1: 10.0.0.1:80
    \\===============================================================================
    \\0
    \\00000000  48 65 6c 6c 6f
    \\1
    \\00000000  57 6f 72 6c 64
;

test "parse follow stream raw" {
    const alloc = std.testing.allocator;
    var sf = try parse(alloc, sample);
    defer sf.deinit(alloc);

    try std.testing.expectEqualStrings("tcp.stream eq 0", sf.filter);
    try std.testing.expectEqualStrings("192.168.1.1:12345", sf.node0);
    try std.testing.expectEqual(@as(usize, 2), sf.chunks.len);
    try std.testing.expect(sf.chunks[0].direction == .client);
    try std.testing.expectEqualSlices(u8, "Hello", sf.chunks[0].data);
    try std.testing.expectEqualSlices(u8, "World", sf.chunks[1].data);
}
