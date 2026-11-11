const std = @import("std");

pub const ParseError = error{
    InvalidLine,
};

/// One captured frame's raw octets from `tshark -x`.
pub const PacketBytes = []u8;

pub fn parse(allocator: std.mem.Allocator, text: []const u8) ![]PacketBytes {
    var packets: std.ArrayList(PacketBytes) = .empty;
    errdefer {
        for (packets.items) |p| allocator.free(p);
        packets.deinit(allocator);
    }

    var chunk: std.ArrayList(u8) = .empty;
    errdefer chunk.deinit(allocator);

    var line_iter = std.mem.splitScalar(u8, text, '\n');
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) {
            if (chunk.items.len > 0) {
                try packets.append(allocator, try chunk.toOwnedSlice(allocator));
                chunk = .empty;
            }
            continue;
        }
        if (!isHexLine(line)) continue;
        try appendHexFromLine(allocator, &chunk, line);
    }
    if (chunk.items.len > 0) {
        try packets.append(allocator, try chunk.toOwnedSlice(allocator));
    }

    return try packets.toOwnedSlice(allocator);
}

fn isHexLine(line: []const u8) bool {
    if (line.len < 4) return false;
    for (line[0..4]) |c| if (!std.ascii.isHex(c)) return false;
    return line[4] == ' ';
}

fn appendHexFromLine(allocator: std.mem.Allocator, chunk: *std.ArrayList(u8), line: []const u8) !void {
    var parts = std.mem.tokenizeAny(u8, line, " \t");
    _ = parts.next(); // offset
    while (parts.next()) |tok| {
        if (tok.len != 2) break;
        if (!std.ascii.isHex(tok[0]) or !std.ascii.isHex(tok[1])) break;
        const byte = try std.fmt.parseInt(u8, tok, 16);
        try chunk.append(allocator, byte);
    }
}

fn readFixture(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const io = std.testing.io;
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited);
}

test "parse hexdump fixture packet count" {
    const alloc = std.testing.allocator;
    const fixture = try readFixture(alloc, "tests/fixtures/1.hexdump");
    defer alloc.free(fixture);
    const pkts = try parse(alloc, fixture);
    defer {
        for (pkts) |p| alloc.free(p);
        alloc.free(pkts);
    }
    try std.testing.expect(pkts.len >= 8);
    try std.testing.expectEqual(@as(usize, 129), pkts[0].len);
    try std.testing.expectEqual(@as(u8, 0x30), pkts[0][0]);
    try std.testing.expectEqual(@as(u8, 0xfd), pkts[0][1]);
}

test "blank line separates packets" {
    const alloc = std.testing.allocator;
    const text =
        \\0000  01 02
        \\
        \\0000  aa
    ;
    const pkts = try parse(alloc, text);
    defer {
        for (pkts) |p| alloc.free(p);
        alloc.free(pkts);
    }
    try std.testing.expectEqual(@as(usize, 2), pkts.len);
    try std.testing.expectEqual(@as(usize, 2), pkts[0].len);
    try std.testing.expectEqual(@as(usize, 1), pkts[1].len);
}
