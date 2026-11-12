const std = @import("std");

pub const Direction = enum { client, server };

pub const Chunk = struct {
    direction: Direction,
    data: []u8,
    /// Frame number from a follow format that carries one. Null means the jump is a payload guess.
    frame: ?u32 = null,

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

/// `tshark -z follow,<proto>,yaml,<n>` lists `packet:` as the capture frame number.
pub fn parseYaml(allocator: std.mem.Allocator, text: []const u8) !StreamFollow {
    var chunks: std.ArrayList(Chunk) = .empty;
    errdefer {
        for (chunks.items) |*chunk| chunk.deinit(allocator);
        chunks.deinit(allocator);
    }

    var frame: ?u32 = null;
    var direction: Direction = .client;
    var in_packet = false;
    var collecting = false;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "- packet:")) {
            if (in_packet) try finishYamlPacket(allocator, &chunks, frame, direction, encoded.items);
            encoded.clearRetainingCapacity();
            frame = std.fmt.parseInt(u32, std.mem.trim(u8, line["- packet:".len..], " \t"), 10) catch null;
            direction = .client;
            in_packet = true;
            collecting = false;
            continue;
        }
        if (!in_packet) continue;
        if (std.mem.startsWith(u8, line, "peer:")) {
            const peer = std.mem.trim(u8, line["peer:".len..], " \t");
            direction = if (std.mem.eql(u8, peer, "1")) .server else .client;
            collecting = false;
            continue;
        }
        if (std.mem.startsWith(u8, line, "data:")) {
            collecting = true;
            continue;
        }
        if (collecting and isBase64Line(line)) {
            try encoded.appendSlice(allocator, line);
            continue;
        }
        collecting = false;
    }
    if (in_packet) try finishYamlPacket(allocator, &chunks, frame, direction, encoded.items);
    if (chunks.items.len == 0) return ParseError.InvalidStream;

    return .{
        .filter = try allocator.dupe(u8, ""),
        .node0 = try allocator.dupe(u8, ""),
        .node1 = try allocator.dupe(u8, ""),
        .chunks = try chunks.toOwnedSlice(allocator),
    };
}

fn finishYamlPacket(
    allocator: std.mem.Allocator,
    chunks: *std.ArrayList(Chunk),
    frame: ?u32,
    direction: Direction,
    encoded: []const u8,
) !void {
    const data = decodeBase64(allocator, encoded) catch try allocator.alloc(u8, 0);
    try chunks.append(allocator, .{ .direction = direction, .data = data, .frame = frame });
}

fn isBase64Line(line: []const u8) bool {
    if (line.len == 0) return false;
    for (line) |char| {
        const ok = std.ascii.isAlphanumeric(char) or char == '+' or char == '/' or char == '=';
        if (!ok) return false;
    }
    return true;
}

fn decodeBase64(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    if (encoded.len == 0) return try allocator.alloc(u8, 0);
    const decoder = std.base64.standard.Decoder;
    const len = try decoder.calcSizeForSlice(encoded);
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    try decoder.decode(out, encoded);
    return out;
}

pub const sequence_line_width: usize = 40;

/// One fixed-width line. The client is on the left and ends in `>`. The server
/// is on the right and starts with `<`. A missing frame number leaves that
/// side unlabeled. Payload bytes that are not printable ASCII become `.`.
pub fn writeSequenceLine(
    writer: *std.Io.Writer,
    direction: Direction,
    data: []const u8,
    frame: ?u32,
) !void {
    var line: [sequence_line_width]u8 = @splat(' ');
    var preview_buf: [12]u8 = undefined;
    const preview = sequencePreview(data, &preview_buf);
    if (direction == .client) {
        const frame_width = 10;
        if (frame) |number| {
            var frame_buf: [10]u8 = undefined;
            const printed = try std.fmt.bufPrint(&frame_buf, "{d:>10}", .{number});
            const n = @min(printed.len, frame_width);
            @memcpy(line[0..n], printed[0..n]);
        }
        const start: usize = frame_width + 1;
        const arrow: usize = sequence_line_width - 1;
        const n = @min(preview.len, arrow - start);
        @memcpy(line[start..][0..n], preview[0..n]);
        for (line[start + n .. arrow]) |*cell| cell.* = '-';
        line[arrow] = '>';
    } else {
        var suffix_buf: [24]u8 = undefined;
        const suffix = if (frame) |number|
            try std.fmt.bufPrint(&suffix_buf, "{s} {d}", .{ preview, number })
        else
            preview;
        const n = @min(suffix.len, sequence_line_width - 1);
        const shown = suffix[suffix.len - n ..];
        const at = sequence_line_width - n;
        line[0] = '<';
        var index: usize = 1;
        while (index < at) : (index += 1) line[index] = '-';
        if (n != 0) @memcpy(line[at..][0..n], shown);
    }
    try writer.writeAll(&line);
}

pub fn sequenceDiagram(allocator: std.mem.Allocator, chunks: []const Chunk) ![]u8 {
    var text: std.Io.Writer.Allocating = .init(allocator);
    errdefer text.deinit();
    for (chunks, 0..) |chunk, index| {
        if (index != 0) try text.writer.writeByte('\n');
        try writeSequenceLine(&text.writer, chunk.direction, chunk.data, chunk.frame);
    }
    return text.toOwnedSlice();
}

fn sequencePreview(data: []const u8, buf: []u8) []const u8 {
    const n = @min(data.len, buf.len);
    for (data[0..n], 0..) |byte, index| {
        buf[index] = if (std.ascii.isPrint(byte)) byte else '.';
    }
    return buf[0..n];
}

pub fn frameContainsFilter(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try writer.writer.writeAll("frame contains ");
    const limit = @min(bytes.len, 8);
    for (bytes[0..limit], 0..) |byte, index| {
        if (index != 0) try writer.writer.writeByte(':');
        try writer.writer.print("{x:0>2}", .{byte});
    }
    return writer.toOwnedSlice();
}

test "sequence diagram keeps the client on the left" {
    const alloc = std.testing.allocator;
    const hello = try alloc.dupe(u8, "Hello");
    defer alloc.free(hello);
    const world = try alloc.dupe(u8, "World");
    defer alloc.free(world);
    const bang = try alloc.dupe(u8, "!\nb");
    defer alloc.free(bang);
    const chunks = [_]Chunk{
        .{ .direction = .client, .data = hello, .frame = 12 },
        .{ .direction = .server, .data = world, .frame = 13 },
        .{ .direction = .client, .data = bang, .frame = null },
    };

    const body = try sequenceDiagram(alloc, &chunks);
    defer alloc.free(body);
    var lines = std.mem.splitScalar(u8, body, '\n');
    const client = lines.next() orelse return error.MissingLine;
    const server = lines.next() orelse return error.MissingLine;
    const unlabeled = lines.next() orelse return error.MissingLine;
    try std.testing.expect(lines.next() == null);

    try std.testing.expectEqual(sequence_line_width, client.len);
    try std.testing.expectEqual(sequence_line_width, server.len);
    try std.testing.expectEqual(sequence_line_width, unlabeled.len);
    try std.testing.expect(client[client.len - 1] == '>');
    try std.testing.expect(server[0] == '<');
    try std.testing.expect(unlabeled[unlabeled.len - 1] == '>');

    const hello_at = std.mem.indexOf(u8, client, "Hello") orelse return error.MissingPayload;
    const world_at = std.mem.indexOf(u8, server, "World") orelse return error.MissingPayload;
    try std.testing.expect(hello_at < sequence_line_width / 2);
    try std.testing.expect(world_at > sequence_line_width / 2);
    try std.testing.expect(std.mem.indexOf(u8, client, "12") != null);
    try std.testing.expect(std.mem.indexOf(u8, server, "13") != null);
    try std.testing.expect(std.mem.indexOfAny(u8, unlabeled, "0123456789") == null);
    try std.testing.expect(std.mem.indexOf(u8, unlabeled, "!.b") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, unlabeled, '\n') == null);
}

test "frame contains filter uses the first bytes" {
    const alloc = std.testing.allocator;
    const filter = try frameContainsFilter(alloc, "Hello");
    defer alloc.free(filter);
    try std.testing.expectEqualStrings("frame contains 48:65:6c:6c:6f", filter);
}

const yaml_sample =
    \\peers:
    \\  - peer: 0
    \\    host: 10.0.0.1
    \\    port: 80
    \\packets:
    \\  - packet: 12
    \\    peer: 0
    \\    data: !!binary |
    \\      SGVsbG8=
    \\  - packet: 13
    \\    peer: 1
    \\    data: !!binary |
    \\      V29ybGQ=
;

test "yaml follow records the frame number" {
    const alloc = std.testing.allocator;
    var sf = try parseYaml(alloc, yaml_sample);
    defer sf.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), sf.chunks.len);
    try std.testing.expectEqual(@as(?u32, 12), sf.chunks[0].frame);
    try std.testing.expect(sf.chunks[0].direction == .client);
    try std.testing.expectEqualSlices(u8, "Hello", sf.chunks[0].data);
    try std.testing.expectEqual(@as(?u32, 13), sf.chunks[1].frame);
    try std.testing.expect(sf.chunks[1].direction == .server);
    try std.testing.expectEqualSlices(u8, "World", sf.chunks[1].data);
    try std.testing.expectError(ParseError.InvalidStream, parseYaml(alloc, sample));
}

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
