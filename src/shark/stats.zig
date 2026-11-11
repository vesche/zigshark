const std = @import("std");

pub const ProtoRow = struct {
    name: []u8,
    frames: u64,
    bytes: u64,

    pub fn deinit(self: *ProtoRow, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};

pub const Endpoint = struct {
    address: []u8,
    port: ?u16 = null,
    packets: u64,
    bytes: u64,

    pub fn deinit(self: *Endpoint, allocator: std.mem.Allocator) void {
        allocator.free(self.address);
    }
};

pub const Kind = enum { tcp, udp, ip, ipv6, eth };

pub fn parseHierarchy(allocator: std.mem.Allocator, text: []const u8) ![]ProtoRow {
    var rows: std.ArrayList(ProtoRow) = .empty;
    errdefer {
        for (rows.items) |*row| row.deinit(allocator);
        rows.deinit(allocator);
    }
    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        const frames_at = std.mem.indexOf(u8, raw, "frames:") orelse continue;
        const name = std.mem.trim(u8, raw[0..frames_at], " \t");
        if (name.len == 0) continue;
        const rest = raw[frames_at + "frames:".len ..];
        const bytes_at = std.mem.indexOf(u8, rest, "bytes:") orelse continue;
        const frames = parseCount(std.mem.trim(u8, rest[0..bytes_at], " \t")) orelse continue;
        const bytes = parseCount(std.mem.trim(u8, rest[bytes_at + "bytes:".len ..], " \t")) orelse continue;
        try rows.append(allocator, .{
            .name = try allocator.dupe(u8, name),
            .frames = frames,
            .bytes = bytes,
        });
    }
    return rows.toOwnedSlice(allocator);
}

pub fn parseEndpoints(allocator: std.mem.Allocator, text: []const u8, kind: Kind) ![]Endpoint {
    var rows: std.ArrayList(Endpoint) = .empty;
    errdefer {
        for (rows.items) |*row| row.deinit(allocator);
        rows.deinit(allocator);
    }
    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0 or line[0] == '=' or std.mem.indexOfScalar(u8, line, '|') != null) continue;
        if (std.mem.indexOf(u8, line, "Filter") != null or std.mem.indexOf(u8, line, "Endpoint") != null) continue;
        var tokens: [16][]const u8 = undefined;
        var count: usize = 0;
        var iter = std.mem.tokenizeAny(u8, line, " \t");
        while (iter.next()) |token| {
            if (count >= tokens.len) break;
            tokens[count] = token;
            count += 1;
        }
        if (count < 3) continue;
        const with_port = kind == .tcp or kind == .udp;
        if (with_port and count < 4) continue;
        const port = if (with_port) std.fmt.parseInt(u16, tokens[1], 10) catch continue else null;
        var index: usize = if (with_port) 2 else 1;
        const packets = nextCount(tokens[0..count], &index) orelse continue;
        const bytes = nextCount(tokens[0..count], &index) orelse continue;
        try rows.append(allocator, .{
            .address = try allocator.dupe(u8, tokens[0]),
            .port = port,
            .packets = packets,
            .bytes = bytes,
        });
    }
    std.mem.sort(Endpoint, rows.items, {}, struct {
        fn louder(_: void, a: Endpoint, b: Endpoint) bool {
            if (a.bytes != b.bytes) return a.bytes > b.bytes;
            return a.packets > b.packets;
        }
    }.louder);
    return rows.toOwnedSlice(allocator);
}

pub fn endpointFilter(allocator: std.mem.Allocator, kind: Kind, row: Endpoint) ![]u8 {
    return switch (kind) {
        .eth => try std.fmt.allocPrint(allocator, "eth.addr == {s}", .{row.address}),
        .ipv6 => try std.fmt.allocPrint(allocator, "ipv6.addr == {s}", .{row.address}),
        .ip => try std.fmt.allocPrint(allocator, "ip.addr == {s}", .{row.address}),
        .tcp => if (row.port) |port|
            try std.fmt.allocPrint(allocator, "ip.addr == {s} and tcp.port == {d}", .{ row.address, port })
        else
            try std.fmt.allocPrint(allocator, "ip.addr == {s}", .{row.address}),
        .udp => if (row.port) |port|
            try std.fmt.allocPrint(allocator, "ip.addr == {s} and udp.port == {d}", .{ row.address, port })
        else
            try std.fmt.allocPrint(allocator, "ip.addr == {s}", .{row.address}),
    };
}

fn nextCount(tokens: []const []const u8, index: *usize) ?u64 {
    while (index.* < tokens.len) {
        const token = tokens[index.*];
        index.* += 1;
        if (std.ascii.eqlIgnoreCase(token, "bytes") or std.ascii.eqlIgnoreCase(token, "byte")) continue;
        if (parseCount(token)) |value| return value;
    }
    return null;
}

fn parseCount(text: []const u8) ?u64 {
    var buf: [32]u8 = undefined;
    var length: usize = 0;
    for (text) |char| {
        if (char == ',') continue;
        if (!std.ascii.isDigit(char)) return null;
        if (length >= buf.len) return null;
        buf[length] = char;
        length += 1;
    }
    if (length == 0) return null;
    return std.fmt.parseInt(u64, buf[0..length], 10) catch null;
}

test "hierarchy keeps protocol rows in file order" {
    const allocator = std.testing.allocator;
    const text =
        \\Protocol Hierarchy Statistics
        \\frame                                    frames:18 bytes:2048
        \\  eth                                    frames:18 bytes:2048
        \\    ip                                   frames:16 bytes:1964
        \\      tcp                                frames:13 bytes:1292
        \\        tls                              frames:8 bytes:962
    ;
    const rows = try parseHierarchy(allocator, text);
    defer {
        for (rows) |*row| {
            var copy = row.*;
            copy.deinit(allocator);
        }
        allocator.free(rows);
    }
    try std.testing.expectEqual(@as(usize, 5), rows.len);
    try std.testing.expectEqualStrings("tcp", rows[3].name);
    try std.testing.expectEqual(@as(u64, 13), rows[3].frames);
    try std.testing.expectEqual(@as(u64, 962), rows[4].bytes);
}

test "endpoints sort by bytes and tcp keeps the port" {
    const allocator = std.testing.allocator;
    const text =
        \\TCP Endpoints
        \\192.168.86.246            42184            3   298 bytes           2      195 bytes            1      103 bytes
        \\52.20.230.126               443            3   100 bytes           1      40 bytes             2      60 bytes
    ;
    const rows = try parseEndpoints(allocator, text, .tcp);
    defer {
        for (rows) |*row| {
            var copy = row.*;
            copy.deinit(allocator);
        }
        allocator.free(rows);
    }
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqualStrings("192.168.86.246", rows[0].address);
    try std.testing.expectEqual(@as(?u16, 42184), rows[0].port);
    const filter = try endpointFilter(allocator, .tcp, rows[0]);
    defer allocator.free(filter);
    try std.testing.expectEqualStrings("ip.addr == 192.168.86.246 and tcp.port == 42184", filter);

    const ip_text = "192.168.86.246                 15   1,821 bytes        10      1,008 bytes          5      813 bytes\n";
    const ip_rows = try parseEndpoints(allocator, ip_text, .ip);
    defer {
        for (ip_rows) |*row| {
            var copy = row.*;
            copy.deinit(allocator);
        }
        allocator.free(ip_rows);
    }
    try std.testing.expectEqual(@as(u64, 1821), ip_rows[0].bytes);
    try std.testing.expect(ip_rows[0].port == null);
}

pub fn listedProtocols(allocator: std.mem.Allocator, text: []const u8, preferred: []const []const u8) ![][]u8 {
    var found = try allocator.alloc(bool, preferred.len);
    defer allocator.free(found);
    @memset(found, false);
    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        var fields = std.mem.splitScalar(u8, raw, '\t');
        _ = fields.next();
        _ = fields.next();
        const short = fields.next() orelse continue;
        for (preferred, 0..) |name, index| {
            if (std.mem.eql(u8, short, name)) found[index] = true;
        }
    }
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |item| allocator.free(item);
        out.deinit(allocator);
    }
    for (preferred, 0..) |name, index| {
        if (found[index]) try out.append(allocator, try allocator.dupe(u8, name));
    }
    return out.toOwnedSlice(allocator);
}
