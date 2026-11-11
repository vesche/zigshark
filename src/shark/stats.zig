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

pub const IoBucket = struct {
    start: f64,
    end: f64,
    frames: u64,
    bytes: u64,
};

pub const TableRow = struct {
    label: []u8,
    filter: []u8,

    pub fn deinit(self: *TableRow, allocator: std.mem.Allocator) void {
        allocator.free(self.label);
        allocator.free(self.filter);
    }
};

pub fn parseIoStat(allocator: std.mem.Allocator, text: []const u8) ![]IoBucket {
    var rows: std.ArrayList(IoBucket) = .empty;
    errdefer rows.deinit(allocator);
    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        var parts = std.mem.splitScalar(u8, raw, '|');
        _ = parts.next();
        const interval = std.mem.trim(u8, parts.next() orelse continue, " \t");
        const split = std.mem.indexOf(u8, interval, "<>") orelse continue;
        const frames = parseCount(std.mem.trim(u8, parts.next() orelse continue, " \t")) orelse continue;
        const bytes = parseCount(std.mem.trim(u8, parts.next() orelse continue, " \t")) orelse continue;
        const start = std.fmt.parseFloat(f64, std.mem.trim(u8, interval[0..split], " \t")) catch continue;
        const end = std.fmt.parseFloat(f64, std.mem.trim(u8, interval[split + 2 ..], " \t")) catch continue;
        try rows.append(allocator, .{ .start = start, .end = end, .frames = frames, .bytes = bytes });
    }
    return rows.toOwnedSlice(allocator);
}

pub fn parseDnsTable(allocator: std.mem.Allocator, text: []const u8) ![]TableRow {
    var rows: std.ArrayList(TableRow) = .empty;
    errdefer {
        for (rows.items) |*row| row.deinit(allocator);
        rows.deinit(allocator);
    }
    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        if (raw.len == 0) continue;
        var fields = std.mem.splitScalar(u8, raw, '\t');
        const frame = std.fmt.parseInt(u32, fields.next() orelse continue, 10) catch continue;
        const name = fields.next() orelse "";
        const rcode = fields.next() orelse "";
        if (name.len == 0 and rcode.len == 0) continue;
        const filter = if (name.len != 0)
            try quoteFilter(allocator, "dns.qry.name", name)
        else
            try std.fmt.allocPrint(allocator, "frame.number == {d}", .{frame});
        errdefer allocator.free(filter);
        const label = try std.fmt.allocPrint(allocator, "{d}  {s}  {s}", .{ frame, name, rcode });
        try rows.append(allocator, .{ .label = label, .filter = filter });
    }
    return rows.toOwnedSlice(allocator);
}

pub fn parseHttpTable(allocator: std.mem.Allocator, text: []const u8) ![]TableRow {
    var rows: std.ArrayList(TableRow) = .empty;
    errdefer {
        for (rows.items) |*row| row.deinit(allocator);
        rows.deinit(allocator);
    }
    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        if (raw.len == 0) continue;
        var fields = std.mem.splitScalar(u8, raw, '\t');
        const frame = std.fmt.parseInt(u32, fields.next() orelse continue, 10) catch continue;
        const method = fields.next() orelse "";
        const host = fields.next() orelse "";
        const uri = fields.next() orelse "";
        const code = fields.next() orelse "";
        if (method.len == 0 and host.len == 0 and uri.len == 0 and code.len == 0) continue;
        const filter = if (host.len != 0)
            try quoteFilter(allocator, "http.host", host)
        else if (method.len != 0)
            try quoteFilter(allocator, "http.request.method", method)
        else
            try std.fmt.allocPrint(allocator, "frame.number == {d}", .{frame});
        errdefer allocator.free(filter);
        const what = if (method.len != 0) method else code;
        const label = try std.fmt.allocPrint(allocator, "{d}  {s}  {s}{s}", .{ frame, what, host, uri });
        try rows.append(allocator, .{ .label = label, .filter = filter });
    }
    return rows.toOwnedSlice(allocator);
}

pub fn compareIdentities(allocator: std.mem.Allocator, here: []const u8, there: []const u8) ![]TableRow {
    const here_rows = try identityLines(allocator, here);
    defer freeIdentities(allocator, here_rows);
    const there_rows = try identityLines(allocator, there);
    defer freeIdentities(allocator, there_rows);
    var rows: std.ArrayList(TableRow) = .empty;
    errdefer {
        for (rows.items) |*row| row.deinit(allocator);
        rows.deinit(allocator);
    }
    for (here_rows) |item| {
        if (identityHas(there_rows, item.key)) continue;
        const filter = try std.fmt.allocPrint(allocator, "frame.number == {d}", .{item.frame});
        errdefer allocator.free(filter);
        const label = try std.fmt.allocPrint(allocator, "only here  {d}  {s}", .{ item.frame, item.key });
        try rows.append(allocator, .{ .label = label, .filter = filter });
    }
    for (there_rows) |item| {
        if (identityHas(here_rows, item.key)) continue;
        const label = try std.fmt.allocPrint(allocator, "only there  {d}  {s}", .{ item.frame, item.key });
        const filter = try allocator.dupe(u8, "");
        try rows.append(allocator, .{ .label = label, .filter = filter });
    }
    return rows.toOwnedSlice(allocator);
}

const Identity = struct {
    frame: u32,
    key: []u8,
};

fn identityLines(allocator: std.mem.Allocator, text: []const u8) ![]Identity {
    var rows: std.ArrayList(Identity) = .empty;
    errdefer {
        for (rows.items) |item| allocator.free(item.key);
        rows.deinit(allocator);
    }
    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        if (raw.len == 0) continue;
        const tab = std.mem.indexOfScalar(u8, raw, '\t') orelse continue;
        const frame = std.fmt.parseInt(u32, raw[0..tab], 10) catch continue;
        const key = try allocator.dupe(u8, raw[tab + 1 ..]);
        try rows.append(allocator, .{ .frame = frame, .key = key });
    }
    return rows.toOwnedSlice(allocator);
}

fn freeIdentities(allocator: std.mem.Allocator, rows: []Identity) void {
    for (rows) |item| allocator.free(item.key);
    allocator.free(rows);
}

fn identityHas(rows: []const Identity, key: []const u8) bool {
    for (rows) |item| if (std.mem.eql(u8, item.key, key)) return true;
    return false;
}

fn quoteFilter(allocator: std.mem.Allocator, field: []const u8, value: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, field);
    try out.appendSlice(allocator, " == \"");
    for (value) |char| {
        if (char == '\\' or char == '"') try out.append(allocator, '\\');
        try out.append(allocator, char);
    }
    try out.append(allocator, '"');
    return out.toOwnedSlice(allocator);
}

pub fn ioMarks(frames: u64, max_frames: u64, width: usize) usize {
    if (max_frames == 0 or frames == 0 or width == 0) return 0;
    const scaled = frames * width / max_frames;
    return @max(scaled, 1);
}

const io_sample =
    \\| IO Statistics |
    \\| Interval   | Frames | Bytes |
    \\| 0.0 <> 0.1 |      3 |   298 |
    \\| 0.1 <> 0.2 |      0 |     0 |
    \\| 0.6 <> 0.7 |      5 |   838 |
;

test "io stat intervals and a scaled bar" {
    const allocator = std.testing.allocator;
    const rows = try parseIoStat(allocator, io_sample);
    defer allocator.free(rows);
    try std.testing.expectEqual(@as(usize, 3), rows.len);
    try std.testing.expectEqual(@as(u64, 5), rows[2].frames);
    try std.testing.expectEqual(@as(usize, 16), ioMarks(5, 5, 16));
    try std.testing.expectEqual(@as(usize, 3), ioMarks(1, 5, 16));
}

test "dns and http rows become display filters" {
    const allocator = std.testing.allocator;
    const dns = try parseDnsTable(allocator, "4\texample.com\tNo error\n");
    defer {
        for (dns) |*row| {
            var copy = row.*;
            copy.deinit(allocator);
        }
        allocator.free(dns);
    }
    try std.testing.expectEqualStrings("dns.qry.name == \"example.com\"", dns[0].filter);

    const http = try parseHttpTable(allocator, "7\tM-SEARCH\t\t*\t\n11\t\t\t\t200\n");
    defer {
        for (http) |*row| {
            var copy = row.*;
            copy.deinit(allocator);
        }
        allocator.free(http);
    }
    try std.testing.expectEqual(@as(usize, 2), http.len);
    try std.testing.expectEqualStrings("http.request.method == \"M-SEARCH\"", http[0].filter);
    try std.testing.expectEqualStrings("frame.number == 11", http[1].filter);
}

test "compare reports identities that are only on one side" {
    const allocator = std.testing.allocator;
    const here = "1\t10.0.0.1\t10.0.0.2\t80\n2\t10.0.0.9\t10.0.0.8\t53\n";
    const there = "9\t10.0.0.1\t10.0.0.2\t80\n4\t10.1.1.1\t10.1.1.2\t443\n";
    const rows = try compareIdentities(allocator, here, there);
    defer {
        for (rows) |*row| {
            var copy = row.*;
            copy.deinit(allocator);
        }
        allocator.free(rows);
    }
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqualStrings("frame.number == 2", rows[0].filter);
    try std.testing.expectEqual(@as(usize, 0), rows[1].filter.len);
    try std.testing.expect(std.mem.indexOf(u8, rows[1].label, "only there") != null);
}
