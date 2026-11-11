const std = @import("std");

pub const Conversation = struct {
    addr_a: []u8,
    port_a: ?u16 = null,
    addr_b: []u8,
    port_b: ?u16 = null,
    frames_ab: u64,
    bytes_ab: u64,
    frames_ba: u64,
    bytes_ba: u64,
    frames_total: u64,
    bytes_total: u64,
    rel_start: f64,
    duration: f64,

    pub fn deinit(self: *Conversation, allocator: std.mem.Allocator) void {
        allocator.free(self.addr_a);
        allocator.free(self.addr_b);
    }
};

pub const ParseError = error{
    InvalidRow,
};

pub fn parse(allocator: std.mem.Allocator, text: []const u8) ![]Conversation {
    var list: std.ArrayList(Conversation) = .empty;
    errdefer {
        for (list.items) |*c| c.deinit(allocator);
        list.deinit(allocator);
    }

    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "=")) continue;
        if (std.mem.startsWith(u8, line, "Filter:")) continue;
        if (std.mem.indexOf(u8, line, "Conversations") != null) continue;
        if (std.mem.indexOf(u8, line, "<->") == null and std.mem.indexOf(u8, line, "Address") != null) continue;
        if (std.mem.indexOf(u8, line, "Frames") != null and std.mem.indexOf(u8, line, "Bytes") != null and std.mem.indexOf(u8, line, "<->") == null) continue;
        if (std.mem.indexOf(u8, line, "|") != null and std.mem.indexOf(u8, line, "<->") == null) continue;

        if (parseModernRow(allocator, line)) |row| {
            try list.append(allocator, row);
            continue;
        } else |_| {}

        if (parseLegacyRow(allocator, line)) |row| {
            try list.append(allocator, row);
        } else |_| {}
    }

    return try list.toOwnedSlice(allocator);
}

fn parseEndpoint(allocator: std.mem.Allocator, tok: []const u8) !struct { addr: []u8, port: ?u16 } {
    if (std.mem.lastIndexOfScalar(u8, tok, ':')) |colon| {
        // Avoid splitting IPv6; only treat as port if trailing part is numeric.
        const maybe_port = tok[colon + 1 ..];
        if (std.fmt.parseInt(u16, maybe_port, 10)) |port| {
            return .{
                .addr = try allocator.dupe(u8, tok[0..colon]),
                .port = port,
            };
        } else |_| {}
    }
    return .{
        .addr = try allocator.dupe(u8, tok),
        .port = null,
    };
}

fn parseModernRow(allocator: std.mem.Allocator, line: []const u8) !Conversation {
    const arrow = std.mem.indexOf(u8, line, "<->") orelse return ParseError.InvalidRow;
    const left = std.mem.trim(u8, line[0..arrow], " \t");
    const right_and_rest = std.mem.trim(u8, line[arrow + 3 ..], " \t");
    const sp = std.mem.indexOfScalar(u8, right_and_rest, ' ') orelse return ParseError.InvalidRow;
    const right = std.mem.trim(u8, right_and_rest[0..sp], " \t");
    const stats = std.mem.trim(u8, right_and_rest[sp..], " \t");

    const a = try parseEndpoint(allocator, left);
    errdefer allocator.free(a.addr);
    const b = try parseEndpoint(allocator, right);
    errdefer allocator.free(b.addr);

    var nums: [8]f64 = undefined;
    var ni: usize = 0;
    var iter = std.mem.tokenizeAny(u8, stats, " \t");
    while (iter.next()) |tok| {
        if (std.ascii.eqlIgnoreCase(tok, "bytes") or std.ascii.eqlIgnoreCase(tok, "byte")) continue;
        if (ni >= nums.len) break;
        nums[ni] = std.fmt.parseFloat(f64, tok) catch continue;
        ni += 1;
    }
    if (ni < 8) return ParseError.InvalidRow;

    return .{
        .addr_a = a.addr,
        .port_a = a.port,
        .addr_b = b.addr,
        .port_b = b.port,
        .frames_ab = @intFromFloat(nums[0]),
        .bytes_ab = @intFromFloat(nums[1]),
        .frames_ba = @intFromFloat(nums[2]),
        .bytes_ba = @intFromFloat(nums[3]),
        .frames_total = @intFromFloat(nums[4]),
        .bytes_total = @intFromFloat(nums[5]),
        .rel_start = nums[6],
        .duration = nums[7],
    };
}

fn parseLegacyRow(allocator: std.mem.Allocator, line: []const u8) !Conversation {
    var tokens: [14][]const u8 = undefined;
    var count: usize = 0;
    var iter = std.mem.tokenizeAny(u8, line, " \t");
    while (iter.next()) |tok| : (count += 1) {
        if (count >= tokens.len) return ParseError.InvalidRow;
        tokens[count] = tok;
    }
    if (count < 12) return ParseError.InvalidRow;

    const addr_a = try allocator.dupe(u8, tokens[0]);
    errdefer allocator.free(addr_a);
    const port_a = std.fmt.parseInt(u16, tokens[1], 10) catch null;
    const addr_b = try allocator.dupe(u8, tokens[2]);
    errdefer allocator.free(addr_b);
    const port_b = std.fmt.parseInt(u16, tokens[3], 10) catch null;

    return .{
        .addr_a = addr_a,
        .port_a = port_a,
        .addr_b = addr_b,
        .port_b = port_b,
        .frames_ab = try std.fmt.parseInt(u64, tokens[4], 10),
        .bytes_ab = try std.fmt.parseInt(u64, tokens[5], 10),
        .frames_ba = try std.fmt.parseInt(u64, tokens[6], 10),
        .bytes_ba = try std.fmt.parseInt(u64, tokens[7], 10),
        .frames_total = try std.fmt.parseInt(u64, tokens[8], 10),
        .bytes_total = try std.fmt.parseInt(u64, tokens[9], 10),
        .rel_start = try std.fmt.parseFloat(f64, tokens[10]),
        .duration = try std.fmt.parseFloat(f64, tokens[11]),
    };
}

const legacy_sample =
    \\================================================================================
    \\TCP Conversations
    \\Filter:<no filter>
    \\Address                   Port Address                   Port  Frames Bytes  Frames Bytes Frames Bytes   Start          |
    \\192.168.86.246            42184 52.20.230.126             443       3     258       2     202       5     460     0.000000000         0.0149
;

const modern_sample =
    \\================================================================================
    \\TCP Conversations
    \\Filter:<No Filter>
    \\                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
    \\                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
    \\192.168.86.246:42184       <-> 52.20.230.126:443                1 103 bytes       2 195 bytes       3 298 bytes     0.000000000         0.0149
;

test "parse legacy tcp conversation row" {
    const alloc = std.testing.allocator;
    const result = try parse(alloc, legacy_sample);
    defer {
        for (result) |*c| c.deinit(alloc);
        alloc.free(result);
    }
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("192.168.86.246", result[0].addr_a);
    try std.testing.expectEqual(@as(?u16, 42184), result[0].port_a);
}

test "parse modern tcp conversation row" {
    const alloc = std.testing.allocator;
    const result = try parse(alloc, modern_sample);
    defer {
        for (result) |*c| c.deinit(alloc);
        alloc.free(result);
    }
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("192.168.86.246", result[0].addr_a);
    try std.testing.expectEqual(@as(?u16, 42184), result[0].port_a);
    try std.testing.expectEqualStrings("52.20.230.126", result[0].addr_b);
    try std.testing.expectEqual(@as(?u16, 443), result[0].port_b);
    try std.testing.expectEqual(@as(u64, 3), result[0].frames_total);
    try std.testing.expect(result[0].duration > 0);
}
