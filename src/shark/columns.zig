const std = @import("std");

pub const ColumnFormat = struct {
    fmt: []u8,
    description: []u8,
    field: ?[]u8 = null,

    pub fn deinit(self: *ColumnFormat, allocator: std.mem.Allocator) void {
        allocator.free(self.fmt);
        allocator.free(self.description);
        if (self.field) |f| allocator.free(f);
    }
};

pub const ParseError = error{
    InvalidLine,
};

pub fn parse(allocator: std.mem.Allocator, text: []const u8) ![]ColumnFormat {
    var list: std.ArrayList(ColumnFormat) = .empty;
    errdefer {
        for (list.items) |*c| c.deinit(allocator);
        list.deinit(allocator);
    }

    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0) continue;
        if (line[0] != '%') continue;

        var fields = std.mem.splitScalar(u8, line, '\t');
        const fmt = fields.next() orelse continue;
        const desc = fields.next() orelse return ParseError.InvalidLine;
        const optional_field = fields.next();

        var entry: ColumnFormat = .{
            .fmt = try allocator.dupe(u8, fmt),
            .description = try allocator.dupe(u8, desc),
        };
        if (optional_field) |f| {
            const trimmed = std.mem.trim(u8, f, " \t");
            if (trimmed.len > 0) {
                entry.field = try allocator.dupe(u8, trimmed);
            }
        }
        try list.append(allocator, entry);
    }

    return try list.toOwnedSlice(allocator);
}

test "three tab-separated fields" {
    const alloc = std.testing.allocator;
    const text = "%t" ++ "\t" ++ "Time" ++ "\t" ++ "frame.time\n";
    const cols = try parse(alloc, text);
    defer {
        for (cols) |*c| c.deinit(alloc);
        alloc.free(cols);
    }
    try std.testing.expectEqual(@as(usize, 1), cols.len);
    try std.testing.expectEqualStrings("%t", cols[0].fmt);
    try std.testing.expectEqualStrings("Time", cols[0].description);
    try std.testing.expectEqualStrings("frame.time", cols[0].field.?);
}

test "two tab-separated fields (modern tshark)" {
    const alloc = std.testing.allocator;
    const text = "%i" ++ "\t" ++ "Source address\n";
    const cols = try parse(alloc, text);
    defer {
        for (cols) |*c| c.deinit(alloc);
        alloc.free(cols);
    }
    try std.testing.expectEqual(@as(usize, 1), cols.len);
    try std.testing.expect(cols[0].field == null);
}

test "multiple lines" {
    const alloc = std.testing.allocator;
    const text =
        "%i" ++ "\t" ++ "Source address\n" ++
        "%ds" ++ "\t" ++ "Destination address\n" ++
        "%m" ++ "\t" ++ "Destination host\n";
    const cols = try parse(alloc, text);
    defer {
        for (cols) |*c| c.deinit(alloc);
        alloc.free(cols);
    }
    try std.testing.expectEqual(@as(usize, 3), cols.len);
}
