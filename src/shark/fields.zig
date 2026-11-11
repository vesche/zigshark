const std = @import("std");

pub const FieldInfo = struct {
    name: []u8,
    display: []u8,
    type_name: []u8,

    pub fn deinit(self: *FieldInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.display);
        allocator.free(self.type_name);
    }
};

pub fn parse(allocator: std.mem.Allocator, text: []const u8) ![]FieldInfo {
    var list: std.ArrayList(FieldInfo) = .empty;
    errdefer {
        for (list.items) |*f| f.deinit(allocator);
        list.deinit(allocator);
    }

    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0) continue;

        var parts = std.mem.splitScalar(u8, line, '\t');
        const kind = parts.next() orelse continue;
        if (kind.len != 1 or kind[0] != 'F') continue;

        const display = parts.next() orelse continue;
        const name = parts.next() orelse continue;
        const type_name = parts.next() orelse continue;

        try list.append(allocator, .{
            .name = try allocator.dupe(u8, name),
            .display = try allocator.dupe(u8, display),
            .type_name = try allocator.dupe(u8, type_name),
        });
    }

    return try list.toOwnedSlice(allocator);
}

pub fn filterPrefix(fields: []const FieldInfo, prefix: []const u8) []const FieldInfo {
    if (prefix.len == 0) return fields;
    var start: ?usize = null;
    var end: usize = 0;
    for (fields, 0..) |f, i| {
        if (std.mem.startsWith(u8, f.name, prefix)) {
            if (start == null) start = i;
            end = i + 1;
        } else if (start != null) break;
    }
    const s = start orelse return fields[0..0];
    return fields[s..end];
}

pub fn matchesFilter(field: FieldInfo, prefix: []const u8) bool {
    return std.mem.startsWith(u8, field.name, prefix);
}

test "parse field lines" {
    const alloc = std.testing.allocator;
    const tab = "\t";
    const text =
        "P" ++ tab ++ "Protocols in frame\n" ++
        "F" ++ tab ++ "Frame Number" ++ tab ++ "frame.number" ++ tab ++ "FT_FRAMENUM" ++ tab ++ "frame\n" ++
        "F" ++ tab ++ "Time delta" ++ tab ++ "frame.time_delta" ++ tab ++ "FT_RELATIVE_TIME" ++ tab ++ "frame\n";
    const fields = try parse(alloc, text);
    defer {
        for (fields) |*f| f.deinit(alloc);
        alloc.free(fields);
    }
    try std.testing.expectEqual(@as(usize, 2), fields.len);
    try std.testing.expectEqualStrings("frame.number", fields[0].name);
    try std.testing.expectEqualStrings("Frame Number", fields[0].display);
    try std.testing.expectEqualStrings("FT_FRAMENUM", fields[0].type_name);
}

test "filterPrefix completion" {
    const alloc = std.testing.allocator;
    const tab = "\t";
    const text =
        "F" ++ tab ++ "A" ++ tab ++ "tcp.a" ++ tab ++ "FT_NONE" ++ tab ++ "x\n" ++
        "F" ++ tab ++ "B" ++ tab ++ "tcp.b" ++ tab ++ "FT_NONE" ++ tab ++ "x\n" ++
        "F" ++ tab ++ "C" ++ tab ++ "udp.c" ++ tab ++ "FT_NONE" ++ tab ++ "x\n";
    const fields = try parse(alloc, text);
    defer {
        for (fields) |*f| f.deinit(alloc);
        alloc.free(fields);
    }
    const tcp = filterPrefix(fields, "tcp.");
    try std.testing.expectEqual(@as(usize, 2), tcp.len);
    try std.testing.expect(matchesFilter(tcp[0], "tcp."));
}
