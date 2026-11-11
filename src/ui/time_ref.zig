const std = @import("std");

/// A numeric time column, relative or absolute seconds. A date string is not a number.
pub fn parseSeconds(text: []const u8) ?f64 {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return null;
    for (trimmed) |char| {
        if (std.ascii.isDigit(char)) continue;
        switch (char) {
            '+', '-', '.', 'e', 'E' => continue,
            else => return null,
        }
    }
    return std.fmt.parseFloat(f64, trimmed) catch null;
}

pub fn formatDelta(buffer: []u8, delta: f64) []const u8 {
    if (delta < 0) return std.fmt.bufPrint(buffer, "{d:.6}", .{delta}) catch buffer[0..0];
    return std.fmt.bufPrint(buffer, "+{d:.6}", .{delta}) catch buffer[0..0];
}

pub fn timeText(headers: []const []const u8, columns: []const []const u8) ?[]const u8 {
    if (headers.len == 0) {
        if (columns.len > 1) return columns[1];
        return null;
    }
    for (headers, 0..) |header, index| {
        if (index >= columns.len) break;
        if (std.ascii.findIgnoreCase(header, "delta") != null) continue;
        if (std.ascii.findIgnoreCase(header, "time") != null) return columns[index];
    }
    return null;
}

test "numeric time parses and a date does not" {
    try std.testing.expectEqual(@as(?f64, 1.5), parseSeconds(" 1.5 "));
    try std.testing.expect(parseSeconds("Feb 22, 2019 22:23:01") == null);
    var buffer: [32]u8 = undefined;
    try std.testing.expectEqualStrings("+0.250000", formatDelta(&buffer, 0.25));
    try std.testing.expectEqualStrings("-0.250000", formatDelta(&buffer, -0.25));
    const headers = [_][]const u8{ "No.", "Time", "Delta" };
    const columns = [_][]const u8{ "1", "1.500000", "0.100000" };
    try std.testing.expectEqualStrings("1.500000", timeText(&headers, &columns).?);
}
