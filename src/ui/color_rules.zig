const std = @import("std");
const config = @import("../config.zig");

/// First matching profile rule wins. The caller paints tshark's color first and
/// uses this only as an override.
pub fn firstMatch(rules: []const config.Config.ColorRule, protocol: []const u8, columns: []const []const u8) ?config.Config.ColorRule {
    for (rules) |rule| {
        if (ruleMatches(rule.filter, protocol, columns)) return rule;
    }
    return null;
}

pub fn ruleMatches(filter: []const u8, protocol: []const u8, columns: []const []const u8) bool {
    const text = std.mem.trim(u8, filter, " \t");
    if (text.len == 0) return true;
    if (std.ascii.eqlIgnoreCase(text, protocol)) return true;
    if (std.ascii.startsWithIgnoreCase(text, "contains ")) {
        const needle = std.mem.trim(u8, text["contains ".len..], " \t\"");
        if (needle.len == 0) return false;
        for (columns) |column| {
            if (containsIgnore(column, needle)) return true;
        }
        return false;
    }
    return false;
}

fn containsIgnore(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > haystack.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[index..][0..needle.len], needle)) return true;
    }
    return false;
}

test "color rules keep file order and sit above a default color" {
    const dns = config.Config.ColorRule{
        .name = @constCast("dns"),
        .filter = @constCast("dns"),
        .fg = .{ .r = 1, .g = 1, .b = 1 },
        .bg = .{ .r = 2, .g = 2, .b = 2 },
    };
    const later = config.Config.ColorRule{
        .name = @constCast("any"),
        .filter = @constCast(""),
        .fg = .{ .r = 9, .g = 9, .b = 9 },
        .bg = null,
    };
    const rules = [_]config.Config.ColorRule{ dns, later };
    const columns = [_][]const u8{ "3", "dns", "query" };
    const matched = firstMatch(&rules, "DNS", &columns).?;
    try std.testing.expectEqualStrings("dns", matched.name);
    try std.testing.expect(ruleMatches("contains 443", "TCP", &.{ "66", "42184 → 443" }));
    try std.testing.expect(!ruleMatches("contains 443", "UDP", &.{"53"}));
    try std.testing.expect(ruleMatches("", "ARP", &.{}));
}
