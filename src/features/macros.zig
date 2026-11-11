const std = @import("std");
const config = @import("../config.zig");

/// Expand `$name` tokens using config macros.
pub fn expand(allocator: std.mem.Allocator, cfg: *const config.Config, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '$' and i + 1 < input.len) {
            const end = std.mem.indexOfScalar(u8, input[i + 1 ..], ' ') orelse (input.len - i - 1);
            const name = input[i + 1 .. i + 1 + end];
            var found = false;
            for (cfg.macros.items) |m| {
                if (std.mem.eql(u8, m.name, name)) {
                    try out.appendSlice(allocator, m.value);
                    found = true;
                    break;
                }
            }
            if (!found) try out.append(allocator, '$');
            i += if (found) 1 + name.len else 1;
        } else {
            try out.append(allocator, input[i]);
            i += 1;
        }
    }
    return try out.toOwnedSlice(allocator);
}

test "macro expand" {
    const allocator = std.testing.allocator;
    var cfg = try config.Config.defaults(allocator);
    defer cfg.deinit();
    try cfg.macros.append(allocator, .{
        .name = try allocator.dupe(u8, "host"),
        .value = try allocator.dupe(u8, "10.0.0.1"),
    });
    const expanded = try expand(allocator, &cfg, "ip.addr == $host");
    defer allocator.free(expanded);
    try std.testing.expect(std.mem.indexOf(u8, expanded, "10.0.0.1") != null);
}
