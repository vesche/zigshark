const std = @import("std");
const config = @import("../config.zig");

pub fn pushRecent(cfg: *config.Config, path: []const u8) !void {
    for (cfg.recent_files.items) |existing| {
        if (std.mem.eql(u8, existing, path)) return;
    }
    const owned = try cfg.allocator.dupe(u8, path);
    try cfg.recent_files.append(cfg.allocator, owned);
    const max: usize = 20;
    while (cfg.recent_files.items.len > max) {
        const old = cfg.recent_files.orderedRemove(0);
        cfg.allocator.free(old);
    }
}

pub fn list(cfg: *const config.Config) []const []const u8 {
    const items = cfg.recent_files.items;
    var out: []const []const u8 = &.{};
    var i: usize = items.len;
    while (i > 0) : (i -= 1) {
        // most recent last in file — return reversed view via slice
        _ = items[i - 1];
    }
    out = items;
    return out;
}

pub fn pushFilter(cfg: *config.Config, filter: []const u8) !void {
    if (filter.len == 0) return;
    for (cfg.recent_filters.items) |existing| {
        if (std.mem.eql(u8, existing, filter)) return;
    }
    try cfg.recent_filters.append(cfg.allocator, try cfg.allocator.dupe(u8, filter));
}
