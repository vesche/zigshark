const std = @import("std");
const config = @import("../config.zig");

pub fn pushFilter(cfg: *config.Config, filter: []const u8) !void {
    if (filter.len == 0) return;
    for (cfg.recent_filters.items) |existing| {
        if (std.mem.eql(u8, existing, filter)) return;
    }
    try cfg.recent_filters.append(cfg.allocator, try cfg.allocator.dupe(u8, filter));
}
