const std = @import("std");
const session_mod = @import("session.zig");
const packet = @import("packet.zig");

pub const Kind = enum {
    filter,
    string,
    regex,
    hex,
};

pub const Target = enum {
    list,
    details,
    bytes,
};

pub const SearchState = struct {
    kind: Kind = .string,
    target: Target = .list,
    needle: []u8 = &.{},
    case_sensitive: bool = false,
    last_index: ?usize = null,

    pub fn deinit(self: *SearchState, allocator: std.mem.Allocator) void {
        if (self.needle.len != 0) allocator.free(self.needle);
    }

    pub fn setNeedle(self: *SearchState, allocator: std.mem.Allocator, text: []const u8) !void {
        if (self.needle.len != 0) allocator.free(self.needle);
        self.needle = try allocator.dupe(u8, text);
        self.last_index = null;
    }
};

pub const Hit = struct {
    packet_index: usize,
    column: ?usize = null,
    byte_offset: ?usize = null,
};

fn haystackMatches(haystack: []const u8, needle: []const u8, case_sensitive: bool) bool {
    if (needle.len == 0) return true;
    if (case_sensitive) return std.mem.indexOf(u8, haystack, needle) != null;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

pub fn findNextList(
    sess: *session_mod.Session,
    state: *SearchState,
    forward: bool,
) ?Hit {
    if (state.needle.len == 0 or sess.packets.len == 0) return null;

    const start = state.last_index orelse sess.selected_index orelse 0;
    var i: usize = if (forward) start + 1 else start;
    while (if (forward) i < sess.packets.len else i > 0) {
        const idx = if (forward) blk: {
            const v = i;
            i += 1;
            break :blk v;
        } else blk: {
            i -= 1;
            break :blk i;
        };
        const summary = sess.packets[idx];
        for (summary.columns, 0..) |col, ci| {
            if (haystackMatches(col, state.needle, state.case_sensitive)) {
                state.last_index = idx;
                _ = sess.select(idx);
                return .{ .packet_index = idx, .column = ci };
            }
        }
        if (!forward and idx == 0) break;
    }
    if (forward) {
        i = 0;
        while (i <= start) : (i += 1) {
            const summary = sess.packets[i];
            for (summary.columns, 0..) |col, ci| {
                if (haystackMatches(col, state.needle, state.case_sensitive)) {
                    state.last_index = i;
                    _ = sess.select(i);
                    return .{ .packet_index = i, .column = ci };
                }
            }
        }
    }
    return null;
}

pub fn findNextBytes(bytes: *const packet.PacketBytes, state: *SearchState, from: usize) ?usize {
    if (state.needle.len == 0) return null;
    switch (state.kind) {
        .hex => {
            var off: usize = from;
            while (off < bytes.raw.len) : (off += 1) {
                if (hexMatchesAt(bytes.raw, off, state.needle)) return off;
            }
        },
        else => {
            if (state.needle.len > bytes.raw.len) return null;
            var off: usize = from;
            while (off + state.needle.len <= bytes.raw.len) : (off += 1) {
                const candidate = bytes.raw[off .. off + state.needle.len];
                if (if (state.case_sensitive)
                    std.mem.eql(u8, candidate, state.needle)
                else
                    std.ascii.eqlIgnoreCase(candidate, state.needle))
                {
                    return off;
                }
            }
        },
    }
    return null;
}

fn hexMatchesAt(data: []const u8, offset: usize, needle: []const u8) bool {
    var data_index = offset;
    var high_nibble: ?u4 = null;
    for (needle) |char| {
        const nibble = hexNibble(char) orelse continue;
        if (high_nibble) |high| {
            if (data_index >= data.len) return false;
            const expected: u8 = (@as(u8, high) << 4) | nibble;
            if (data[data_index] != expected) return false;
            data_index += 1;
            high_nibble = null;
        } else {
            high_nibble = nibble;
        }
    }
    return high_nibble == null and data_index > offset;
}

fn hexNibble(char: u8) ?u4 {
    return switch (char) {
        '0'...'9' => @intCast(char - '0'),
        'a'...'f' => @intCast(char - 'a' + 10),
        'A'...'F' => @intCast(char - 'A' + 10),
        else => null,
    };
}

test "search list forward" {
    const allocator = std.testing.allocator;
    var session = session_mod.Session.init(allocator, .{ .file = "/x" });
    defer session.deinit();

    var cols1 = [_][]const u8{ "1", "syn" };
    var cols2 = [_][]const u8{ "2", "ack" };
    var cols3 = [_][]const u8{ "3", "syn retrans" };
    var packets = [_]packet.PacketSummary{
        .{ .frame = 1, .columns = &cols1, .owns_columns = false },
        .{ .frame = 2, .columns = &cols2, .owns_columns = false },
        .{ .frame = 3, .columns = &cols3, .owns_columns = false },
    };
    session.setPacketsBorrowed(&packets);
    _ = session.select(0);

    var state = SearchState{};
    defer state.deinit(allocator);
    try state.setNeedle(allocator, "syn");

    const hit = findNextList(&session, &state, true);
    try std.testing.expect(hit != null);
    try std.testing.expectEqual(@as(usize, 2), hit.?.packet_index);
}

test "search byte text returns actual offset" {
    const allocator = std.testing.allocator;
    const raw = try allocator.dupe(u8, "zero needle end");
    defer allocator.free(raw);
    const lines: [][]const u8 = &.{};
    const bytes = packet.PacketBytes{ .frame = 1, .raw = raw, .hexdump_lines = lines };
    var state = SearchState{ .kind = .string };
    defer state.deinit(allocator);
    try state.setNeedle(allocator, "needle");
    try std.testing.expectEqual(@as(?usize, 5), findNextBytes(&bytes, &state, 0));
}

test "search hexadecimal byte sequence" {
    const allocator = std.testing.allocator;
    const raw = try allocator.dupe(u8, &.{ 0x00, 0xde, 0xad, 0xbe, 0xef });
    defer allocator.free(raw);
    const lines: [][]const u8 = &.{};
    const bytes = packet.PacketBytes{ .frame = 1, .raw = raw, .hexdump_lines = lines };
    var state = SearchState{ .kind = .hex };
    defer state.deinit(allocator);
    try state.setNeedle(allocator, "de ad be ef");
    try std.testing.expectEqual(@as(?usize, 1), findNextBytes(&bytes, &state, 0));
}
