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

fn fieldMatches(state: *const SearchState, haystack: []const u8) bool {
    if (state.needle.len == 0) return true;
    if (state.kind == .regex) return regexFind(haystack, state.needle) != null;
    return haystackMatches(haystack, state.needle, state.case_sensitive);
}

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
            if (fieldMatches(state, col)) {
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
                if (fieldMatches(state, col)) {
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
        .regex => {
            if (from > bytes.raw.len) return null;
            const rel = regexFind(bytes.raw[from..], state.needle) orelse return null;
            return from + rel;
        },
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

/// Byte-oriented search. Supports `.`, `*`, `+`, `?`, `[]` classes, `^`, `$`, and `\`.
/// Returns the start offset of the first match.
pub fn regexFind(haystack: []const u8, pattern: []const u8) ?usize {
    if (pattern.len == 0) return 0;
    if (pattern[0] == '^') {
        return if (regexMatchAt(haystack, pattern[1..], 0)) 0 else null;
    }
    var i: usize = 0;
    while (i <= haystack.len) : (i += 1) {
        if (regexMatchAt(haystack, pattern, i)) return i;
        if (i == haystack.len) break;
    }
    return null;
}

fn regexMatchAt(haystack: []const u8, pattern: []const u8, index: usize) bool {
    if (pattern.len == 0) return true;
    if (pattern[0] == '$' and pattern.len == 1) return index == haystack.len;
    const atom_len = regexAtomLen(pattern) orelse return false;
    const atom = pattern[0..atom_len];
    var rest = pattern[atom_len..];
    const quant: u8 = if (rest.len > 0 and (rest[0] == '*' or rest[0] == '+' or rest[0] == '?')) blk: {
        const q = rest[0];
        rest = rest[1..];
        break :blk q;
    } else 1;
    return regexQuant(haystack, atom, quant, rest, index);
}

fn regexQuant(
    haystack: []const u8,
    atom: []const u8,
    quant: u8,
    rest: []const u8,
    index: usize,
) bool {
    var ends: [160]usize = undefined;
    var count: usize = 0;
    ends[0] = index;
    var pos = index;
    const max: usize = if (quant == '?') 1 else if (quant == 1) 1 else ends.len - 1;
    while (count < max) {
        const next = regexAtom(haystack, atom, pos) orelse break;
        if (next == pos) break;
        count += 1;
        pos = next;
        ends[count] = pos;
    }
    const min: usize = if (quant == '+' or quant == 1) 1 else 0;
    if (count < min) return false;
    var taken = count;
    while (true) {
        if (regexMatchAt(haystack, rest, ends[taken])) return true;
        if (taken == min) break;
        taken -= 1;
    }
    return false;
}

fn regexAtomLen(pattern: []const u8) ?usize {
    if (pattern.len == 0) return null;
    if (pattern[0] == '\\') return if (pattern.len >= 2) 2 else null;
    if (pattern[0] == '[') {
        var i: usize = 1;
        if (i < pattern.len and pattern[i] == '^') i += 1;
        var closed = false;
        while (i < pattern.len) : (i += 1) {
            if (pattern[i] == '\\' and i + 1 < pattern.len) {
                i += 1;
                continue;
            }
            if (pattern[i] == ']') {
                closed = true;
                i += 1;
                break;
            }
        }
        return if (closed) i else null;
    }
    return 1;
}

fn regexAtom(haystack: []const u8, atom: []const u8, index: usize) ?usize {
    if (index >= haystack.len) return null;
    const byte = haystack[index];
    if (atom.len == 1 and atom[0] == '.') return index + 1;
    if (atom.len == 2 and atom[0] == '\\') {
        return if (byte == atom[1]) index + 1 else null;
    }
    if (atom.len >= 2 and atom[0] == '[' and atom[atom.len - 1] == ']') {
        return if (classContains(atom, byte)) index + 1 else null;
    }
    if (atom.len == 1 and byte == atom[0]) return index + 1;
    return null;
}

fn classContains(atom: []const u8, byte: u8) bool {
    var body = atom[1 .. atom.len - 1];
    var negated = false;
    if (body.len > 0 and body[0] == '^') {
        negated = true;
        body = body[1..];
    }
    var found = false;
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        var ch = body[i];
        if (ch == '\\' and i + 1 < body.len) {
            i += 1;
            ch = body[i];
        }
        if (i + 2 < body.len and body[i + 1] == '-' and body[i + 2] != ']') {
            const end = body[i + 2];
            if (byte >= ch and byte <= end) found = true;
            i += 2;
            continue;
        }
        if (byte == ch) found = true;
    }
    return if (negated) !found else found;
}

test "regex finds a wildcard span" {
    try std.testing.expectEqual(@as(?usize, 0), regexFind("syn retrans", "syn.*retrans"));
    try std.testing.expectEqual(@as(?usize, null), regexFind("ack", "^syn"));
    try std.testing.expectEqual(@as(?usize, 1), regexFind("xdead", "de.d"));
    try std.testing.expectEqual(@as(?usize, 3), regexFind("ab 42 zz", "[0-9]+"));
}

test "regex class, anchors, and escapes stay within the small matcher" {
    try std.testing.expectEqual(@as(?usize, 2), regexFind("zz9", "[0-9]"));
    try std.testing.expectEqual(@as(?usize, 1), regexFind("az9", "z[0-9]"));
    try std.testing.expectEqual(@as(?usize, 0), regexFind("x^", "x^"));
    try std.testing.expectEqual(@as(?usize, null), regexFind("x", "x^"));
    try std.testing.expectEqual(@as(?usize, 0), regexFind("a$b", "a$b"));
    try std.testing.expectEqual(@as(?usize, null), regexFind("ab", "a$b"));
    try std.testing.expectEqual(@as(?usize, 0), regexFind("ab", "ab$"));
    try std.testing.expectEqual(@as(?usize, 0), regexFind("a.b", "a\\.b"));
    try std.testing.expectEqual(@as(?usize, null), regexFind("axb", "a\\.b"));
}

test "odd trailing hex nibble does not match" {
    const allocator = std.testing.allocator;
    const raw = try allocator.dupe(u8, &.{ 0xde, 0xad });
    defer allocator.free(raw);
    const lines: [][]const u8 = &.{};
    const bytes = packet.PacketBytes{ .frame = 1, .raw = raw, .hexdump_lines = lines };
    var state = SearchState{ .kind = .hex };
    defer state.deinit(allocator);
    try state.setNeedle(allocator, "dea");
    try std.testing.expectEqual(@as(?usize, null), findNextBytes(&bytes, &state, 0));
    try state.setNeedle(allocator, "dead");
    try std.testing.expectEqual(@as(?usize, 0), findNextBytes(&bytes, &state, 0));
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
