const std = @import("std");
const process = @import("../shark/process.zig");
const packet = @import("packet.zig");
const marks_mod = @import("marks.zig");

pub const LoadingState = enum {
    idle,
    loading_list,
    loading_detail,
    capturing,
    error_state,
};

pub const SortState = struct {
    column: usize = 0,
    ascending: bool = true,
};

pub const DecodeAs = struct {
    field: []u8,
    value: []u8,

    pub fn deinit(self: *DecodeAs, allocator: std.mem.Allocator) void {
        allocator.free(self.field);
        allocator.free(self.value);
    }
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    source: process.Source,
    display_filter: []u8 = &.{},
    capture_filter: []u8 = &.{},
    decode_as: std.ArrayList(DecodeAs) = .empty,
    decode_as_args: std.ArrayList([]u8) = .empty,
    timestamp_format: []u8 = &.{},
    wireshark_profile: []u8 = &.{},
    tls_keylog_file: []u8 = &.{},
    name_resolution: []u8 = &.{},
    packets: []packet.PacketSummary = &.{},
    packets_owned: bool = false,
    list_headers: [][]u8 = &.{},
    selected_index: ?usize = null,
    loading: LoadingState = .idle,
    error_message: []u8 = &.{},
    marks: marks_mod.Marks,
    sort: SortState = .{},
    capture_path: []u8 = &.{},
    source_path_owned: []u8 = &.{},

    pub fn init(allocator: std.mem.Allocator, source: process.Source) Session {
        return .{
            .allocator = allocator,
            .source = source,
            .marks = marks_mod.Marks.init(allocator),
        };
    }

    pub fn deinit(self: *Session) void {
        self.clearPackets();
        self.clearListHeaders();
        self.freeFilterStrings();
        for (self.decode_as.items) |*d| d.deinit(self.allocator);
        self.decode_as.deinit(self.allocator);
        for (self.decode_as_args.items) |arg| self.allocator.free(arg);
        self.decode_as_args.deinit(self.allocator);
        if (self.timestamp_format.len != 0) self.allocator.free(self.timestamp_format);
        if (self.wireshark_profile.len != 0) self.allocator.free(self.wireshark_profile);
        if (self.tls_keylog_file.len != 0) self.allocator.free(self.tls_keylog_file);
        if (self.name_resolution.len != 0) self.allocator.free(self.name_resolution);
        self.marks.deinit();
        if (self.capture_path.len != 0) self.allocator.free(self.capture_path);
        if (self.source_path_owned.len != 0) self.allocator.free(self.source_path_owned);
    }

    fn freeFilterStrings(self: *Session) void {
        if (self.display_filter.len != 0) self.allocator.free(self.display_filter);
        if (self.capture_filter.len != 0) self.allocator.free(self.capture_filter);
        if (self.error_message.len != 0) self.allocator.free(self.error_message);
        self.display_filter = &.{};
        self.capture_filter = &.{};
        self.error_message = &.{};
    }

    pub fn clearPackets(self: *Session) void {
        if (self.packets_owned) {
            for (self.packets) |*p| p.deinit(self.allocator);
            if (self.packets.len != 0) self.allocator.free(self.packets);
        }
        self.packets = &.{};
        self.packets_owned = false;
        self.selected_index = null;
    }

    pub fn setListHeaders(self: *Session, headers: [][]u8) void {
        self.clearListHeaders();
        self.list_headers = headers;
    }

    pub fn clearListHeaders(self: *Session) void {
        for (self.list_headers) |header| self.allocator.free(header);
        if (self.list_headers.len != 0) self.allocator.free(self.list_headers);
        self.list_headers = &.{};
    }

    pub fn appendPackets(self: *Session, more: []packet.PacketSummary) !void {
        if (more.len == 0) {
            self.allocator.free(more);
            return;
        }
        if (self.packets.len == 0) {
            self.packets = more;
            self.packets_owned = true;
            if (self.selected_index == null) self.selected_index = 0;
            return;
        }
        const keep_frame = self.selectedFrame();
        const merged = try self.allocator.alloc(packet.PacketSummary, self.packets.len + more.len);
        @memcpy(merged[0..self.packets.len], self.packets);
        @memcpy(merged[self.packets.len..], more);
        if (self.packets_owned) self.allocator.free(self.packets);
        self.allocator.free(more);
        self.packets = merged;
        self.packets_owned = true;
        const resort = self.sort.column != 0 or !self.sort.ascending;
        if (resort) self.applySort();
        if (keep_frame) |frame| {
            for (self.packets, 0..) |summary, index| {
                if (summary.frame == frame) {
                    self.selected_index = index;
                    break;
                }
            }
        }
    }

    pub fn setPackets(self: *Session, summaries: []packet.PacketSummary) void {
        setPacketsOwned(self, summaries, true);
    }

    pub fn setPacketsBorrowed(self: *Session, summaries: []packet.PacketSummary) void {
        setPacketsOwned(self, summaries, false);
    }

    fn setPacketsOwned(self: *Session, summaries: []packet.PacketSummary, owned: bool) void {
        self.clearPackets();
        self.packets = summaries;
        self.packets_owned = owned;
        if (summaries.len > 0) self.selected_index = 0;
    }

    pub fn select(self: *Session, index: usize) bool {
        if (index >= self.packets.len) return false;
        self.selected_index = index;
        return true;
    }

    pub fn setFileSource(self: *Session, path: []const u8) !void {
        const copy = try self.allocator.dupe(u8, path);
        if (self.source_path_owned.len != 0) self.allocator.free(self.source_path_owned);
        self.source_path_owned = copy;
        self.source = .{ .file = self.source_path_owned };
    }

    pub fn selectedFrame(self: *const Session) ?u32 {
        const idx = self.selected_index orelse return null;
        if (idx >= self.packets.len) return null;
        return self.packets[idx].frame;
    }

    pub fn next(self: *Session) bool {
        const idx = self.selected_index orelse return false;
        return self.select(@min(idx + 1, if (self.packets.len > 0) self.packets.len - 1 else 0));
    }

    pub fn prev(self: *Session) bool {
        const idx = self.selected_index orelse return false;
        return self.select(if (idx > 0) idx - 1 else 0);
    }

    pub fn markLocal(self: *Session, label: u8) void {
        if (self.selectedFrame()) |f| self.marks.setLocal(label, f);
    }

    pub fn markGlobal(self: *Session, label: u8) void {
        if (self.selectedFrame()) |f| self.marks.setGlobal(label, f);
    }

    pub fn jumpToMark(self: *Session, label: u8, global: bool) bool {
        const frame = if (global) self.marks.jumpGlobal(label) else self.marks.jumpLocal(label);
        const f = frame orelse return false;
        for (self.packets, 0..) |p, i| {
            if (p.frame == f) return self.select(i);
        }
        return false;
    }

    pub fn setFilter(self: *Session, display: ?[]const u8, capture: ?[]const u8) !void {
        if (display) |d| {
            if (self.display_filter.len != 0) self.allocator.free(self.display_filter);
            self.display_filter = try self.allocator.dupe(u8, d);
        }
        if (capture) |c| {
            if (self.capture_filter.len != 0) self.allocator.free(self.capture_filter);
            self.capture_filter = try self.allocator.dupe(u8, c);
        }
    }

    pub fn addDecodeAs(self: *Session, value: []const u8) !void {
        try self.decode_as_args.append(self.allocator, try self.allocator.dupe(u8, value));
    }

    /// Drop every rule for this layer and protocol. `true` when one was removed.
    pub fn removeDecodeAs(self: *Session, layer: []const u8, protocol: []const u8) bool {
        var index = self.decode_as_args.items.len;
        var removed = false;
        while (index > 0) {
            index -= 1;
            if (!decodeRuleMatches(self.decode_as_args.items[index], layer, protocol)) continue;
            self.allocator.free(self.decode_as_args.orderedRemove(index));
            removed = true;
        }
        return removed;
    }

    fn decodeRuleMatches(rule: []const u8, layer: []const u8, protocol: []const u8) bool {
        if (!std.mem.startsWith(u8, rule, layer)) return false;
        if (!std.mem.startsWith(u8, rule[layer.len..], "==")) return false;
        const comma = std.mem.lastIndexOfScalar(u8, rule, ',') orelse return false;
        return std.mem.eql(u8, rule[comma + 1 ..], protocol);
    }

    pub fn setTimestampFormat(self: *Session, value: []const u8) !void {
        const copy = try self.allocator.dupe(u8, value);
        if (self.timestamp_format.len != 0) self.allocator.free(self.timestamp_format);
        self.timestamp_format = copy;
    }

    pub fn setWiresharkProfile(self: *Session, value: []const u8) !void {
        const copy = try self.allocator.dupe(u8, value);
        if (self.wireshark_profile.len != 0) self.allocator.free(self.wireshark_profile);
        self.wireshark_profile = copy;
    }

    pub fn setTlsKeylog(self: *Session, value: []const u8) !void {
        if (self.tls_keylog_file.len != 0) self.allocator.free(self.tls_keylog_file);
        self.tls_keylog_file = if (value.len == 0) &.{} else try self.allocator.dupe(u8, value);
    }

    pub fn setNameResolution(self: *Session, value: []const u8) !void {
        if (self.name_resolution.len != 0) self.allocator.free(self.name_resolution);
        self.name_resolution = if (value.len == 0) &.{} else try self.allocator.dupe(u8, value);
    }

    pub fn setError(self: *Session, msg: []const u8) !void {
        if (self.error_message.len != 0) self.allocator.free(self.error_message);
        self.error_message = try self.allocator.dupe(u8, msg);
        self.loading = .error_state;
    }

    pub fn setSort(self: *Session, column: usize, ascending: bool) void {
        const selected_frame = self.selectedFrame();
        self.sort = .{ .column = column, .ascending = ascending };
        self.applySort();
        if (selected_frame) |frame| {
            for (self.packets, 0..) |summary, index| {
                if (summary.frame == frame) {
                    self.selected_index = index;
                    break;
                }
            }
        }
    }

    fn applySort(self: *Session) void {
        if (self.packets.len < 2) return;
        std.mem.sort(packet.PacketSummary, self.packets, self.sort, struct {
            fn less(ctx: SortState, a: packet.PacketSummary, b: packet.PacketSummary) bool {
                const av: []const u8 = if (ctx.column < a.columns.len) a.columns[ctx.column] else "";
                const bv: []const u8 = if (ctx.column < b.columns.len) b.columns[ctx.column] else "";
                if (ctx.column == 0 or ctx.column == 5) {
                    const an = std.fmt.parseInt(u64, av, 10) catch null;
                    const bn = std.fmt.parseInt(u64, bv, 10) catch null;
                    if (an != null and bn != null) {
                        return if (ctx.ascending) an.? < bn.? else bn.? < an.?;
                    }
                }
                if (ctx.column == 1) {
                    const an = std.fmt.parseFloat(f64, av) catch null;
                    const bn = std.fmt.parseFloat(f64, bv) catch null;
                    if (an != null and bn != null) {
                        return if (ctx.ascending) an.? < bn.? else bn.? < an.?;
                    }
                }
                return if (ctx.ascending)
                    std.ascii.lessThanIgnoreCase(av, bv)
                else
                    std.ascii.lessThanIgnoreCase(bv, av);
            }
        }.less);
    }
};

test "session navigation and marks" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator, .{ .file = "/tmp/x.pcap" });
    defer session.deinit();

    var cols1 = [_][]const u8{ "1", "0", "a", "b", "tcp", "60", "syn" };
    var cols2 = [_][]const u8{ "2", "0", "a", "b", "tcp", "60", "syn" };
    var packets = [_]packet.PacketSummary{
        .{ .frame = 1, .columns = &cols1, .owns_columns = false },
        .{ .frame = 2, .columns = &cols2, .owns_columns = false },
    };
    session.setPacketsBorrowed(&packets);
    try std.testing.expect(session.select(1));
    try std.testing.expectEqual(@as(?u32, 2), session.selectedFrame());
    session.markLocal('a');
    _ = session.select(0);
    try std.testing.expect(session.jumpToMark('a', false));
    session.setSort(0, false);
    try std.testing.expectEqual(@as(u32, 2), session.packets[0].frame);
    try std.testing.expectEqual(@as(?u32, 2), session.selectedFrame());
}

test "sort reverses a column, compares numbers, and keeps the selected frame" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator, .{ .file = "/tmp/x.pcap" });
    defer session.deinit();

    // "10" sorts before "2" as text and after it as a number.
    var ten = [_][]const u8{ "10", "1.5", "b" };
    var two = [_][]const u8{ "2", "0.5", "c" };
    var three = [_][]const u8{ "3", "10", "a" };
    var packets = [_]packet.PacketSummary{
        .{ .frame = 10, .columns = &ten, .owns_columns = false },
        .{ .frame = 2, .columns = &two, .owns_columns = false },
        .{ .frame = 3, .columns = &three, .owns_columns = false },
    };
    session.setPacketsBorrowed(&packets);
    try std.testing.expect(session.select(0));

    session.setSort(0, true);
    try std.testing.expectEqual(@as(u32, 2), session.packets[0].frame);
    try std.testing.expectEqual(@as(u32, 3), session.packets[1].frame);
    try std.testing.expectEqual(@as(u32, 10), session.packets[2].frame);
    try std.testing.expectEqual(@as(?u32, 10), session.selectedFrame());

    session.setSort(0, false);
    try std.testing.expectEqual(@as(u32, 10), session.packets[0].frame);
    try std.testing.expectEqual(@as(u32, 3), session.packets[1].frame);
    try std.testing.expectEqual(@as(u32, 2), session.packets[2].frame);
    try std.testing.expectEqual(@as(?u32, 10), session.selectedFrame());

    session.setSort(1, true);
    try std.testing.expectEqual(@as(u32, 2), session.packets[0].frame);
    try std.testing.expectEqual(@as(u32, 10), session.packets[1].frame);
    try std.testing.expectEqual(@as(u32, 3), session.packets[2].frame);

    session.setSort(2, true);
    try std.testing.expectEqual(@as(u32, 3), session.packets[0].frame);
    try std.testing.expectEqual(@as(u32, 10), session.packets[1].frame);
    try std.testing.expectEqual(@as(u32, 2), session.packets[2].frame);
    try std.testing.expectEqual(@as(?u32, 10), session.selectedFrame());
}
