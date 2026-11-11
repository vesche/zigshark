const std = @import("std");

pub const Entry = struct {
    key: []u8,
    value: []u8,

    pub fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }
};

pub const CapInfo = struct {
    entries: []Entry,

    pub fn deinit(self: *CapInfo, allocator: std.mem.Allocator) void {
        for (self.entries) |*e| e.deinit(allocator);
        allocator.free(self.entries);
    }

    pub fn get(self: CapInfo, key: []const u8) ?[]const u8 {
        for (self.entries) |e| {
            if (std.ascii.eqlIgnoreCase(e.key, key)) return e.value;
        }
        return null;
    }

    pub fn fileName(self: CapInfo) ?[]const u8 {
        return self.get("File name");
    }

    pub fn fileType(self: CapInfo) ?[]const u8 {
        return self.get("File type");
    }

    pub fn packetCount(self: CapInfo) ?[]const u8 {
        return self.get("Number of packets");
    }

    pub fn fileSizeBytes(self: CapInfo) ?[]const u8 {
        return self.get("File size");
    }
};

pub const ParseError = error{
    InvalidLine,
};

pub fn parse(allocator: std.mem.Allocator, text: []const u8) !CapInfo {
    var list: std.ArrayList(Entry) = .empty;
    errdefer {
        for (list.items) |*e| e.deinit(allocator);
        list.deinit(allocator);
    }

    var lines = std.mem.splitAny(u8, text, "\n\r");
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, " \t");
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key_part = std.mem.trim(u8, line[0..colon], " \t");
        const val_part = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (key_part.len == 0) continue;

        try list.append(allocator, .{
            .key = try allocator.dupe(u8, key_part),
            .value = try allocator.dupe(u8, val_part),
        });
    }

    return .{ .entries = try list.toOwnedSlice(allocator) };
}

const sample =
    \\File name:           wlan.pcap
    \\File type:           pcap
    \\File encapsulation:  Ethernet
    \\File timestamp precision:  microseconds (6)
    \\Packet size limit:    file hdr: 262144 bytes
    \\Number of packets:   12
    \\File size:           4 KiB
    \\Number of interfaces in file: 1
;

test "parse capinfos helpers" {
    const alloc = std.testing.allocator;
    var info = try parse(alloc, sample);
    defer info.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 8), info.entries.len);
    try std.testing.expectEqualStrings("wlan.pcap", info.fileName().?);
    try std.testing.expectEqualStrings("pcap", info.fileType().?);
    try std.testing.expectEqualStrings("12", info.packetCount().?);
    try std.testing.expect(std.mem.indexOf(u8, info.fileSizeBytes().?, "KiB") != null);
}

test "get case insensitive" {
    const alloc = std.testing.allocator;
    var info = try parse(alloc, "file name: x\n");
    defer info.deinit(alloc);
    try std.testing.expectEqualStrings("x", info.get("File name").?);
}
