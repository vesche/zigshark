const std = @import("std");
const packet = @import("../model/packet.zig");

pub const Kind = enum { conversation, address, exchange };

const End = struct {
    addr: []const u8,
    port: ?u16,
};

const Flow = struct {
    left: End,
    right: End,
};

pub fn find(
    packets: []const packet.PacketSummary,
    headers: []const []const u8,
    from: usize,
    kind: Kind,
    forward: bool,
) ?usize {
    if (from >= packets.len) return null;
    const origin = flowOf(headers, packets[from]);
    const origin_role = roleOf(infoOf(headers, packets[from]));
    var step: isize = if (forward) 1 else -1;
    if (kind == .exchange and origin_role == .response) step = -step;
    var cursor: isize = @as(isize, @intCast(from)) + step;
    while (cursor >= 0 and cursor < @as(isize, @intCast(packets.len))) : (cursor += step) {
        const index: usize = @intCast(cursor);
        const other = flowOf(headers, packets[index]);
        const matched = switch (kind) {
            .conversation => sameFlow(origin, other),
            .address => sharesAddress(origin.left.addr, other),
            .exchange => oppositeRole(origin_role, roleOf(infoOf(headers, packets[index]))) and sameFlow(origin, other),
        };
        if (matched) return index;
    }
    if (kind == .exchange) {
        const fallback: isize = if (step < 0) 1 else -1;
        cursor = @as(isize, @intCast(from)) + fallback;
        while (cursor >= 0 and cursor < @as(isize, @intCast(packets.len))) : (cursor += fallback) {
            const index: usize = @intCast(cursor);
            const other = flowOf(headers, packets[index]);
            if (oppositeRole(origin_role, roleOf(infoOf(headers, packets[index]))) and
                (sameFlow(origin, other) or sharesAddress(origin.left.addr, other)))
            {
                return index;
            }
        }
    }
    return null;
}

const Role = enum { request, response, other };

fn roleOf(info: []const u8) Role {
    if (std.ascii.findIgnoreCase(info, "response") != null or
        std.ascii.findIgnoreCase(info, "reply") != null)
    {
        return .response;
    }
    if (std.ascii.findIgnoreCase(info, "request") != null or
        std.ascii.findIgnoreCase(info, "query") != null)
    {
        return .request;
    }
    return .other;
}

fn oppositeRole(origin: Role, other: Role) bool {
    return (origin == .request and other == .response) or (origin == .response and other == .request);
}

fn sharesAddress(addr: []const u8, flow: Flow) bool {
    if (addr.len == 0) return false;
    return std.mem.eql(u8, addr, flow.left.addr) or std.mem.eql(u8, addr, flow.right.addr);
}

fn sameFlow(a: Flow, b: Flow) bool {
    return (sameEnd(a.left, b.left) and sameEnd(a.right, b.right)) or
        (sameEnd(a.left, b.right) and sameEnd(a.right, b.left));
}

fn sameEnd(a: End, b: End) bool {
    if (!std.mem.eql(u8, a.addr, b.addr)) return false;
    if (a.port != null and b.port != null) return a.port.? == b.port.?;
    return true;
}

fn flowOf(headers: []const []const u8, packet_row: packet.PacketSummary) Flow {
    const source = cell(headers, packet_row, &.{ "source", "src" }, 2);
    const dest = cell(headers, packet_row, &.{ "destination", "dest", "dst" }, 3);
    const info = infoOf(headers, packet_row);
    const ports = portsFromInfo(info);
    return .{
        .left = .{ .addr = source, .port = if (ports) |pair| pair.src else null },
        .right = .{ .addr = dest, .port = if (ports) |pair| pair.dst else null },
    };
}

fn infoOf(headers: []const []const u8, packet_row: packet.PacketSummary) []const u8 {
    return cell(headers, packet_row, &.{ "info", "information" }, 6);
}

fn cell(headers: []const []const u8, packet_row: packet.PacketSummary, names: []const []const u8, fallback: usize) []const u8 {
    for (headers, 0..) |header, index| {
        if (index >= packet_row.columns.len) break;
        for (names) |name| {
            if (std.ascii.eqlIgnoreCase(header, name)) return packet_row.columns[index];
        }
    }
    const index = if (packet_row.columns.len >= 8 and fallback >= 2) fallback + 1 else fallback;
    return if (index < packet_row.columns.len) packet_row.columns[index] else "";
}

const Ports = struct { src: u16, dst: u16 };

fn portsFromInfo(info: []const u8) ?Ports {
    const arrow = if (std.mem.indexOf(u8, info, " → ")) |at|
        at
    else
        std.mem.indexOf(u8, info, " -> ") orelse return null;
    const width: usize = if (std.mem.startsWith(u8, info[arrow..], " → ")) 5 else 4;
    const src = lastNumber(info[0..arrow]) orelse return null;
    const dst = firstNumber(info[arrow + width ..]) orelse return null;
    return .{ .src = src, .dst = dst };
}

fn lastNumber(text: []const u8) ?u16 {
    var end = std.mem.trim(u8, text, " \t").len;
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0) return null;
    end = trimmed.len;
    var start = end;
    while (start > 0 and std.ascii.isDigit(trimmed[start - 1])) start -= 1;
    if (start == end) return null;
    return std.fmt.parseInt(u16, trimmed[start..end], 10) catch null;
}

fn firstNumber(text: []const u8) ?u16 {
    const trimmed = std.mem.trim(u8, text, " \t");
    var end: usize = 0;
    while (end < trimmed.len and std.ascii.isDigit(trimmed[end])) end += 1;
    if (end == 0) return null;
    return std.fmt.parseInt(u16, trimmed[0..end], 10) catch null;
}

fn summaryRow(columns: []const []const u8) packet.PacketSummary {
    return .{ .frame = 0, .columns = @constCast(columns) };
}

test "related packets stay inside the flow, the address, or the exchange" {
    const headers = [_][]const u8{ "Source", "Destination", "Info" };
    const a = [_][]const u8{ "10.0.0.1", "10.0.0.2", "12345 → 80 request" };
    const other = [_][]const u8{ "10.0.0.1", "10.0.0.9", "111 → 53 query" };
    const back = [_][]const u8{ "10.0.0.2", "10.0.0.1", "80 → 12345 response" };
    const packets = [_]packet.PacketSummary{ summaryRow(&a), summaryRow(&other), summaryRow(&back) };

    try std.testing.expectEqual(@as(?usize, 2), find(&packets, &headers, 0, .conversation, true));
    try std.testing.expectEqual(@as(?usize, null), find(&packets, &headers, 0, .conversation, false));
    try std.testing.expectEqual(@as(?usize, 1), find(&packets, &headers, 0, .address, true));
    try std.testing.expectEqual(@as(?usize, 2), find(&packets, &headers, 0, .exchange, true));
    try std.testing.expectEqual(@as(?usize, 0), find(&packets, &headers, 2, .exchange, true));
}
