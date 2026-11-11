const std = @import("std");

pub const Op = enum { eq, ne, both, either, not_eq, contains };

pub fn expression(
    allocator: std.mem.Allocator,
    current: []const u8,
    name: []const u8,
    value: []const u8,
    op: Op,
) ![]u8 {
    if (name.len == 0) return error.NoField;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const trimmed = std.mem.trim(u8, current, " \t");
    switch (op) {
        .both, .either => {
            if (trimmed.len != 0) {
                try out.appendSlice(allocator, trimmed);
                try out.appendSlice(allocator, if (op == .both) " and (" else " or (");
            }
            try appendComparison(allocator, &out, name, value, .eq);
            if (trimmed.len != 0) try out.append(allocator, ')');
        },
        .not_eq => {
            try out.appendSlice(allocator, "!(");
            try appendComparison(allocator, &out, name, value, .eq);
            try out.append(allocator, ')');
        },
        else => try appendComparison(allocator, &out, name, value, op),
    }
    return out.toOwnedSlice(allocator);
}

fn appendComparison(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    name: []const u8,
    value: []const u8,
    op: Op,
) !void {
    if (value.len == 0) {
        try out.appendSlice(allocator, name);
        return;
    }
    try out.appendSlice(allocator, name);
    const relation: []const u8 = switch (op) {
        .ne => " != ",
        .contains => " contains ",
        else => " == ",
    };
    try out.appendSlice(allocator, relation);
    try appendValue(allocator, out, value);
}

fn appendValue(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    if (isBare(value)) {
        try out.appendSlice(allocator, value);
        return;
    }
    try out.append(allocator, '"');
    for (value) |char| {
        if (char == '\\' or char == '"') try out.append(allocator, '\\');
        try out.append(allocator, char);
    }
    try out.append(allocator, '"');
}

fn isBare(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |char| {
        const ok = std.ascii.isAlphanumeric(char) or char == '.' or char == ':' or char == '_' or char == '-';
        if (!ok) return false;
    }
    return true;
}

const Endpoint = struct {
    host: []const u8,
    port: ?u16 = null,
};

fn endpoint(text: []const u8) Endpoint {
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len > 2 and trimmed[0] == '[') {
        if (std.mem.indexOfScalar(u8, trimmed, ']')) |end| {
            const host = trimmed[1..end];
            if (end + 2 < trimmed.len and trimmed[end + 1] == ':') {
                const port = std.fmt.parseInt(u16, trimmed[end + 2 ..], 10) catch null;
                return .{ .host = host, .port = port };
            }
            return .{ .host = host };
        }
    }
    if (std.mem.lastIndexOfScalar(u8, trimmed, ':')) |colon| {
        const host = trimmed[0..colon];
        const port_text = trimmed[colon + 1 ..];
        if (host.len > 0 and std.mem.indexOfScalar(u8, host, ':') == null) {
            if (std.fmt.parseInt(u16, port_text, 10)) |port| {
                return .{ .host = host, .port = port };
            } else |_| {}
        }
    }
    return .{ .host = trimmed };
}

pub fn conversation(
    allocator: std.mem.Allocator,
    protocol: []const u8,
    source: []const u8,
    destination: []const u8,
) ![]u8 {
    const left = endpoint(source);
    const right = endpoint(destination);
    if (left.host.len == 0 or right.host.len == 0) return error.NoAddress;
    var proto_buf: [16]u8 = undefined;
    const raw_proto = std.mem.trim(u8, protocol, " \t");
    const proto_len = @min(raw_proto.len, proto_buf.len);
    const proto = std.ascii.lowerString(proto_buf[0..proto_len], raw_proto[0..proto_len]);
    const transport = std.mem.eql(u8, proto, "tcp") or std.mem.eql(u8, proto, "udp");
    const addr = if (std.mem.eql(u8, proto, "ipv6")) "ipv6.addr" else "ip.addr";
    if (transport) {
        if (left.port) |port_a| {
            if (right.port) |port_b| {
                return std.fmt.allocPrint(
                    allocator,
                    "({s} == {s} and {s} == {s}) and ({s}.port == {d} and {s}.port == {d})",
                    .{ addr, left.host, addr, right.host, proto, port_a, proto, port_b },
                );
            }
        }
    }
    return std.fmt.allocPrint(
        allocator,
        "{s} == {s} and {s} == {s}",
        .{ addr, left.host, addr, right.host },
    );
}

pub fn formatFieldCopy(
    allocator: std.mem.Allocator,
    name: []const u8,
    show: []const u8,
    subtree: []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    if (name.len != 0) {
        const atom = try expression(allocator, "", name, show, .eq);
        defer allocator.free(atom);
        try out.appendSlice(allocator, atom);
        try out.append(allocator, '\n');
        if (show.len != 0) {
            try out.appendSlice(allocator, show);
            try out.append(allocator, '\n');
        }
        if (subtree.len != 0) try out.append(allocator, '\n');
    }
    try out.appendSlice(allocator, subtree);
    return out.toOwnedSlice(allocator);
}

test "field copy includes the filter atom and the raw value" {
    const allocator = std.testing.allocator;
    const text = try formatFieldCopy(allocator, "tcp.port", "443", "Source Port: 443");
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "tcp.port == 443") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\n443\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, text, "Source Port: 443"));
}

test "field filter quotes text and appends and or" {
    const allocator = std.testing.allocator;
    const eq = try expression(allocator, "", "tcp.port", "443", .eq);
    defer allocator.free(eq);
    try std.testing.expectEqualStrings("tcp.port == 443", eq);

    const text = try expression(allocator, "", "http.host", "example.com", .eq);
    defer allocator.free(text);
    try std.testing.expectEqualStrings("http.host == example.com", text);

    const spaced = try expression(allocator, "", "frame.comment", "a \"b\"", .contains);
    defer allocator.free(spaced);
    try std.testing.expectEqualStrings("frame.comment contains \"a \\\"b\\\"\"", spaced);

    const both = try expression(allocator, "dns", "ip.addr", "10.0.0.1", .both);
    defer allocator.free(both);
    try std.testing.expectEqualStrings("dns and (ip.addr == 10.0.0.1)", both);

    const either = try expression(allocator, "", "tcp", "", .either);
    defer allocator.free(either);
    try std.testing.expectEqualStrings("tcp", either);

    const negated = try expression(allocator, "dns", "tcp.port", "80", .not_eq);
    defer allocator.free(negated);
    try std.testing.expectEqualStrings("!(tcp.port == 80)", negated);
}

test "conversation filter uses ports for tcp and udp" {
    const allocator = std.testing.allocator;
    const tcp = try conversation(allocator, "TCP", "10.0.0.1:443", "10.0.0.2:52344");
    defer allocator.free(tcp);
    try std.testing.expectEqualStrings(
        "(ip.addr == 10.0.0.1 and ip.addr == 10.0.0.2) and (tcp.port == 443 and tcp.port == 52344)",
        tcp,
    );

    const udp = try conversation(allocator, "udp", "10.1.1.1:53", "10.1.1.2");
    defer allocator.free(udp);
    try std.testing.expectEqualStrings("ip.addr == 10.1.1.1 and ip.addr == 10.1.1.2", udp);

    const v6 = try conversation(allocator, "ipv6", "[2001:db8::a]:443", "2001:db8::b");
    defer allocator.free(v6);
    try std.testing.expectEqualStrings("ipv6.addr == 2001:db8::a and ipv6.addr == 2001:db8::b", v6);
}
