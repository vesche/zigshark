const std = @import("std");
const xml = @import("../xml_util.zig");

pub const Node = struct {
    is_proto: bool,
    name: ?[]u8 = null,
    showname: ?[]u8 = null,
    show: ?[]u8 = null,
    value: ?[]u8 = null,
    pos: ?u32 = null,
    size: ?u32 = null,
    hide: bool = false,
    children: []Node = &.{},

    pub fn deinit(self: *Node, allocator: std.mem.Allocator) void {
        if (self.name) |s| allocator.free(s);
        if (self.showname) |s| allocator.free(s);
        if (self.show) |s| allocator.free(s);
        if (self.value) |s| allocator.free(s);
        for (self.children) |*c| c.deinit(allocator);
        allocator.free(self.children);
    }
};

pub const PacketDetail = struct {
    frame_number: u32,
    nodes: []Node,

    pub fn deinit(self: *PacketDetail, allocator: std.mem.Allocator) void {
        for (self.nodes) |*n| n.deinit(allocator);
        allocator.free(self.nodes);
    }
};

pub fn deinitPackets(allocator: std.mem.Allocator, packets: []PacketDetail) void {
    for (packets) |*p| p.deinit(allocator);
    allocator.free(packets);
}

pub fn parse(allocator: std.mem.Allocator, input: []const u8) ![]PacketDetail {
    var out: std.ArrayList(PacketDetail) = .empty;
    errdefer deinitPackets(allocator, out.items);

    var pos: usize = 0;
    while (xml.findTagOpen(input, pos, "packet")) |popen| {
        const te = xml.openingTagEnd(input, popen) orelse return xml.ParseError.MalformedTag;
        const close = findPacketClose(input, te.end) orelse return xml.ParseError.UnexpectedEnd;

        var nodes: std.ArrayList(Node) = .empty;
        errdefer {
            for (nodes.items) |*n| n.deinit(allocator);
            nodes.deinit(allocator);
        }

        var child_pos = te.end;
        while (child_pos < close) {
            child_pos = xml.skipWs(input, child_pos);
            if (child_pos >= close) break;
            if (input[child_pos] == '<' and child_pos + 1 < input.len and input[child_pos + 1] == '/') break;
            const parsed = try parseElement(allocator, input, child_pos);
            try nodes.append(allocator, parsed.node);
            child_pos = parsed.next;
        }

        const owned_nodes = try nodes.toOwnedSlice(allocator);
        const frame_number = extractFrameNumber(owned_nodes) orelse 0;
        try out.append(allocator, .{
            .frame_number = frame_number,
            .nodes = owned_nodes,
        });
        pos = close;
    }

    return try out.toOwnedSlice(allocator);
}

pub fn parseSinglePacket(allocator: std.mem.Allocator, input: []const u8) !PacketDetail {
    const packets = try parse(allocator, input);
    defer allocator.free(packets);
    if (packets.len == 0) return xml.ParseError.UnexpectedEnd;
    if (packets.len > 1) {
        for (packets[1..]) |*p| p.deinit(allocator);
    }
    return packets[0];
}

fn findPacketClose(input: []const u8, content_start: usize) ?usize {
    return xml.findCloseTag(input, content_start, "packet");
}

const ElementParse = struct { node: Node, next: usize };

fn parseElement(allocator: std.mem.Allocator, input: []const u8, pos: usize) !ElementParse {
    const is_proto = pos + 6 <= input.len and std.mem.eql(u8, input[pos + 1 .. pos + 6], "proto");
    const is_field = pos + 6 <= input.len and std.mem.eql(u8, input[pos + 1 .. pos + 6], "field");
    if (!is_proto and !is_field) return xml.ParseError.MalformedTag;

    const tag_name = if (is_proto) "proto" else "field";
    const te = xml.openingTagEnd(input, pos) orelse return xml.ParseError.MalformedTag;
    const tag_slice = input[pos..te.end];

    var node: Node = .{ .is_proto = is_proto };
    try fillAttributes(allocator, &node, tag_slice);

    if (te.self_closing) return .{ .node = node, .next = te.end };

    var children: std.ArrayList(Node) = .empty;
    errdefer {
        for (children.items) |*c| c.deinit(allocator);
        children.deinit(allocator);
        node.deinit(allocator);
    }

    var child_pos = te.end;
    while (child_pos < input.len) {
        child_pos = xml.skipWs(input, child_pos);
        if (child_pos >= input.len) return xml.ParseError.UnexpectedEnd;
        if (input[child_pos] == '<' and child_pos + 1 < input.len and input[child_pos + 1] == '/') {
            const close_end = xml.findCloseTag(input, child_pos, tag_name) orelse return xml.ParseError.MalformedTag;
            node.children = try children.toOwnedSlice(allocator);
            return .{ .node = node, .next = close_end };
        }
        const child = try parseElement(allocator, input, child_pos);
        try children.append(allocator, child.node);
        child_pos = child.next;
    }
    return xml.ParseError.UnexpectedEnd;
}

fn dupAttr(allocator: std.mem.Allocator, tag_slice: []const u8, attr: []const u8) !?[]u8 {
    const raw = xml.getAttribute(tag_slice, attr) orelse return null;
    return try xml.unescapeEntities(allocator, raw);
}

fn fillAttributes(allocator: std.mem.Allocator, node: *Node, tag_slice: []const u8) !void {
    node.name = try dupAttr(allocator, tag_slice, "name");
    node.showname = try dupAttr(allocator, tag_slice, "showname");
    node.show = try dupAttr(allocator, tag_slice, "show");
    node.value = try dupAttr(allocator, tag_slice, "value");
    node.pos = xml.parseU32Attr(xml.getAttribute(tag_slice, "pos"));
    node.size = xml.parseU32Attr(xml.getAttribute(tag_slice, "size"));
    if (xml.getAttribute(tag_slice, "hide")) |h| {
        node.hide = std.mem.eql(u8, h, "yes") or std.mem.eql(u8, h, "true") or std.mem.eql(u8, h, "1");
    }
}

fn extractFrameNumber(nodes: []Node) ?u32 {
    for (nodes) |*root| {
        if (frameFromTree(root)) |n| return n;
    }
    return null;
}

fn frameFromTree(node: *const Node) ?u32 {
    if (node.name) |n| {
        if (std.mem.eql(u8, n, "frame.number") or std.mem.eql(u8, n, "num")) {
            if (node.show) |s| return std.fmt.parseInt(u32, s, 10) catch null;
            if (node.value) |v| return std.fmt.parseInt(u32, v, 10) catch null;
        }
    }
    for (node.children) |*c| {
        if (frameFromTree(c)) |num| return num;
    }
    return null;
}

fn readFixture(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const io = std.testing.io;
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited);
}

test "parse pdml fixture frame and tree" {
    const alloc = std.testing.allocator;
    const fixture = try readFixture(alloc, "tests/fixtures/1.pdml");
    defer alloc.free(fixture);
    const packets = try parse(alloc, fixture);
    defer deinitPackets(alloc, packets);

    try std.testing.expectEqual(@as(usize, 18), packets.len);
    try std.testing.expectEqual(@as(u32, 1), packets[0].frame_number);
    try std.testing.expect(packets[0].nodes.len > 0);

    const eth = findNodeNamed(packets[0].nodes, "eth");
    try std.testing.expect(eth != null);
    try std.testing.expectEqual(@as(?u32, 0), eth.?.pos);
    try std.testing.expectEqual(@as(?u32, 14), eth.?.size);
}

test "entity unescape in showname" {
    const alloc = std.testing.allocator;
    const fixture = try readFixture(alloc, "tests/fixtures/1.pdml");
    defer alloc.free(fixture);
    const packets = try parse(alloc, fixture);
    defer deinitPackets(alloc, packets);
    const ip_flags = findNodeNamedDeep(packets[0].nodes, "ip.flags");
    try std.testing.expect(ip_flags != null);
    try std.testing.expect(ip_flags.?.showname != null);
    try std.testing.expect(std.mem.indexOf(u8, ip_flags.?.showname.?, "Don't") != null);
}

fn findNodeNamed(nodes: []Node, name: []const u8) ?*const Node {
    for (nodes) |*n| {
        if (n.name) |nm| if (std.mem.eql(u8, nm, name)) return n;
    }
    return null;
}

fn findNodeNamedDeep(nodes: []Node, name: []const u8) ?*const Node {
    for (nodes) |*n| {
        if (n.name) |nm| if (std.mem.eql(u8, nm, name)) return n;
        if (findNodeNamedDeep(n.children, name)) |found| return found;
    }
    return null;
}
