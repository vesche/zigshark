const std = @import("std");
const zigshark = @import("zigshark");

fn readFixture(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .unlimited);
}

fn treeHas(node: *const zigshark.model.packet.DetailNode, name: []const u8) bool {
    if (std.mem.eql(u8, node.name, name)) return true;
    for (node.children) |*child| {
        if (treeHas(child, name)) return true;
    }
    return false;
}

fn findNamed(node: *const zigshark.model.packet.DetailNode, name: []const u8) ?*const zigshark.model.packet.DetailNode {
    if (std.mem.eql(u8, node.name, name)) return node;
    for (node.children) |*child| {
        if (findNamed(child, name)) |found| return found;
    }
    return null;
}

test "fixture psml keeps headers, frames, and colors" {
    const allocator = std.testing.allocator;
    const xml = try readFixture(allocator, "tests/fixtures/1.psml");
    defer allocator.free(xml);
    var table = try zigshark.model.packet.parsePsml(allocator, xml);
    defer table.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 7), table.headers.len);
    try std.testing.expectEqualStrings("Protocol", table.headers[4]);
    try std.testing.expectEqual(@as(usize, 18), table.packets.len);
    try std.testing.expectEqual(@as(u32, 1), table.packets[0].frame);
    try std.testing.expectEqual(@as(u32, 18), table.packets[17].frame);
    try std.testing.expectEqualStrings("TLSv1.2", table.packets[0].columns[4]);
}

test "empty and comment-only psml produce no packets" {
    const allocator = std.testing.allocator;
    var table = try zigshark.model.packet.parsePsml(allocator, "<!-- nothing -->\n");
    defer table.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), table.packets.len);
}

test "pdml fixture drops geninfo and hidden fields" {
    const allocator = std.testing.allocator;
    const xml = try readFixture(allocator, "tests/fixtures/1.pdml");
    defer allocator.free(xml);
    var detail = try zigshark.model.packet.parsePdmlPacket(allocator, xml, 1);
    defer detail.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 1), detail.frame);
    try std.testing.expect(!treeHas(&detail.root, "geninfo"));
    try std.testing.expect(!treeHas(&detail.root, "eth.dst_resolved"));
    try std.testing.expect(!treeHas(&detail.root, "ip.addr"));
    try std.testing.expect(treeHas(&detail.root, "eth"));
    try std.testing.expect(treeHas(&detail.root, "ip"));
    try std.testing.expect(treeHas(&detail.root, "tcp"));

    const eth_type = findNamed(&detail.root, "eth.type") orelse return error.MissingField;
    try std.testing.expectEqual(@as(usize, 12), eth_type.pos);
    try std.testing.expectEqual(@as(usize, 2), eth_type.size);
    try std.testing.expect(std.mem.indexOf(u8, eth_type.showname, "IPv4") != null);

    const eth = findNamed(&detail.root, "eth") orelse return error.MissingField;
    try std.testing.expectEqual(@as(usize, 14), eth.size);
}

test "pdml without a packet is an error" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UnexpectedEnd, zigshark.model.packet.parsePdmlPacket(allocator, "<pdml></pdml>", 1));
}

test "hexdump fixture matches the first ethernet header" {
    const allocator = std.testing.allocator;
    const text = try readFixture(allocator, "tests/fixtures/1.hexdump");
    defer allocator.free(text);
    var bytes = try zigshark.model.packet.parseHexdump(allocator, text, 1);
    defer bytes.deinit(allocator);
    try std.testing.expect(bytes.raw.len >= 14);
    try std.testing.expectEqual(@as(u8, 0x08), bytes.raw[12]);
    try std.testing.expectEqual(@as(u8, 0x00), bytes.raw[13]);
}

test "hexdump ignores prose and splits on a blank line" {
    const allocator = std.testing.allocator;
    const text =
        \\not a hex line
        \\0000  aa bb
        \\
        \\0010  cc
        \\
    ;
    const packets = try zigshark.shark.hexdump.parse(allocator, text);
    defer {
        for (packets) |packet| allocator.free(packet);
        allocator.free(packets);
    }
    try std.testing.expectEqual(@as(usize, 2), packets.len);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, packets[0]);
    try std.testing.expectEqualSlices(u8, &.{0xcc}, packets[1]);
}

test "conversation rows skip banners and build filters" {
    const allocator = std.testing.allocator;
    const text =
        \\UDP Conversations
        \\Address A <-> Address B
        \\10.0.0.1:53       <-> 10.0.0.2:9999     1 10 bytes  1 10 bytes  2 20 bytes  0  0.1
        \\this line is junk
    ;
    const rows = try zigshark.shark.convs.parse(allocator, text);
    defer {
        for (rows) |*row| row.deinit(allocator);
        allocator.free(rows);
    }
    try std.testing.expectEqual(@as(usize, 1), rows.len);
    const filter = try zigshark.shark.convs.displayFilter(allocator, rows[0], "udp");
    defer allocator.free(filter);
    try std.testing.expect(std.mem.indexOf(u8, filter, "udp.port == 53") != null);
    try std.testing.expect(std.mem.indexOf(u8, filter, "udp.port == 9999") != null);

    const eth_filter = try zigshark.shark.convs.displayFilter(allocator, rows[0], "eth");
    defer allocator.free(eth_filter);
    try std.testing.expect(std.mem.startsWith(u8, eth_filter, "eth.addr"));
}

test "stream follow parser rejects a truncated hex line and accepts an empty body" {
    const allocator = std.testing.allocator;
    var empty = try zigshark.shark.streams.parse(allocator, "Filter: tcp.stream eq 3\n");
    defer empty.deinit(allocator);
    try std.testing.expectEqualStrings("tcp.stream eq 3", empty.filter);
    try std.testing.expectEqual(@as(usize, 0), empty.chunks.len);

    const bad = try zigshark.shark.streams.frameContainsFilter(allocator, &.{});
    defer allocator.free(bad);
    try std.testing.expectEqualStrings("frame contains ", bad);
}

test "column and field dumps tolerate short rows" {
    const allocator = std.testing.allocator;
    const columns = try zigshark.shark.columns.parse(allocator, "\nnot a column\n%m\tNumber\n");
    defer {
        for (columns) |*column| column.deinit(allocator);
        allocator.free(columns);
    }
    try std.testing.expectEqual(@as(usize, 1), columns.len);
    try std.testing.expect(columns[0].field == null);

    const fields = try zigshark.shark.fields.parse(allocator, "F\tonly-two\nF\tDisplay\tip.src\tFT_IPv4\tbase\n");
    defer {
        for (fields) |*field| field.deinit(allocator);
        allocator.free(fields);
    }
    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqualStrings("ip.src", fields[0].name);
    const matches = zigshark.shark.fields.filterPrefix(fields, "ip.");
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqual(@as(usize, 0), zigshark.shark.fields.filterPrefix(fields, "tcp").len);
}

test "capinfos ignores blank lines and reads the packet count" {
    const allocator = std.testing.allocator;
    var info = try zigshark.shark.capinfo.parse(allocator, "\nNumber of packets:   18\nFile name: one.pcap\n");
    defer info.deinit(allocator);
    try std.testing.expectEqualStrings("18", info.packetCount().?);
    try std.testing.expectEqualStrings("one.pcap", info.fileName().?);
}

test "xml entities and missing attributes" {
    const allocator = std.testing.allocator;
    const text = try zigshark.xml_util.unescapeEntities(allocator, "a&lt;b&gt;c&amp;d");
    defer allocator.free(text);
    try std.testing.expectEqualStrings("a<b>c&d", text);
    try std.testing.expect(zigshark.xml_util.getAttribute("<proto name=\"eth\">", "size") == null);
    try std.testing.expectEqualStrings("eth", zigshark.xml_util.getAttribute("<proto name=\"eth\">", "name").?);
}
