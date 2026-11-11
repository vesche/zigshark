const std = @import("std");
const zigshark = @import("zigshark");

test "live tshark follow/convs/capinfos against fixture" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    if (!zigshark.shark.tools.tsharkAvailable(io)) return error.SkipZigTest;

    var discovered = try zigshark.shark.tools.discover(allocator, io, .{
        .tshark = "tshark",
        .dumpcap = "dumpcap",
        .capinfos = "capinfos",
    });
    defer discovered.deinit();

    const pcap = "tests/fixtures/1.pcap";

    {
        var argv = try zigshark.shark.process.argvFollowStream(allocator, discovered.tshark, pcap, "tcp", 0);
        defer argv.deinit(allocator);
        var out = try zigshark.shark.process.runCapture(allocator, io, argv.slice());
        defer out.deinit(allocator);
        try std.testing.expect(out.stdout.len > 0);
        try std.testing.expect(std.mem.indexOf(u8, out.stdout, "Follow:") != null);
    }

    {
        var argv = try zigshark.shark.process.argvConversations(allocator, discovered.tshark, pcap, "tcp");
        defer argv.deinit(allocator);
        var out = try zigshark.shark.process.runCapture(allocator, io, argv.slice());
        defer out.deinit(allocator);
        try std.testing.expect(out.stdout.len > 0);
        const parsed = try zigshark.shark.convs.parse(allocator, out.stdout);
        defer {
            for (parsed) |*c| c.deinit(allocator);
            allocator.free(parsed);
        }
        try std.testing.expect(parsed.len > 0);
    }

    {
        var argv = try zigshark.shark.process.argvCapinfos(allocator, discovered.capinfos, pcap);
        defer argv.deinit(allocator);
        var out = try zigshark.shark.process.runCapture(allocator, io, argv.slice());
        defer out.deinit(allocator);
        try std.testing.expect(out.stdout.len > 0);
        var info = try zigshark.shark.capinfo.parse(allocator, out.stdout);
        defer info.deinit(allocator);
        try std.testing.expect(info.packetCount() != null);
    }

    {
        var argv = try zigshark.shark.process.argvPsmlLoad(allocator, discovered.tshark, .{ .file = pcap }, null, null);
        defer argv.deinit(allocator);
        var out = try zigshark.shark.process.runCapture(allocator, io, argv.slice());
        defer out.deinit(allocator);
        try std.testing.expect(out.term.success());
        var table = try zigshark.model.packet.parsePsml(allocator, out.stdout);
        defer table.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 18), table.packets.len);
        try std.testing.expect(table.headers.len >= 7);
    }

    {
        var argv = try zigshark.shark.process.argvPdmlBundle(allocator, discovered.tshark, pcap, null, 1, 1);
        defer argv.deinit(allocator);
        var out = try zigshark.shark.process.runCapture(allocator, io, argv.slice());
        defer out.deinit(allocator);
        try std.testing.expect(out.term.success());
        var detail = try zigshark.model.packet.parsePdmlPacket(allocator, out.stdout, 1);
        defer detail.deinit(allocator);
        try std.testing.expect(detail.root.children.len >= 3);
        try std.testing.expectEqual(@as(u32, 1), detail.frame);
    }

    try std.testing.expect(try zigshark.shark.filter.validateDisplayFilter(
        allocator,
        io,
        discovered.tshark,
        "tests/fixtures/empty.pcap",
        "tcp.port == 443",
    ));
    try std.testing.expect(!try zigshark.shark.filter.validateDisplayFilter(
        allocator,
        io,
        discovered.tshark,
        "tests/fixtures/empty.pcap",
        "this is not a filter",
    ));
}
