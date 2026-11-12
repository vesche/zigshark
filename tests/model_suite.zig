const std = @import("std");
const builtin = @import("builtin");
const zigshark = @import("zigshark");
const packet = zigshark.model.packet;
const session_mod = zigshark.model.session;
const search = zigshark.model.search;
const marks = zigshark.model.marks;
const process = zigshark.shark.process;
const loader_mod = zigshark.model.loader;

fn summary(frame: u32, columns: [][]const u8) packet.PacketSummary {
    return .{ .frame = frame, .columns = columns, .owns_columns = false };
}

test "session sort is numeric for the frame column and keeps the selection" {
    const allocator = std.testing.allocator;
    var session = session_mod.Session.init(allocator, .{ .file = "/tmp/suite.pcap" });
    defer session.deinit();

    var a = [_][]const u8{ "10", "1.5", "aa" };
    var b = [_][]const u8{ "2", "0.2", "bb" };
    var c = [_][]const u8{ "3", "0.1", "cc" };
    var packets = [_]packet.PacketSummary{
        summary(10, &a),
        summary(2, &b),
        summary(3, &c),
    };
    session.setPacketsBorrowed(&packets);
    try std.testing.expect(session.select(0));
    session.setSort(0, true);
    try std.testing.expectEqual(@as(u32, 2), session.packets[0].frame);
    try std.testing.expectEqual(@as(u32, 10), session.packets[2].frame);
    try std.testing.expectEqual(@as(?u32, 10), session.selectedFrame());

    session.setSort(1, true);
    try std.testing.expectEqual(@as(u32, 3), session.packets[0].frame);
}

test "filters, decode-as, and timestamp replace previous values" {
    const allocator = std.testing.allocator;
    var session = session_mod.Session.init(allocator, .{ .file = "/tmp/suite.pcap" });
    defer session.deinit();
    try session.setFilter("tcp", "port 80");
    try session.setFilter("udp", null);
    try std.testing.expectEqualStrings("udp", session.display_filter);
    try std.testing.expectEqualStrings("port 80", session.capture_filter);
    try session.addDecodeAs("tcp.port==80,http");
    try session.addDecodeAs("tcp.port==443,tls");
    try std.testing.expectEqual(@as(usize, 2), session.decode_as_args.items.len);
    try session.setTimestampFormat("ad");
    try session.setTimestampFormat("e");
    try std.testing.expectEqualStrings("e", session.timestamp_format);
    try session.setError("boom");
    try std.testing.expect(session.loading == .error_state);
    try std.testing.expectEqualStrings("boom", session.error_message);
}

test "marks ignore the wrong case and overwrite the same label" {
    const allocator = std.testing.allocator;
    var book = marks.Marks.init(allocator);
    defer book.deinit();
    book.setLocal('A', 1);
    book.setLocal('a', 4);
    book.setLocal('a', 9);
    book.setGlobal('a', 2);
    book.setGlobal('Z', 8);
    try std.testing.expect(book.getLocal('A') == null);
    try std.testing.expectEqual(@as(?u32, 9), book.getLocal('a'));
    try std.testing.expect(book.getGlobal('a') == null);
    try std.testing.expectEqual(@as(?u32, 8), book.getGlobal('Z'));
    try book.bindGlobalPath("/tmp/a.pcap");
    try book.bindGlobalPath("/tmp/b.pcap");
    try std.testing.expectEqualStrings("/tmp/b.pcap", book.global_path.?);
}

test "list search wraps and honors case sensitivity" {
    const allocator = std.testing.allocator;
    var session = session_mod.Session.init(allocator, .{ .file = "/tmp/suite.pcap" });
    defer session.deinit();
    var a = [_][]const u8{"SYN"};
    var b = [_][]const u8{"ack"};
    var c = [_][]const u8{"syn"};
    var packets = [_]packet.PacketSummary{
        summary(1, &a),
        summary(2, &b),
        summary(3, &c),
    };
    session.setPacketsBorrowed(&packets);
    _ = session.select(2);

    var state = search.SearchState{ .case_sensitive = true };
    defer state.deinit(allocator);
    try state.setNeedle(allocator, "SYN");
    const wrapped = search.findNextList(&session, &state, true).?;
    try std.testing.expectEqual(@as(usize, 0), wrapped.packet_index);

    state.case_sensitive = false;
    state.last_index = null;
    _ = session.select(0);
    const hit = search.findNextList(&session, &state, true).?;
    try std.testing.expectEqual(@as(usize, 2), hit.packet_index);
}

test "regex search rejects an open class and matches anchors" {
    try std.testing.expect(search.regexFind("abcdef", "[") == null);
    try std.testing.expectEqual(@as(?usize, 0), search.regexFind("abcdef", "^abc"));
    try std.testing.expect(search.regexFind("abcdef", "^def") == null);
    try std.testing.expectEqual(@as(?usize, 3), search.regexFind("abcdef", "def$"));
    try std.testing.expect(search.regexFind("abcdef", "de$") == null);
    try std.testing.expectEqual(@as(?usize, 0), search.regexFind("abbbc", "ab+c"));
    try std.testing.expectEqual(@as(?usize, 0), search.regexFind("ac", "ab?c"));
    try std.testing.expect(search.regexFind("a1c", "a[^0-9]c") == null);
    try std.testing.expectEqual(@as(?usize, 0), search.regexFind("axc", "a[^0-9]c"));
}

test "byte search does not match a short hex nibble" {
    const allocator = std.testing.allocator;
    const raw = try allocator.dupe(u8, &.{ 0x10, 0x20 });
    defer allocator.free(raw);
    const bytes = packet.PacketBytes{ .frame = 1, .raw = raw, .hexdump_lines = &.{} };
    var state = search.SearchState{ .kind = .hex };
    defer state.deinit(allocator);
    try state.setNeedle(allocator, "f");
    try std.testing.expect(search.findNextBytes(&bytes, &state, 0) == null);
    try state.setNeedle(allocator, "10 20");
    try std.testing.expectEqual(@as(?usize, 0), search.findNextBytes(&bytes, &state, 0));
    try std.testing.expect(search.findNextBytes(&bytes, &state, 1) == null);
}

test "retaining every frame does not reallocate" {
    const allocator = std.testing.allocator;
    var cols = [_][]const u8{"1"};
    const packets = try allocator.alloc(packet.PacketSummary, 1);
    packets[0] = summary(5, &cols);
    const kept = try packet.retainFramesAfter(allocator, packets, 0);
    defer allocator.free(kept);
    try std.testing.expectEqual(@as(usize, 1), kept.len);
    try std.testing.expectEqual(@as(u32, 5), kept[0].frame);
}

test "dropping every frame frees the allocation" {
    const allocator = std.testing.allocator;
    var cols = [_][]const u8{"1"};
    const packets = try allocator.alloc(packet.PacketSummary, 1);
    packets[0] = summary(5, &cols);
    const kept = try packet.retainFramesAfter(allocator, packets, 5);
    defer allocator.free(kept);
    try std.testing.expectEqual(@as(usize, 0), kept.len);
}

test "column format falls back and psml argv uses the override" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqualStrings(process.default_column_format, process.columnFormatOrDefault(null));
    try std.testing.expectEqualStrings(process.default_column_format, process.columnFormatOrDefault(""));
    try std.testing.expectEqualStrings(process.delta_column_format, process.columnFormatOrDefault(process.delta_column_format));

    var argv = try process.argvPsmlLoad(allocator, "tshark", .{ .file = "a.pcap" }, "tcp", process.delta_column_format);
    defer argv.deinit(allocator);
    var saw_delta = false;
    for (argv.slice()) |arg| {
        if (std.mem.indexOf(u8, arg, "%Gt") != null) saw_delta = true;
    }
    try std.testing.expect(saw_delta);
}

test "a cancelled capture does not start the process" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var token = process.CancellationToken{};
    token.cancel(io);
    try std.testing.expectError(
        error.Cancelled,
        process.runCaptureCancellable(allocator, io, &.{ "true" }, &token),
    );
}

test "cancelling a live child does not panic when it has already exited" {
    const io = std.testing.io;
    var i: usize = 0;
    while (i < 30) : (i += 1) {
        var token = process.CancellationToken{};
        const thread = try std.Thread.spawn(.{}, struct {
            fn run(tok: *process.CancellationToken) void {
                var output = process.runCaptureCancellable(
                    std.testing.allocator,
                    std.testing.io,
                    &.{ "sleep", "2" },
                    tok,
                ) catch return;
                output.deinit(std.testing.allocator);
            }
        }.run, .{&token});
        token.cancel(io);
        thread.join();
    }
}

test "one detail window runs pdml and hex together and fills the cache" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tool = try fakeTsharkPath(allocator);
    defer allocator.free(tool);
    const path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/bothwait.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(path);

    var tools = try testingTools(allocator, tool);
    defer tools.deinit();
    var loader = loader_mod.CaptureLoader.init(allocator, io, &tools, .{});
    defer {
        joinWorkers(&loader);
        loader.deinit(io);
    }
    var session = session_mod.Session.init(allocator, .{ .file = path });
    defer session.deinit();

    try loader.requestDetail(&session, 2);
    const pdml_started = try std.fmt.allocPrint(allocator, "{s}.pdml.started", .{path});
    defer allocator.free(pdml_started);
    const hex_started = try std.fmt.allocPrint(allocator, "{s}.hex.started", .{path});
    defer allocator.free(hex_started);
    try waitForPath(io, pdml_started);
    try waitForPath(io, hex_started);
    try expectMissing(io, try marker(allocator, path, ".pdml.finished"));
    try expectMissing(io, try marker(allocator, path, ".hex.finished"));

    const release = try std.fmt.allocPrint(allocator, "{s}.release", .{path});
    defer allocator.free(release);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = release, .data = "go\n" });
    joinWorkers(&loader);

    const cached = loader.detail_cache.get(io, 2) orelse return error.MissingBundle;
    try std.testing.expectEqual(@as(u32, 2), cached.pdml.frame);
    const events = try loader.drainEvents();
    defer allocator.free(events);
    switch (events[0]) {
        .detail_loaded => |bundle| try std.testing.expectEqual(@as(u32, 2), bundle.pdml.frame),
        else => return error.UnexpectedEvent,
    }
    for (events) |*event| event.deinit(allocator);
}

test "a second detail selection cancels the first window" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tool = try fakeTsharkPath(allocator);
    defer allocator.free(tool);
    const slow_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/bothsleep.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(slow_path);
    const fast_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/bothfast.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(fast_path);

    var tools = try testingTools(allocator, tool);
    defer tools.deinit();
    var loader = loader_mod.CaptureLoader.init(allocator, io, &tools, .{});
    defer {
        joinWorkers(&loader);
        loader.deinit(io);
    }
    var session = session_mod.Session.init(allocator, .{ .file = slow_path });
    defer session.deinit();

    try loader.requestDetail(&session, 2);
    const pdml_started = try std.fmt.allocPrint(allocator, "{s}.pdml.started", .{slow_path});
    defer allocator.free(pdml_started);
    const hex_started = try std.fmt.allocPrint(allocator, "{s}.hex.started", .{slow_path});
    defer allocator.free(hex_started);
    try waitForPath(io, pdml_started);
    try waitForPath(io, hex_started);

    const before = std.Io.Timestamp.now(io, .awake).nanoseconds;
    try session.setFileSource(fast_path);
    try loader.requestDetail(&session, 7);
    joinWorkers(&loader);
    const after = std.Io.Timestamp.now(io, .awake).nanoseconds;
    try std.testing.expect(after - before < 3 * std.time.ns_per_s);
    try expectMissing(io, try marker(allocator, slow_path, ".pdml.finished"));
    try expectMissing(io, try marker(allocator, slow_path, ".hex.finished"));
    try std.testing.expect(loader.detail_cache.get(io, 2) == null);
    const kept = loader.detail_cache.get(io, 7) orelse return error.MissingBundle;
    try std.testing.expectEqual(@as(u32, 7), kept.pdml.frame);
}

test "quit cancels a sleeping detail load" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tool = try fakeTsharkPath(allocator);
    defer allocator.free(tool);
    const path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/bothsleep.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(path);

    var tools = try testingTools(allocator, tool);
    defer tools.deinit();
    var loader = loader_mod.CaptureLoader.init(allocator, io, &tools, .{});
    errdefer loader.deinit(io);
    var session = session_mod.Session.init(allocator, .{ .file = path });
    defer session.deinit();

    try loader.requestDetail(&session, 2);
    const pdml_started = try std.fmt.allocPrint(allocator, "{s}.pdml.started", .{path});
    defer allocator.free(pdml_started);
    const hex_started = try std.fmt.allocPrint(allocator, "{s}.hex.started", .{path});
    defer allocator.free(hex_started);
    try waitForPath(io, pdml_started);
    try waitForPath(io, hex_started);

    const before = std.Io.Timestamp.now(io, .awake).nanoseconds;
    loader.deinit(io);
    const elapsed = std.Io.Timestamp.now(io, .awake).nanoseconds - before;
    if (elapsed >= 3 * std.time.ns_per_s) return error.QuitWaitedOnTshark;
    try expectMissing(io, try marker(allocator, path, ".pdml.finished"));
    try expectMissing(io, try marker(allocator, path, ".hex.finished"));
}

fn marker(allocator: std.mem.Allocator, path: []const u8, suffix: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ path, suffix });
}

fn expectMissing(io: std.Io, path: []u8) !void {
    const allocator = std.testing.allocator;
    defer allocator.free(path);
    if (std.Io.Dir.cwd().access(io, path, .{})) |_| return error.ChildWasNotCancelled else |_| {}
}

fn fakeTsharkPath(allocator: std.mem.Allocator) ![]u8 {
    const name = if (builtin.os.tag == .windows) "fake-tshark.exe" else "fake-tshark";
    return std.fmt.allocPrint(allocator, "zig-out/bin/{s}", .{name});
}

fn waitForPath(io: std.Io, path: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    var spins: usize = 0;
    while (spins < 150) : (spins += 1) {
        if (cwd.access(io, path, .{})) |_| return else |_| {
            try std.Io.sleep(io, .fromMilliseconds(20), .awake);
        }
    }
    return error.TimedOut;
}

fn joinWorkers(loader: *loader_mod.CaptureLoader) void {
    loader.joinWorkers();
}

fn testingTools(allocator: std.mem.Allocator, tshark: []const u8) !zigshark.shark.tools.Tools {
    return .{
        .allocator = allocator,
        .tshark = try allocator.dupe(u8, tshark),
        .dumpcap = try allocator.dupe(u8, "dumpcap"),
        .capinfos = try allocator.dupe(u8, "capinfos"),
        .tshark_version = try allocator.dupe(u8, "0.0.0"),
        .dumpcap_version = try allocator.dupe(u8, "0"),
        .capinfos_version = try allocator.dupe(u8, "0"),
        .supports_color = false,
        .dumpcap_can_capture = false,
    };
}

test "lru get refreshes a key and remove returns the value" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var cache = zigshark.cache.lru.Lru(u8, u8).init(allocator, 2);
    defer cache.deinit();
    try cache.put(io, 1, 10);
    try cache.put(io, 2, 20);
    try std.testing.expectEqual(@as(?u8, 10), cache.get(io, 1));
    try cache.put(io, 3, 30);
    try std.testing.expect(cache.get(io, 2) == null);
    try std.testing.expectEqual(@as(?u8, 10), cache.get(io, 1));
    try std.testing.expectEqual(@as(?u8, 30), cache.remove(io, 3));
    try std.testing.expectEqual(@as(usize, 1), cache.len(io));
}
