const std = @import("std");
const builtin = @import("builtin");
const zigshark = @import("zigshark");

const app_mod = zigshark.ui.app;
const cli = zigshark.cli;
const config_mod = zigshark.config;
const packet = zigshark.model.packet;
const session_mod = zigshark.model.session;
const loader_mod = zigshark.model.loader;
const paths_mod = zigshark.platform.paths;
const process = zigshark.shark.process;
const tools_mod = zigshark.shark.tools;

const tcp_conversation =
    \\192.168.86.246:42184 <-> 52.20.230.126:443  1 103 bytes  2 195 bytes  3 298 bytes  0.000000000  0.0149
;
const udp_conversation =
    \\10.0.0.1:12345 <-> 10.0.0.2:53  1 10 bytes  1 10 bytes  2 20 bytes  0.1  0.2
;
const eth_conversation =
    \\aa:bb:cc:dd:ee:ff <-> 11:22:33:44:55:6a  1 10 bytes  1 10 bytes  2 20 bytes  0.1  0.2
;
const ip_conversation =
    \\10.1.1.1 <-> 10.2.2.2  1 10 bytes  1 10 bytes  2 20 bytes  0.1  0.2
;
const ipv6_conversation =
    \\2001:db8::a <-> 2001:db8::b  1 10 bytes  1 10 bytes  2 20 bytes  0.1  0.2
;
const follow_text =
    \\===============================================================================
    \\Follow: tcp,raw
    \\Filter: tcp.stream eq 0
    \\Node 0: 192.168.1.1:12345
    \\Node 1: 10.0.0.1:80
    \\===============================================================================
    \\0
    \\00000000  48 65 6c 6c 6f
    \\1
    \\00000000  57 6f 72 6c 64
;
const io_stat_text =
    \\| 0.0 <> 1.0 |      3 |   298 |
    \\| 1.0 <> 2.0 |      5 |   800 |
;
const hierarchy_text =
    \\frame                                    frames:4 bytes:40
    \\  eth                                    frames:4 bytes:40
    \\    ip                                   frames:4 bytes:40
    \\      tcp                                frames:4 bytes:40
    \\        tls                              frames:2 bytes:20
;
const endpoint_text =
    \\TCP Endpoints
    \\10.0.0.9                  443            4   900 bytes           2      400 bytes            2      500 bytes
    \\10.0.0.1                  80             2   100 bytes           1      40 bytes             1      60 bytes
;
const expert_stat =
    \\
    \\Errors (1)
    \\=============
    \\   Frequency      Group           Protocol  Summary
    \\           1   Malformed               TCP  Bad checksum
    \\
    \\Notes (1)
    \\=============
    \\   Frequency      Group           Protocol  Summary
    \\           4       Sequence               TCP  Previous segment not captured
    \\
;
const protocol_text = "Hypertext Transfer Protocol\tHTTP\thttp\tT\tT\tT\n" ++
    "Transport Layer Security\tTLS\ttls\tT\tT\tT\n" ++
    "Domain Name System\tDNS\tdns\tT\tT\tT\n";

const Script = struct {
    allocator: std.mem.Allocator,
    calls: std.ArrayList([]u8) = .empty,

    fn deinit(self: *Script) void {
        for (self.calls.items) |call| self.allocator.free(call);
        self.calls.deinit(self.allocator);
    }

    fn note(self: *Script, argv: []const []const u8) !void {
        var line: std.ArrayList(u8) = .empty;
        errdefer line.deinit(self.allocator);
        for (argv, 0..) |arg, index| {
            if (index != 0) try line.append(self.allocator, '\n');
            try line.appendSlice(self.allocator, arg);
        }
        try self.calls.append(self.allocator, try line.toOwnedSlice(self.allocator));
    }

    fn saw(self: *const Script, needle: []const u8) bool {
        for (self.calls.items) |call| {
            if (std.mem.indexOf(u8, call, needle) != null) return true;
        }
        return false;
    }
};

threadlocal var active_script: ?*Script = null;

fn scriptedRun(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
) !process.RunOutput {
    _ = io;
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "boom")) return error.ToolFailed;
    }
    const script = active_script orelse return error.NoScript;
    try script.note(argv);
    var failed = false;
    for (argv) |arg| {
        if (std.mem.indexOf(u8, arg, "nope") != null) failed = true;
    }
    const stdout = try replyFor(allocator, argv);
    return .{
        .stdout = stdout,
        .stderr = try allocator.dupe(u8, if (failed) "tshark: \"nope\" was unexpected\n" else ""),
        .term = .{ .exited = if (failed) @as(u8, 1) else 0 },
    };
}

fn commentListReply(allocator: std.mem.Allocator) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    try body.appendSlice(allocator, "4\thello\n9\t\n12\tnote two\n");
    var extra: usize = 0;
    while (extra < 199) : (extra += 1) try body.appendSlice(allocator, "4\tagain\n");
    return try body.toOwnedSlice(allocator);
}

fn argvHas(argv: []const []const u8, needle: []const u8) bool {
    for (argv) |arg| if (std.mem.eql(u8, arg, needle)) return true;
    return false;
}

fn replyFor(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    if (argvHas(argv, "dns.qry.name")) return allocator.dupe(u8, "4\texample.com\t0\n");
    if (argvHas(argv, "http.request.method")) return allocator.dupe(u8, "7\tM-SEARCH\t\t*\t\n");
    if (argvHas(argv, "frame.number") and argvHas(argv, "frame.comment")) return commentListReply(allocator);
    if (argvHas(argv, "frame.comment")) return allocator.dupe(u8, "saved note\n");
    if (argvHas(argv, "ip.src")) {
        for (argv) |item| if (std.mem.indexOf(u8, item, "other.pcap") != null) {
            return allocator.dupe(u8, "9\t10.9.9.9\t10.8.8.8\t9\t\t\t99\n");
        };
        return allocator.dupe(u8, "1\t10.0.0.1\t10.0.0.2\t80\t\t\t\t60\n2\t10.0.0.9\t10.0.0.8\t\t\t53\t\t40\n");
    }
    for (argv) |arg| {
        if (std.mem.startsWith(u8, arg, "conv,")) {
            if (std.mem.endsWith(u8, arg, "udp")) return allocator.dupe(u8, udp_conversation);
            if (std.mem.endsWith(u8, arg, "eth")) return allocator.dupe(u8, eth_conversation);
            if (std.mem.endsWith(u8, arg, "ipv6")) return allocator.dupe(u8, ipv6_conversation);
            if (std.mem.endsWith(u8, arg, "ip")) return allocator.dupe(u8, ip_conversation);
            return allocator.dupe(u8, tcp_conversation);
        }
        if (std.mem.startsWith(u8, arg, "follow,")) return allocator.dupe(u8, follow_text);
        if (std.mem.eql(u8, arg, "io,phs")) return allocator.dupe(u8, hierarchy_text);
        if (std.mem.startsWith(u8, arg, "io,stat,")) return allocator.dupe(u8, io_stat_text);
        if (std.mem.startsWith(u8, arg, "lua_script:")) return allocator.dupe(u8, "lua ok\n");
        if (std.mem.startsWith(u8, arg, "endpoints,")) return allocator.dupe(u8, endpoint_text);
        if (std.mem.eql(u8, arg, "protocols")) return allocator.dupe(u8, protocol_text);
        if (std.mem.indexOf(u8, arg, "_ws.expert.message") != null) return allocator.dupe(u8, "12\n");
        if (std.mem.eql(u8, arg, "expert")) return allocator.dupe(u8, expert_stat);
        if (std.mem.eql(u8, arg, "frame.number")) return allocator.dupe(u8, "1\n4\n9\n");
    }
    return allocator.dupe(u8, "");
}

const Harness = struct {
    allocator: std.mem.Allocator = undefined,
    io: std.Io = undefined,
    tmp: std.testing.TmpDir = undefined,
    paths: paths_mod.Paths = undefined,
    cfg: config_mod.Config = undefined,
    tools: tools_mod.Tools = undefined,
    session: session_mod.Session = undefined,
    loader: loader_mod.CaptureLoader = undefined,
    script: Script = undefined,
    app: app_mod.AppModel = undefined,

    fn setup(self: *Harness) !void {
        const allocator = std.testing.allocator;
        const io = std.testing.io;
        self.allocator = allocator;
        self.io = io;
        self.tmp = std.testing.tmpDir(.{});
        errdefer self.tmp.cleanup();

        self.paths = .{
            .allocator = allocator,
            .config_dir = try allocator.alloc(u8, 0),
            .cache_dir = try allocator.alloc(u8, 0),
            .data_dir = try allocator.alloc(u8, 0),
            .log_path = try allocator.alloc(u8, 0),
        };
        errdefer self.paths.deinit();
        try self.replacePath(&self.paths.config_dir, "home");
        try self.replacePath(&self.paths.cache_dir, "cache");
        try self.replacePath(&self.paths.data_dir, "data");
        const log_path = try std.fs.path.join(allocator, &.{ self.paths.cache_dir, "zigshark.log" });
        allocator.free(self.paths.log_path);
        self.paths.log_path = log_path;
        const cwd = std.Io.Dir.cwd();
        try cwd.createDirPath(io, self.paths.config_dir);
        try cwd.createDirPath(io, self.paths.cache_dir);

        self.cfg = try config_mod.Config.defaults(allocator);
        errdefer self.cfg.deinit();
        self.tools = try fakeTools(allocator);
        errdefer self.tools.deinit();
        self.session = session_mod.Session.init(allocator, .{ .file = "tests/fixtures/1.pcap" });
        errdefer self.session.deinit();
        self.loader = loader_mod.CaptureLoader.init(allocator, io, &self.tools, .{});
        self.loader.defer_spawn = true;
        errdefer self.loader.deinit(io);
        self.script = .{ .allocator = allocator };
        errdefer self.script.deinit();

        const opts: cli.Options = .{};
        try self.app.initOffline(allocator, io, .{
            .config = &self.cfg,
            .tools = &self.tools,
            .session = &self.session,
            .loader = &self.loader,
            .paths = &self.paths,
            .cli = opts,
        });
        self.app.process_runner = scriptedRun;
        active_script = &self.script;
    }

    fn teardown(self: *Harness) void {
        if (active_script == &self.script) active_script = null;
        self.app.deinit();
        self.script.deinit();
        self.loader.deinit(self.io);
        self.session.deinit();
        self.tools.deinit();
        self.cfg.deinit();
        self.paths.deinit();
        self.tmp.cleanup();
    }

    fn replacePath(self: *Harness, slot: *[]u8, name: []const u8) !void {
        const joined = try std.fs.path.join(self.allocator, &.{
            ".zig-cache",
            "tmp",
            self.tmp.sub_path[0..],
            name,
        });
        self.allocator.free(slot.*);
        slot.* = joined;
    }

    fn setFrames(self: *Harness, frames: []const u32) !void {
        var table = try tableOf(self.allocator, frames);
        self.session.setListHeaders(table.headers);
        table.headers = &.{};
        self.session.setPackets(table.packets);
    }

    fn setFields(self: *Harness, names: []const []const u8) !void {
        const fields = try self.allocator.alloc([]u8, names.len);
        for (names, 0..) |name, index| fields[index] = try self.allocator.dupe(u8, name);
        self.app.fields = fields;
        self.app.fields_ready.store(true, .release);
    }

    fn expectBar(self: *Harness, expected: []const u8) !void {
        const text = try self.app.filter.copyText(self.allocator);
        defer self.allocator.free(text);
        try std.testing.expectEqualStrings(expected, text);
    }

    fn columnFormat(self: *const Harness) []const u8 {
        const argv = self.loader.psml_argv.slice();
        for (argv, 0..) |arg, index| {
            if (std.mem.eql(u8, arg, "-o") and index + 1 < argv.len) return argv[index + 1];
        }
        return "";
    }
};

fn fakeTools(allocator: std.mem.Allocator) !tools_mod.Tools {
    return .{
        .allocator = allocator,
        .tshark = try allocator.dupe(u8, "tshark"),
        .dumpcap = try allocator.dupe(u8, "dumpcap"),
        .capinfos = try allocator.dupe(u8, "capinfos"),
        .tshark_version = try allocator.dupe(u8, "0.0.0"),
        .dumpcap_version = try allocator.dupe(u8, "0.0.0"),
        .capinfos_version = try allocator.dupe(u8, "0.0.0"),
        .supports_color = false,
        .dumpcap_can_capture = false,
    };
}

fn tableOf(allocator: std.mem.Allocator, frames: []const u32) !packet.PsmlTable {
    const headers = try allocator.alloc([]u8, 1);
    errdefer allocator.free(headers);
    headers[0] = try allocator.dupe(u8, "No.");
    errdefer allocator.free(headers[0]);
    const packets = try allocator.alloc(packet.PacketSummary, frames.len);
    var filled: usize = 0;
    errdefer {
        for (packets[0..filled]) |*summary| summary.deinit(allocator);
        allocator.free(packets);
    }
    for (frames) |frame| {
        const columns = try allocator.alloc([]const u8, 1);
        errdefer allocator.free(columns);
        columns[0] = try std.fmt.allocPrint(allocator, "{d}", .{frame});
        packets[filled] = .{ .frame = frame, .columns = columns };
        filled += 1;
    }
    return .{ .headers = headers, .packets = packets };
}

fn leaf(
    allocator: std.mem.Allocator,
    name: []const u8,
    showname: []const u8,
    show: []const u8,
    pos: usize,
    size: usize,
) !packet.DetailNode {
    return .{
        .name = try allocator.dupe(u8, name),
        .showname = try allocator.dupe(u8, showname),
        .show = try allocator.dupe(u8, show),
        .pos = pos,
        .size = size,
        .children = try allocator.alloc(packet.DetailNode, 0),
    };
}

fn installDetail(h: *Harness, children: []packet.DetailNode, raw: []const u8) !void {
    const root = packet.DetailNode{
        .name = try h.allocator.dupe(u8, "__packet_root"),
        .showname = try h.allocator.dupe(u8, ""),
        .show = try h.allocator.dupe(u8, ""),
        .pos = 0,
        .size = 0,
        .children = children,
    };
    h.app.detail_bundle = .{
        .pdml = .{ .frame = 1, .root = root },
        .bytes = .{
            .frame = 1,
            .raw = try h.allocator.dupe(u8, raw),
            .hexdump_lines = try h.allocator.alloc([]const u8, 0),
        },
    };
    h.app.hex.raw = h.app.detail_bundle.?.bytes.raw;
    h.app.protocol_tree.setRoot(&h.app.detail_bundle.?.pdml.root);
}

fn readFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .unlimited);
}

test "commands run without a tty" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();

    try h.setFrames(&.{ 1, 4, 9 });
    try h.app.session.setFilter("dns", null);
    try h.app.runCommand("search-filter", "tcp.port == 80");
    try std.testing.expect(h.script.saw("frame.number"));
    try std.testing.expect(h.script.saw("tcp.port == 80"));
    try std.testing.expectEqual(@as(?u32, 4), h.app.session.selectedFrame());
    try std.testing.expectEqualStrings("dns", h.app.session.display_filter);

    try h.app.runCommand("convs", "tcp");
    try std.testing.expect(h.script.saw("conv,tcp"));
    try std.testing.expect(h.app.overlay == .convs);

    try h.app.applyMark('a', false, false);
    try std.testing.expectEqualStrings("Mark set", h.app.msg_overlay.body);
    try std.testing.expect(h.app.session.select(0));
    try h.app.applyMark('a', false, true);
    try std.testing.expectEqual(@as(?u32, 4), h.app.session.selectedFrame());

    try std.testing.expect(h.app.session.select(2));
    try h.app.applyMark('Q', true, false);
    try std.testing.expect(h.app.session.select(0));
    try h.app.applyMark('Q', true, true);
    try std.testing.expectEqual(@as(?u32, 9), h.app.session.selectedFrame());

    try h.app.config.setGlobalMark('C', "other.pcap", 7, null);
    try h.app.applyMark('C', true, true);
    try std.testing.expectEqual(@as(?u32, 7), h.app.pending_global_frame);
    switch (h.app.session.source) {
        .file => |path| try std.testing.expectEqualStrings("other.pcap", path),
        else => return error.UnexpectedSource,
    }
    try h.app.loader.pushEvent(.{ .packets_loaded = try tableOf(h.allocator, &.{ 2, 7 }) });
    try h.app.processLoaderEvents();
    try std.testing.expectEqual(@as(?u32, 7), h.app.session.selectedFrame());
    try std.testing.expect(h.app.pending_global_frame == null);
}

test "filter completion cycles the original stem" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.setFields(&.{ "ip.src", "ip.dst", "ipv6.src", "tcp.port", "tcp.flags" });

    try h.app.filter.setText("not ip");
    try std.testing.expect(try h.app.completeFilter(true));
    try h.expectBar("not ip.src");
    try std.testing.expectEqualStrings(" complete 1/3", h.app.status.mode);

    try std.testing.expect(try h.app.completeFilter(true));
    try h.expectBar("not ip.dst");
    try std.testing.expectEqualStrings(" complete 2/3", h.app.status.mode);

    try std.testing.expect(try h.app.completeFilter(true));
    try h.expectBar("not ipv6.src");
    try std.testing.expectEqualStrings(" complete 3/3", h.app.status.mode);

    try std.testing.expect(try h.app.completeFilter(true));
    try h.expectBar("not ip.src");
    try std.testing.expectEqualStrings(" complete 1/3", h.app.status.mode);

    try std.testing.expect(try h.app.completeFilter(false));
    try h.expectBar("not ipv6.src");
    try std.testing.expectEqualStrings(" complete 3/3", h.app.status.mode);

    try h.app.filter.setText("ipv6");
    try std.testing.expect(try h.app.completeFilter(true));
    try h.expectBar("ipv6.src");
    try std.testing.expectEqualStrings(" complete 1/1", h.app.status.mode);

    try h.app.filter.setText("tcp");
    try std.testing.expect(try h.app.completeFilter(false));
    try h.expectBar("tcp.flags");
    try std.testing.expectEqualStrings(" complete 2/2", h.app.status.mode);
}

test "clear-packets cutoff survives the next load until a file is opened" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();

    try h.setFrames(&.{ 2, 3 });
    try h.app.runCommand("clear-packets", "");
    try std.testing.expectEqual(@as(u32, 0), h.app.hide_through_frame);

    h.app.live_capture = true;
    try h.setFrames(&.{ 2, 3 });
    try h.app.runCommand("clear-packets", "");
    try std.testing.expectEqual(@as(u32, 3), h.app.hide_through_frame);
    try std.testing.expectEqual(@as(usize, 0), h.app.session.packets.len);

    try h.app.loader.pushEvent(.{ .packets_loaded = try tableOf(h.allocator, &.{ 3, 4 }) });
    try h.app.processLoaderEvents();
    try std.testing.expectEqual(@as(usize, 1), h.app.session.packets.len);
    try std.testing.expectEqual(@as(u32, 4), h.app.session.packets[0].frame);

    h.app.tailing = true;
    try h.setFrames(&.{ 8, 9 });
    try h.app.runCommand("clear-packets", "");
    try std.testing.expectEqual(@as(u32, 9), h.app.hide_through_frame);

    try h.app.runCommand("load", "other.pcap");
    try std.testing.expectEqual(@as(u32, 0), h.app.hide_through_frame);
    try std.testing.expect(!h.app.live_capture);
    try h.app.loader.pushEvent(.{ .packets_loaded = try tableOf(h.allocator, &.{ 1, 2 }) });
    try h.app.processLoaderEvents();
    try std.testing.expectEqual(@as(usize, 2), h.app.session.packets.len);
    try std.testing.expectEqual(@as(u32, 1), h.app.session.packets[0].frame);
    try std.testing.expectEqual(@as(u32, 2), h.app.session.packets[1].frame);
}

test "hex cursor selects the covering field once and does not snap back" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();

    const children = try h.allocator.alloc(packet.DetailNode, 2);
    children[0] = try leaf(h.allocator, "eth", "Ethernet", "", 0, 14);
    children[1] = try leaf(h.allocator, "ip", "IPv4", "", 14, 20);
    var raw: [40]u8 = @splat(0);
    try installDetail(&h, children, &raw);

    var hits: usize = 0;
    h.app.protocol_tree.cover_probe = &hits;
    h.app.hex.setCursor(20, true);
    try std.testing.expectEqual(@as(usize, 1), hits);
    try std.testing.expectEqual(@as(usize, 20), h.app.hex.cursor);
    const ipv4 = h.app.protocol_tree.selectedHighlight();
    try std.testing.expectEqual(@as(usize, 14), ipv4.pos);
    try std.testing.expectEqual(@as(usize, 20), ipv4.size);
    try std.testing.expectEqual(@as(usize, 14), h.app.hex.highlight_pos);
    try std.testing.expect(std.mem.indexOf(u8, h.app.protocol_tree.selectedText(), "IPv4") != null);

    h.app.hex.setCursor(2, true);
    try std.testing.expectEqual(@as(usize, 2), hits);
    try std.testing.expectEqual(@as(usize, 2), h.app.hex.cursor);
    const eth = h.app.protocol_tree.selectedHighlight();
    try std.testing.expectEqual(@as(usize, 0), eth.pos);
    try std.testing.expectEqual(@as(usize, 14), eth.size);
}

test "column presets are the psml format string" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();

    try h.app.runCommand("columns", "delta");
    try std.testing.expectEqualStrings(process.delta_column_format, h.columnFormat());
    try h.app.runCommand("columns", "absolute");
    try std.testing.expectEqualStrings(process.absolute_column_format, h.columnFormat());
    try h.app.runCommand("columns", "set gui.column.format:\"No.\",\"%m\"");
    try std.testing.expectEqualStrings("gui.column.format:\"No.\",\"%m\"", h.columnFormat());
    try h.app.runCommand("columns", "default");
    try std.testing.expectEqual(@as(usize, 0), h.cfg.column_format.len);
    try std.testing.expectEqualStrings(process.default_column_format, h.columnFormat());
}

test "stream follows tcp before udp and a chunk does not replace the list filter" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.setFrames(&.{ 1, 4, 9 });
    try h.app.session.setFilter("dns", null);

    const both = try h.allocator.alloc(packet.DetailNode, 2);
    both[0] = try leaf(h.allocator, "tcp.stream", "tcp.stream", "4", 0, 1);
    both[1] = try leaf(h.allocator, "udp.stream", "udp.stream", "9", 1, 1);
    try installDetail(&h, both, "Hello");
    try h.app.runCommand("streams", "");
    try std.testing.expect(h.script.saw("follow,tcp,hex,4"));
    try std.testing.expect(!h.script.saw("follow,udp"));
    try std.testing.expectEqualStrings("dns", h.app.session.display_filter);

    try h.app.activatePick();
    try std.testing.expect(h.script.saw("frame contains 48:65:6c:6c:6f"));
    try std.testing.expect(h.script.saw("tcp.stream eq 0"));
    try std.testing.expectEqualStrings("dns", h.app.session.display_filter);

    const udp_only = try h.allocator.alloc(packet.DetailNode, 1);
    udp_only[0] = try leaf(h.allocator, "udp.stream", "udp.stream", "9", 0, 1);
    if (h.app.detail_bundle) |*bundle| bundle.deinit(h.allocator);
    h.app.detail_bundle = null;
    try installDetail(&h, udp_only, "Hello");
    try h.app.runCommand("streams", "");
    try std.testing.expect(h.script.saw("follow,udp,hex,9"));
}

test "conversation enter builds tcp udp eth ip and ipv6 filters" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();

    try h.app.runCommand("convs", "tcp");
    try h.app.activatePick();
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "tcp.port == 42184") != null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "tcp.port == 443") != null);

    try h.app.runCommand("convs", "udp");
    try h.app.activatePick();
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "udp.port == 12345") != null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "udp.port == 53") != null);

    try h.app.runCommand("convs", "eth");
    try h.app.activatePick();
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "eth.addr == aa:bb:cc:dd:ee:ff") != null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "eth.addr == 11:22:33:44:55:6a") != null);

    try h.app.runCommand("convs", "ip");
    try h.app.activatePick();
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "ip.addr == 10.1.1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "ipv6") == null);

    try h.app.runCommand("convs", "ipv6");
    try h.app.activatePick();
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "ipv6.addr == 2001:db8::a") != null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "ipv6.addr == 2001:db8::b") != null);
}

test "set rejects a bad value and an unknown key without rewriting the file" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();

    try h.app.runCommand("set", "pager less");
    try std.testing.expectEqualStrings("less", h.cfg.pager);
    try std.testing.expectEqualStrings("Option updated", h.app.msg_overlay.body);

    const path = try h.paths.configFile(h.allocator);
    defer h.allocator.free(path);
    const saved = try readFile(h.allocator, h.io, path);
    defer h.allocator.free(saved);
    const marked = try std.fmt.allocPrint(h.allocator, "{s}\n# keep-me\n", .{saved});
    defer h.allocator.free(marked);
    try std.Io.Dir.cwd().writeFile(h.io, .{ .sub_path = path, .data = marked });

    try h.app.runCommand("set", "nope 1");
    const after_unknown = try readFile(h.allocator, h.io, path);
    defer h.allocator.free(after_unknown);
    try std.testing.expect(std.mem.indexOf(u8, after_unknown, "# keep-me") != null);
    try std.testing.expectEqualStrings("less", h.cfg.pager);
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "Unknown setting") != null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "Option updated") == null);

    try h.app.runCommand("set", "layout diagonal");
    const after_bad = try readFile(h.allocator, h.io, path);
    defer h.allocator.free(after_bad);
    try std.testing.expect(std.mem.indexOf(u8, after_bad, "# keep-me") != null);
    try std.testing.expect(h.cfg.layout == .stacked);
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "not valid") != null);

    try h.app.runCommand("set", "pager more");
    const after_ok = try readFile(h.allocator, h.io, path);
    defer h.allocator.free(after_ok);
    try std.testing.expect(std.mem.indexOf(u8, after_ok, "# keep-me") == null);
    try std.testing.expect(std.mem.indexOf(u8, after_ok, "pager = \"more\"") != null);
    try std.testing.expectEqualStrings("more", h.cfg.pager);
    try std.testing.expectEqualStrings("Option updated", h.app.msg_overlay.body);
}

test "goto selects a frame and reports a miss" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.setFrames(&.{ 1, 4, 9 });

    try h.app.runCommand("goto", "4");
    try std.testing.expectEqual(@as(?u32, 4), h.app.session.selectedFrame());

    try h.app.runCommand("goto", "99");
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "not in the list") != null);
    try std.testing.expectEqual(@as(?u32, 4), h.app.session.selectedFrame());
}

test "field filter can prepare without reloading and apply when asked" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    const children = try h.allocator.alloc(zigshark.model.packet.DetailNode, 1);
    children[0] = try leaf(h.allocator, "tcp.srcport", "Source Port: 443", "443", 0, 2);
    try installDetail(&h, children, "abcd");

    try h.app.chooseFieldFilter(6);
    try h.expectBar("tcp.srcport == 443");
    try std.testing.expectEqual(@as(usize, 0), h.app.session.display_filter.len);

    try h.app.session.setFilter("dns", null);
    try h.app.chooseFieldFilter(2);
    try std.testing.expectEqualStrings("dns and (tcp.srcport == 443)", h.app.session.display_filter);
}

test "filter bar recalls recent filters and an empty bar shows the list" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.cfg.addRecentFilter("tcp");
    try h.cfg.addRecentFilter("udp");

    try h.app.filter.setText("");
    try h.app.recallRecent(true);
    try h.expectBar("udp");
    try std.testing.expect(std.mem.indexOf(u8, h.app.status.mode, "recent 1/2") != null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.status.mode, "tcp") != null);

    try h.app.recallRecent(true);
    try h.expectBar("tcp");
    try std.testing.expect(std.mem.indexOf(u8, h.app.status.mode, "recent 2/2") != null);
}

test "a recent filter can be selected and clear restores the full list" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.cfg.addRecentFilter("dns");
    try h.cfg.addRecentFilter("tcp.port == 443");

    try h.app.openRecentFilters();
    try std.testing.expect(h.app.help_overlay.visible);
    try std.testing.expect(h.app.help_overlay.pick);
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "tcp.port == 443") != null);
    h.app.help_overlay.selected = 0;
    try h.app.activatePick();
    try std.testing.expectEqualStrings("tcp.port == 443", h.app.session.display_filter);
    try h.expectBar("tcp.port == 443");
    try std.testing.expect(!h.app.help_overlay.visible);

    try h.app.clearDisplayFilter();
    try h.expectBar("");
    try std.testing.expectEqual(@as(usize, 0), h.app.session.display_filter.len);
    try std.testing.expect(h.app.filter.state == .neutral);
}

test "saved filters apply by name and macros show before submit" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.cfg.upsertNamedFilter("web", "tcp.port == 443");
    try h.app.runCommand("filters", "web");
    try std.testing.expectEqualStrings("tcp.port == 443", h.app.session.display_filter);

    try h.cfg.macros.append(h.allocator, .{
        .name = try h.allocator.dupe(u8, "web"),
        .value = try h.allocator.dupe(u8, "tcp.port == 443"),
    });
    try h.app.filter.setText("ip.addr == $web");
    h.app.pollFilterFeedback();
    try std.testing.expectEqualStrings("ip.addr == tcp.port == 443", h.app.status.expansion);
}

test "filter feedback waits for a pause and shows the tshark error" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    h.app.filter_check_sync = true;

    try h.app.filter.setText("nope");
    h.app.pollFilterFeedback();
    try std.testing.expect(h.app.filter.state == .neutral);

    h.app.pollFilterFeedback();
    h.app.pollFilterFeedback();
    h.app.pollFilterFeedback();
    try std.testing.expect(h.app.filter.state == .bad);
    try std.testing.expect(std.mem.indexOf(u8, h.app.status.filter_error, "unexpected") != null);

    try h.app.filter.setText("");
    h.app.pollFilterFeedback();
    h.app.pollFilterFeedback();
    h.app.pollFilterFeedback();
    h.app.pollFilterFeedback();
    try std.testing.expect(h.app.filter.state == .neutral);
    try std.testing.expectEqual(@as(usize, 0), h.app.status.filter_error.len);
    try std.testing.expectEqual(@as(usize, 0), h.app.session.display_filter.len);
}

test "a settled display filter reloads the packet list" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    h.app.filter_check_sync = true;

    try h.app.filter.setText("tcp.port == 443");
    var i: usize = 0;
    while (i < 4) : (i += 1) h.app.pollFilterFeedback();
    try std.testing.expect(h.app.filter.state == .ok);
    try std.testing.expectEqualStrings("tcp.port == 443", h.app.session.display_filter);
    var saw_filter = false;
    const argv = h.loader.psml_argv.slice();
    for (argv, 0..) |arg, index| {
        if (std.mem.eql(u8, arg, "-Y") and index + 1 < argv.len) {
            try std.testing.expectEqualStrings("tcp.port == 443", argv[index + 1]);
            saw_filter = true;
        }
    }
    try std.testing.expect(saw_filter);

    try h.app.filter.setText("");
    i = 0;
    while (i < 4) : (i += 1) h.app.pollFilterFeedback();
    try std.testing.expectEqual(@as(usize, 0), h.app.session.display_filter.len);
    for (h.loader.psml_argv.slice()) |arg| {
        try std.testing.expect(!std.mem.eql(u8, arg, "-Y"));
    }
}

test "theme load falls back from the config directory to themes/" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();

    try h.app.runCommand("theme", "midnight");
    try std.testing.expect(h.app.theme.accent.eql(zigshark.ui.theme.rgb(0xf7, 0x81, 0x66)));

    const themes_dir = try h.paths.themesDir(h.allocator);
    defer h.allocator.free(themes_dir);
    try std.Io.Dir.cwd().createDirPath(h.io, themes_dir);
    const override = try std.fs.path.join(h.allocator, &.{ themes_dir, "midnight.toml" });
    defer h.allocator.free(override);
    try std.Io.Dir.cwd().writeFile(h.io, .{
        .sub_path = override,
        .data = "accent = \"#010203\"\n",
    });
    try h.app.runCommand("theme", "midnight");
    try std.testing.expect(h.app.theme.accent.eql(zigshark.ui.theme.rgb(1, 2, 3)));
}

fn ownedSummary(allocator: std.mem.Allocator, frame: u32) !packet.PacketSummary {
    const columns = try allocator.alloc([]const u8, 1);
    columns[0] = try std.fmt.allocPrint(allocator, "{d}", .{frame});
    return .{ .frame = frame, .columns = columns };
}

test "a later packet chunk keeps the selected frame" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();

    const headers = try h.allocator.alloc([]u8, 1);
    headers[0] = try h.allocator.dupe(u8, "No.");
    const first = try h.allocator.alloc(packet.PacketSummary, 2);
    first[0] = try ownedSummary(h.allocator, 1);
    first[1] = try ownedSummary(h.allocator, 2);
    try h.app.loader.pushEvent(.{ .packets_loaded = .{
        .headers = headers,
        .packets = first,
    } });
    try h.app.processLoaderEvents();
    try std.testing.expect(h.app.session.select(1));

    const more = try h.allocator.alloc(packet.PacketSummary, 1);
    more[0] = try ownedSummary(h.allocator, 3);
    try h.app.loader.pushEvent(.{ .packets_loaded = .{
        .packets = more,
        .append = true,
    } });
    try h.app.processLoaderEvents();
    try std.testing.expectEqual(@as(usize, 3), h.app.session.packets.len);
    try std.testing.expectEqual(@as(u32, 2), h.app.session.selectedFrame().?);
}

test "applying the loaded filter does not request the list again" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.app.commitFilter("dns", true);
    const generation = h.app.loader.list_generation.load(.acquire);
    try h.app.commitFilter("dns", true);
    try std.testing.expectEqual(generation, h.app.loader.list_generation.load(.acquire));
    try h.app.commitFilter("tcp", true);
    try std.testing.expectEqual(generation + 1, h.app.loader.list_generation.load(.acquire));
}

fn manyConversations(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
) !process.RunOutput {
    _ = io;
    _ = argv;
    var text: std.Io.Writer.Allocating = .init(allocator);
    errdefer text.deinit();
    var index: usize = 0;
    while (index < process.view_row_cap + 5) : (index += 1) {
        try text.writer.print(
            "10.0.0.1 <-> 10.0.0.2  1 {d} bytes  1 1 bytes  2 2 bytes  0  0.1\n",
            .{index + 1},
        );
    }
    return .{
        .stdout = try text.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .term = .{ .exited = 0 },
    };
}

fn manyChunks(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
) !process.RunOutput {
    _ = io;
    _ = argv;
    var text: std.Io.Writer.Allocating = .init(allocator);
    errdefer text.deinit();
    try text.writer.writeAll("Filter: tcp.stream eq 7\nNode 0: a\nNode 1: b\n");
    var index: usize = 0;
    while (index < process.view_row_cap + 5) : (index += 1) {
        try text.writer.print("{d}\n00000000  61\n", .{index % 2});
    }
    return .{
        .stdout = try text.toOwnedSlice(),
        .stderr = try allocator.dupe(u8, ""),
        .term = .{ .exited = 0 },
    };
}

test "conversation and stream views stop at the row cap" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();

    h.app.process_runner = manyConversations;
    try h.app.runCommand("convs", "tcp");
    try std.testing.expectEqual(process.view_row_cap, h.app.conversations.len);
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "Stopped after 200 rows") != null);

    h.app.process_runner = manyChunks;
    try h.app.runCommand("streams", "tcp 0");
    try std.testing.expectEqual(process.view_row_cap, h.app.stream_chunks.len);
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "Stopped after 200 rows") != null);
}

test "expert info comes from the open packet and time zero is local" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();

    const chat = try leaf(h.allocator, "_ws.expert", "Expert Info (Chat/Sequence): hello", "", 0, 0);
    const warning = try leaf(h.allocator, "_ws.expert", "Expert Info (Warning/Malformed): bad", "", 0, 0);
    const children = try h.allocator.alloc(packet.DetailNode, 2);
    children[0] = chat;
    children[1] = warning;
    try installDetail(&h, children, "");
    try h.app.runCommand("expert", "");
    try std.testing.expectEqual(@as(usize, 2), h.app.expert_items.len);
    try std.testing.expect(h.app.overlay == .expert);
    try std.testing.expect(std.mem.startsWith(u8, h.app.help_overlay.body, "warning"));
    try h.app.activatePick();
    const selected = h.app.protocol_tree.selectedField() orelse return error.MissingField;
    try std.testing.expectEqualStrings("_ws.expert", selected.name);

    const headers = try h.allocator.alloc([]u8, 2);
    headers[0] = try h.allocator.dupe(u8, "No.");
    headers[1] = try h.allocator.dupe(u8, "Time");
    h.app.session.setListHeaders(headers);
    const packets = try h.allocator.alloc(packet.PacketSummary, 2);
    packets[0] = try timedRow(h.allocator, 1, "1.000000");
    packets[1] = try timedRow(h.allocator, 2, "1.250000");
    h.app.session.setPackets(packets);
    try std.testing.expect(h.app.session.select(0));
    try h.app.toggleTimeReference();
    try std.testing.expectEqual(@as(?f64, 1), h.app.packet_table.time_base);
    try std.testing.expect(h.app.session.select(1));
    try h.app.toggleTimeReference();
    try std.testing.expectEqual(@as(?u32, 2), h.app.time_reference_frame);
    try h.app.toggleTimeReference();
    try std.testing.expect(h.app.time_reference_frame == null);

    try h.setFrames(&.{ 4, 12 });
    try h.app.runCommand("expert", "all");
    try std.testing.expect(h.app.overlay == .expert_file);
    try std.testing.expect(std.mem.startsWith(u8, h.app.help_overlay.body, "error"));
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "Bad checksum") != null);
    try std.testing.expectEqual(@as(usize, 0), h.app.expert_items.len);
    h.app.help_overlay.selected = 0;
    try h.app.activatePick();
    try std.testing.expectEqual(@as(?u32, 12), h.app.session.selectedFrame());
    try std.testing.expectEqual(@as(usize, 0), h.app.session.display_filter.len);
}

fn timedRow(allocator: std.mem.Allocator, frame: u32, time: []const u8) !packet.PacketSummary {
    const columns = try allocator.alloc([]const u8, 2);
    columns[0] = try std.fmt.allocPrint(allocator, "{d}", .{frame});
    columns[1] = try allocator.dupe(u8, time);
    return .{ .frame = frame, .columns = columns };
}

test "a field becomes a column and a tls key log reaches tshark" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    const field = try leaf(h.allocator, "tls.handshake.extensions_server_name", "Server Name: example", "example", 0, 1);
    const children = try h.allocator.alloc(packet.DetailNode, 1);
    children[0] = field;
    try installDetail(&h, children, "");
    try std.testing.expect(h.app.protocol_tree.selectNamed("tls.handshake.extensions_server_name", 0));
    try h.app.runCommand("columns", "add");
    try std.testing.expect(std.mem.indexOf(u8, h.columnFormat(), "%Cus:tls.handshake.extensions_server_name") != null);
    try h.app.runCommand("columns", "drop tls.handshake.extensions_server_name");
    try std.testing.expect(std.mem.indexOf(u8, h.columnFormat(), "%Cus:") == null);

    try h.app.runCommand("set", "tls-keylog-file /tmp/keys.log");
    try std.testing.expectEqualStrings("/tmp/keys.log", h.app.session.tls_keylog_file);
    var saw = false;
    for (h.loader.psml_argv.slice()) |arg| {
        if (std.mem.indexOf(u8, arg, "tls.keylog_file:/tmp/keys.log") != null) saw = true;
    }
    try std.testing.expect(saw);
}

test "hierarchy and endpoints apply a filter from the selected row" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.app.session.setFilter("dns", null);
    try h.app.runCommand("hierarchy", "");
    try std.testing.expect(h.script.saw("io,phs"));
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "tls") != null);
    h.app.help_overlay.selected = 4;
    try h.app.activatePick();
    try std.testing.expectEqualStrings("(dns) and tls", h.app.session.display_filter);

    try h.app.runCommand("endpoints", "tcp");
    try std.testing.expect(h.script.saw("endpoints,tcp"));
    try h.app.activatePick();
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "ip.addr == 10.0.0.9") != null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "tcp.port == 443") != null);
}

test "export writes displayed rows and confirms before replacing a file" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    const headers = try h.allocator.alloc([]u8, 2);
    headers[0] = try h.allocator.dupe(u8, "No.");
    headers[1] = try h.allocator.dupe(u8, "Info");
    h.app.session.setListHeaders(headers);
    const packets = try h.allocator.alloc(packet.PacketSummary, 1);
    const columns = try h.allocator.alloc([]const u8, 2);
    columns[0] = try h.allocator.dupe(u8, "1");
    columns[1] = try h.allocator.dupe(u8, "hello");
    packets[0] = .{ .frame = 1, .columns = columns };
    h.app.session.setPackets(packets);
    try std.testing.expect(h.app.session.select(0));

    const json_path = try std.fmt.allocPrint(h.allocator, ".zig-cache/tmp/{s}/rows.json", .{h.tmp.sub_path[0..]});
    defer h.allocator.free(json_path);
    const json_args = try std.fmt.allocPrint(h.allocator, "json {s}", .{json_path});
    defer h.allocator.free(json_args);
    try h.app.runCommand("export", json_args);
    const json = try readFile(h.allocator, h.io, json_path);
    defer h.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"Info\":\"hello\"") != null);

    const pcap_path = try std.fmt.allocPrint(h.allocator, ".zig-cache/tmp/{s}/out.pcapng", .{h.tmp.sub_path[0..]});
    defer h.allocator.free(pcap_path);
    try std.Io.Dir.cwd().writeFile(h.io, .{ .sub_path = pcap_path, .data = "exists" });
    const pcap_args = try std.fmt.allocPrint(h.allocator, "packets {s}", .{pcap_path});
    defer h.allocator.free(pcap_args);
    try h.app.runCommand("export", pcap_args);
    try std.testing.expect(!h.script.saw("-w"));
    try std.testing.expect(h.app.export_confirm);
    try h.app.acceptExport();
    try std.testing.expect(h.script.saw("-F"));
    try std.testing.expect(h.script.saw("pcapng"));
    try std.testing.expect(h.script.saw(pcap_path));

    const objects = try std.fmt.allocPrint(h.allocator, ".zig-cache/tmp/{s}/objects", .{h.tmp.sub_path[0..]});
    defer h.allocator.free(objects);
    const object_args = try std.fmt.allocPrint(h.allocator, "objects http {s}", .{objects});
    defer h.allocator.free(object_args);
    try h.app.runCommand("export", object_args);
    try std.testing.expect(h.script.saw("--export-objects"));
    try std.testing.expect(h.script.saw(objects));
}

test "decode-as offers the selected packet's port and a short protocol list" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    const port = try leaf(h.allocator, "tcp.dstport", "Destination Port: 443", "443", 0, 2);
    const children = try h.allocator.alloc(packet.DetailNode, 1);
    children[0] = port;
    try installDetail(&h, children, "");
    try h.app.runCommand("decode-as", "");
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "tcp.port==443") != null);
    try h.app.activatePick();
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "http") != null);
    try h.app.activatePick();
    try std.testing.expectEqual(@as(usize, 1), h.app.session.decode_as_args.items.len);
    try std.testing.expectEqualStrings("tcp.port==443,http", h.app.session.decode_as_args.items[0]);
}

test "io graph, dns, http, and compare apply a filter from the selected row" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();

    try h.app.runCommand("iograph", "1");
    try std.testing.expect(h.script.saw("io,stat,"));
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "#") != null);
    try h.app.activatePick();
    try std.testing.expect(std.mem.indexOf(u8, h.app.session.display_filter, "frame.time_relative") != null);

    try h.app.runCommand("dns", "");
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "example.com") != null);
    try h.app.activatePick();
    try std.testing.expectEqualStrings("dns.qry.name == \"example.com\"", h.app.session.display_filter);

    try h.app.runCommand("http", "");
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "M-SEARCH") != null);
    try h.app.activatePick();
    try std.testing.expectEqualStrings("http.request.method == \"M-SEARCH\"", h.app.session.display_filter);

    try h.setFrames(&.{ 1, 2 });
    try h.app.runCommand("compare", "other.pcap");
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "only here") != null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "only there") != null);
    const kept = try h.allocator.dupe(u8, h.app.session.display_filter);
    defer h.allocator.free(kept);
    try h.app.activatePick();
    try std.testing.expectEqual(@as(?u32, 1), h.app.session.selectedFrame());
    try std.testing.expectEqualStrings(kept, h.app.session.display_filter);

    try h.app.runCommand("compare", "other.pcap");
    h.app.help_overlay.selected = compareLine(h.app.help_overlay.body, "only there");
    const current = h.app.capturePath() orelse return error.NoCaptureFile;
    try h.app.activatePick();
    try std.testing.expectEqualStrings(kept, h.app.session.display_filter);
    switch (h.app.session.source) {
        .file => |path| try std.testing.expectEqualStrings("other.pcap", path),
        else => return error.UnexpectedSource,
    }
    try std.testing.expectEqual(@as(?u32, 9), h.app.pending_global_frame);
    var reopened = false;
    for (h.app.config.recent_files.items) |file| {
        if (std.mem.eql(u8, file, current)) reopened = true;
    }
    try std.testing.expect(reopened);
}

fn compareLine(body: []const u8, needle: []const u8) usize {
    var index: usize = 0;
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, needle) != null) return index;
        index += 1;
    }
    return 0;
}

test "color rules, packet comments, and lua scripts" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.app.runCommand("color", "dns dns|#112233|#445566");
    try std.testing.expectEqual(@as(usize, 1), h.app.config.color_rules.items.len);
    try std.testing.expectEqualStrings("dns", h.app.config.color_rules.items[0].filter);
    try h.app.runCommand("color", "delete dns");
    try std.testing.expectEqual(@as(usize, 0), h.app.config.color_rules.items.len);

    try h.setFrames(&.{7});
    try h.app.runCommand("comment", "");
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "saved note") != null);
    try h.app.runCommand("comment", "hello");
    try std.testing.expect(h.script.saw("-a"));
    try std.testing.expect(h.script.saw("7:hello"));

    try h.app.runCommand("comment", "list");
    try std.testing.expect(h.script.saw("frame.number"));
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "4  hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "12  note two") != null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "9  ") == null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.body, "Stopped after 200 rows") != null);
    try h.setFrames(&.{4});
    try h.app.activatePick();
    try std.testing.expectEqual(@as(?u32, 4), h.app.session.selectedFrame());
    try std.testing.expectEqual(@as(usize, 0), h.app.session.display_filter.len);

    try h.app.runCommand("comment", "list");
    h.app.help_overlay.selected = 1;
    try h.app.activatePick();
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "not in the list") != null);
    try std.testing.expectEqual(@as(usize, 0), h.app.session.display_filter.len);

    try h.app.runCommand("lua", "script.lua");
    try std.testing.expect(h.script.saw("lua_script:script.lua"));
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "lua ok") != null);
}

fn endpointRow(
    allocator: std.mem.Allocator,
    frame: u32,
    source: []const u8,
    dest: []const u8,
    info: []const u8,
) !packet.PacketSummary {
    const columns = try allocator.alloc([]const u8, 3);
    columns[0] = try allocator.dupe(u8, source);
    columns[1] = try allocator.dupe(u8, dest);
    columns[2] = try allocator.dupe(u8, info);
    return .{ .frame = frame, .columns = columns };
}

test "related packets, the previous filter, and shown of total" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    const headers = try h.allocator.alloc([]u8, 3);
    headers[0] = try h.allocator.dupe(u8, "Source");
    headers[1] = try h.allocator.dupe(u8, "Destination");
    headers[2] = try h.allocator.dupe(u8, "Info");
    h.app.session.setListHeaders(headers);
    const packets = try h.allocator.alloc(packet.PacketSummary, 3);
    packets[0] = try endpointRow(h.allocator, 1, "10.0.0.1", "10.0.0.2", "12345 → 80 request");
    packets[1] = try endpointRow(h.allocator, 2, "10.0.0.1", "10.0.0.9", "111 → 53 query");
    packets[2] = try endpointRow(h.allocator, 3, "10.0.0.2", "10.0.0.1", "80 → 12345 response");
    h.app.session.setPackets(packets);

    try h.app.runCommand("related", "conv next");
    try std.testing.expectEqual(@as(?u32, 3), h.app.session.selectedFrame());
    try h.app.runCommand("related", "pair next");
    try std.testing.expectEqual(@as(?u32, 1), h.app.session.selectedFrame());
    try h.app.runCommand("related", "addr next");
    try std.testing.expectEqual(@as(?u32, 2), h.app.session.selectedFrame());

    try h.app.commitFilter("dns", true);
    try h.app.commitFilter("tcp", true);
    try h.app.runCommand("back", "");
    try std.testing.expectEqualStrings("dns", h.app.session.display_filter);
    try h.app.runCommand("back", "");
    try std.testing.expectEqualStrings("tcp", h.app.session.display_filter);

    h.app.session.setFilter("", null) catch {};
    try h.app.loader.pushEvent(.done);
    try h.app.processLoaderEvents();
    try std.testing.expectEqual(@as(?usize, 3), h.app.unfiltered_total);
    try h.app.commitFilter("tcp", true);
    try std.testing.expectEqual(@as(?usize, 3), h.app.status.packet_total);
}

test "a display filter during tail keeps the cutoff and the tail flag" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    h.app.tailing = true;
    h.app.hide_through_frame = 3;
    try h.app.commitFilter("tcp", true);
    try std.testing.expect(h.app.tailing);
    try std.testing.expectEqual(@as(u32, 3), h.app.hide_through_frame);
    try std.testing.expectEqualStrings("tcp", h.app.session.display_filter);

    const headers = try h.allocator.alloc([]u8, 1);
    headers[0] = try h.allocator.dupe(u8, "No.");
    const rows = try h.allocator.alloc(packet.PacketSummary, 3);
    rows[0] = try endpointRow(h.allocator, 1, "1", "", "");
    rows[1] = try endpointRow(h.allocator, 2, "2", "", "");
    rows[2] = try endpointRow(h.allocator, 5, "5", "", "");
    try h.app.loader.pushEvent(.{ .packets_loaded = .{ .headers = headers, .packets = rows } });
    try h.app.processLoaderEvents();
    try std.testing.expect(h.app.tailing);
    try std.testing.expectEqual(@as(usize, 1), h.app.session.packets.len);
    try std.testing.expectEqual(@as(u32, 5), h.app.session.packets[0].frame);
}

test "name resolution reaches tshark and a mark keeps its note" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.setFrames(&.{7});
    try h.app.runCommand("set", "name-resolution dmN");
    try std.testing.expectEqualStrings("dmN", h.app.session.name_resolution);
    var saw_flag = false;
    const argv = h.loader.psml_argv.slice();
    for (argv, 0..) |arg, index| {
        if (std.mem.eql(u8, arg, "-N") and index + 1 < argv.len and std.mem.eql(u8, argv[index + 1], "dmN")) {
            saw_flag = true;
        }
    }
    try std.testing.expect(saw_flag);
    try h.app.runCommand("set", "name-resolution nope");
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "not valid") != null);
    try std.testing.expectEqualStrings("dmN", h.app.session.name_resolution);

    try h.app.runCommand("mark", "A handshake");
    try std.testing.expectEqual(@as(usize, 1), h.app.config.global_marks.items.len);
    try std.testing.expectEqualStrings("handshake", h.app.config.global_marks.items[0].note);
    try h.app.runCommand("marks", "");
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "handshake") != null);

    const data = try h.allocator.dupe(u8, "hi");
    const chunks = try h.allocator.alloc(zigshark.shark.streams.Chunk, 1);
    chunks[0] = .{ .direction = .client, .data = data, .frame = 7 };
    h.app.stream_chunks = chunks;
    h.app.overlay = .streams;
    h.app.help_overlay.selected = 0;
    try h.app.activatePick();
    try std.testing.expectEqual(@as(?u32, 7), h.app.session.selectedFrame());
    try std.testing.expect(!h.script.saw("frame contains"));
}

test "selecting a packet pauses live tail and End resumes it" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.setFrames(&.{ 1, 2, 3 });
    h.app.live_capture = true;
    h.app.follow_tail = true;
    h.app.syncFromSession();
    h.app.packet_table.onSelect.?(h.app.packet_table.userdata, 0);
    try std.testing.expect(!h.app.follow_tail);
    try std.testing.expectEqual(@as(?usize, 0), h.app.session.selected_index);

    h.app.packet_table.onSelect.?(h.app.packet_table.userdata, 2);
    try std.testing.expect(h.app.follow_tail);
    try std.testing.expectEqual(@as(?usize, 2), h.app.session.selected_index);
}

const yaml_follow =
    \\  - packet: 12
    \\    peer: 0
    \\    data: !!binary |
    \\      SGVsbG8=
    \\  - packet: 13
    \\    peer: 1
    \\    data: !!binary |
    \\      V29ybGQ=
    \\  - packet:
    \\    peer: 0
    \\    data: !!binary |
    \\      IQ==
;

fn fakeTsharkPath(allocator: std.mem.Allocator) ![]u8 {
    const name = if (builtin.os.tag == .windows) "fake-tshark.exe" else "fake-tshark";
    return std.fmt.allocPrint(allocator, "zig-out/bin/{s}", .{name});
}

fn waitForFile(io: std.Io, path: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    var spins: usize = 0;
    while (spins < 150) : (spins += 1) {
        if (cwd.access(io, path, .{})) |_| return else |_| {
            try std.Io.sleep(io, .fromMilliseconds(20), .awake);
        }
    }
    return error.NotStarted;
}

test "stop ends a live capture and names the saved file" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    h.app.live_capture = true;
    h.app.follow_tail = true;
    h.session.capture_path = try h.allocator.dupe(u8, "/tmp/keep.pcap");
    try h.app.runCommand("stop", "");
    try std.testing.expect(!h.app.live_capture);
    try std.testing.expect(!h.app.follow_tail);
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "/tmp/keep.pcap") != null);
}

fn menuRowIndex(body: []const u8, row: []const u8) !usize {
    var index: usize = 0;
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |line| {
        if (std.mem.eql(u8, line, row)) return index;
        index += 1;
    }
    return error.MissingMenuRow;
}

test "an analysis menu row runs the same command" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.app.runCommand("hierarchy", "");
    const expected = try h.allocator.dupe(u8, h.app.help_overlay.body);
    defer h.allocator.free(expected);
    h.app.dismissOverlays();

    h.app.header_menu = .analysis;
    h.app.menu_analysis = true;
    const activate = h.app.dropdown.on_activate orelse return error.MissingMenu;
    const hierarchy = try menuRowIndex(zigshark.ui.widgets.header_bar.analysis_menu, "hierarchy");
    activate(h.app.dropdown.userdata, hierarchy);
    try std.testing.expectEqualStrings(expected, h.app.help_overlay.body);

    h.app.header_menu = .analysis;
    h.app.menu_analysis = true;
    const export_row = try menuRowIndex(zigshark.ui.widgets.header_bar.analysis_menu, "export");
    activate(h.app.dropdown.userdata, export_row);
    try std.testing.expect(h.app.command.visible);
    const palette = try zigshark.ui.widgets.filter_bar.fieldText(h.allocator, &h.app.command.field);
    defer h.allocator.free(palette);
    try std.testing.expectEqualStrings("export ", palette);
    try std.testing.expect(std.mem.indexOf(u8, zigshark.ui.widgets.header_bar.analysis_menu, "comment list") != null);
}

test "a failed analysis menu item is shown" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.app.openCapture("boom");
    h.app.header_menu = .analysis;
    h.app.menu_analysis = true;
    const activate = h.app.dropdown.on_activate orelse return error.MissingMenu;
    activate(h.app.dropdown.userdata, 2);
    try std.testing.expect(h.app.header_menu == null);
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "ToolFailed") != null);
}

test "stream diagram selects the frame and f filters the list" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    try h.app.runCommand("streams", "filter");
    try std.testing.expect(std.mem.indexOf(u8, h.app.msg_overlay.body, "Follow a stream") != null);

    try h.setFrames(&.{ 12, 13 });
    try h.app.showStream("TCP", 2, yaml_follow, false);
    try std.testing.expectEqualStrings("tcp.stream == 2", h.app.stream_list_filter);
    try std.testing.expect(std.mem.indexOf(u8, h.app.help_overlay.title, "Enter selects") != null);

    var lines = std.mem.splitScalar(u8, h.app.help_overlay.body, '\n');
    const client = lines.next() orelse return error.MissingLine;
    const server = lines.next() orelse return error.MissingLine;
    const unlabeled = lines.next() orelse return error.MissingLine;
    try std.testing.expect(client[client.len - 1] == '>');
    try std.testing.expect(std.mem.indexOf(u8, client, "Hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, client, "12") != null);
    try std.testing.expect(server[0] == '<');
    try std.testing.expect(std.mem.indexOf(u8, server, "World") != null);
    try std.testing.expect(std.mem.indexOf(u8, unlabeled, "!") != null);
    try std.testing.expect(std.mem.indexOfAny(u8, unlabeled, "0123456789") == null);

    h.app.help_overlay.selected = 0;
    try h.app.activatePick();
    try std.testing.expectEqual(@as(?u32, 12), h.app.session.selectedFrame());
    try std.testing.expectEqual(@as(usize, 0), h.app.session.display_filter.len);

    try h.app.runCommand("streams", "filter");
    try std.testing.expectEqualStrings("tcp.stream == 2", h.app.session.display_filter);
    try std.testing.expect(!h.script.saw("frame contains"));
}

test "quit destroys a sleeping wormhole job" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tool = try fakeTsharkPath(allocator);
    defer allocator.free(tool);
    const started = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/sleep-wormhole.started", .{tmp.sub_path[0..]});
    defer allocator.free(started);

    // A shell script is not a valid Windows image. fake-tshark sleeps instead.
    const job = try zigshark.features.transfer.Job.startArgv(allocator, io, &.{ tool, "--sleep-marker", started });
    var destroyed = false;
    errdefer if (!destroyed) job.destroy();
    try waitForFile(io, started);

    const before = std.Io.Timestamp.now(io, .awake).nanoseconds;
    job.destroy();
    destroyed = true;
    const elapsed = std.Io.Timestamp.now(io, .awake).nanoseconds - before;
    if (elapsed >= 3 * std.time.ns_per_s) return error.QuitWaitedOnWormhole;
}

test "quit kills a running field dump" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    const tool = try fakeTsharkPath(h.allocator);
    defer h.allocator.free(tool);
    const owned = try h.allocator.dupe(u8, tool);
    h.allocator.free(h.app.fields_tshark_path);
    h.app.fields_tshark_path = owned;

    try h.app.ensureFieldCompletions();
    try std.Io.sleep(h.io, .fromMilliseconds(100), .awake);
    const before = std.Io.Timestamp.now(h.io, .awake).nanoseconds;
    h.app.cancelToolChildren();
    const elapsed = std.Io.Timestamp.now(h.io, .awake).nanoseconds - before;
    if (elapsed >= 3 * std.time.ns_per_s) return error.QuitWaitedOnTshark;
}

test "quit kills a running filter check" {
    var h: Harness = undefined;
    try h.setup();
    defer h.teardown();
    h.app.process_runner = null;
    const tool = try fakeTsharkPath(h.allocator);
    defer h.allocator.free(tool);
    const owned = try h.allocator.dupe(u8, tool);
    h.allocator.free(h.tools.tshark);
    h.tools.tshark = owned;

    const slow = try std.fs.path.join(h.allocator, &.{ h.paths.cache_dir, "slow.pcap" });
    h.allocator.free(h.app.empty_pcap);
    h.app.empty_pcap = slow;
    const started = try std.fmt.allocPrint(h.allocator, "{s}.started", .{slow});
    defer h.allocator.free(started);
    const finished = try std.fmt.allocPrint(h.allocator, "{s}.finished", .{slow});
    defer h.allocator.free(finished);

    try h.app.filter.setText("tcp");
    var i: usize = 0;
    while (i < 4) : (i += 1) h.app.pollFilterFeedback();
    try waitForFile(h.io, started);

    const before = std.Io.Timestamp.now(h.io, .awake).nanoseconds;
    h.app.cancelToolChildren();
    const elapsed = std.Io.Timestamp.now(h.io, .awake).nanoseconds - before;
    if (elapsed >= 3 * std.time.ns_per_s) return error.QuitWaitedOnTshark;
    if (std.Io.Dir.cwd().access(h.io, finished, .{})) |_| {
        return error.FilterCheckRanToCompletion;
    } else |_| {}
    try std.testing.expectEqual(@as(usize, 0), h.app.session.display_filter.len);
}
