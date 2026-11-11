const std = @import("std");
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
    const script = active_script orelse return error.NoScript;
    try script.note(argv);
    const stdout = try replyFor(allocator, argv);
    return .{
        .stdout = stdout,
        .stderr = try allocator.dupe(u8, ""),
        .term = .{ .exited = 0 },
    };
}

fn replyFor(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    for (argv) |arg| {
        if (std.mem.startsWith(u8, arg, "conv,")) {
            if (std.mem.endsWith(u8, arg, "udp")) return allocator.dupe(u8, udp_conversation);
            if (std.mem.endsWith(u8, arg, "eth")) return allocator.dupe(u8, eth_conversation);
            if (std.mem.endsWith(u8, arg, "ipv6")) return allocator.dupe(u8, ipv6_conversation);
            if (std.mem.endsWith(u8, arg, "ip")) return allocator.dupe(u8, ip_conversation);
            return allocator.dupe(u8, tcp_conversation);
        }
        if (std.mem.startsWith(u8, arg, "follow,")) return allocator.dupe(u8, follow_text);
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

    try h.app.config.setGlobalMark('C', "other.pcap", 7);
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
