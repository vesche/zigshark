const std = @import("std");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;

const theme_mod = @import("theme.zig");
const packet_table = @import("widgets/packet_table.zig");
const protocol_tree = @import("widgets/protocol_tree.zig");
const hex_view = @import("widgets/hex_view.zig");
const hsplit = @import("widgets/hsplit.zig");
const vsplit = @import("widgets/vsplit.zig");
const overlay_mod = @import("widgets/overlay.zig");
const command_palette = @import("widgets/command_palette.zig");
const filter_bar = @import("widgets/filter_bar.zig");
const status_bar = @import("widgets/status_bar.zig");
const header_bar = @import("widgets/header_bar.zig");
const help_view = @import("views/help.zig");
const streams_view = @import("views/streams.zig");
const convs_view = @import("views/convs.zig");
const convs_shark = @import("../shark/convs.zig");
const streams_shark = @import("../shark/streams.zig");
const capinfo_view = @import("views/capinfo.zig");
const search_mod = @import("../model/search.zig");
const signals = @import("../platform/signals.zig");

const config = @import("../config.zig");
const log_mod = @import("../log.zig");
const session_mod = @import("../model/session.zig");
const loader_mod = @import("../model/loader.zig");
const packet = @import("../model/packet.zig");
const tools_mod = @import("../shark/tools.zig");
const filter_mod = @import("../shark/filter.zig");
const process_mod = @import("../shark/process.zig");
const paths_mod = @import("../platform/paths.zig");
const cli = @import("../cli.zig");
const recents = @import("../features/recents.zig");
const transfer = @import("../features/transfer.zig");
const copy_feature = @import("../features/copy.zig");
const macros_feature = @import("../features/macros.zig");
const profiles_feature = @import("../features/profiles.zig");
const runtime_mod = @import("runtime.zig");

pub const Focus = enum { filter, packets, protocol, hex };

pub const OverlayKind = enum {
    none,
    help,
    quit,
    message,
    streams,
    convs,
    capinfo,
};

fn hexNeedleLength(value: []const u8) usize {
    var digits: usize = 0;
    for (value) |char| {
        if (std.ascii.isHex(char)) digits += 1;
    }
    return digits / 2;
}

fn loadFieldCompletionsWorker(app: *AppModel) void {
    app.loadFieldCompletions() catch {};
    app.fields_ready.store(true, .release);
}

pub const AppModel = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: *config.Config,
    tools: *tools_mod.Tools,
    session: *session_mod.Session,
    loader: *loader_mod.CaptureLoader,
    paths: *paths_mod.Paths,
    cli_opts: cli.Options,

    theme: theme_mod.Theme,
    focus: Focus = .packets,
    overlay: OverlayKind = .none,
    layout_stacked: bool = true,
    quit_confirm: bool = false,
    pending_z: bool = false,
    copy_mode: bool = false,
    zoomed: ?Focus = null,

    packet_table: packet_table.PacketTable,
    protocol_tree: protocol_tree.ProtocolTree,
    hex: hex_view.HexView,
    filter: filter_bar.FilterBar,
    status: status_bar.StatusBar,
    header: header_bar.HeaderBar,
    command: command_palette.CommandPalette,
    help_overlay: overlay_mod.Overlay,
    msg_overlay: overlay_mod.Overlay,

    detail_bundle: ?packet.DetailBundle = null,
    overlay_body_owned: []u8 = &.{},
    detail_frame: ?u32 = null,
    detail_requested_frame: ?u32 = null,
    empty_pcap: []u8 = &.{},
    search: search_mod.SearchState = .{},
    awaiting_mark: bool = false,
    awaiting_jump: bool = false,
    live_capture: bool = false,
    live_refresh_ticks: u8 = 0,
    fields: [][]u8 = &.{},
    fields_worker: ?std.Thread = null,
    fields_ready: std.atomic.Value(bool) = .init(false),
    fields_cancelled: std.atomic.Value(bool) = .init(false),
    fields_tshark_path: []u8 = &.{},
    byte_search_offset: usize = 0,
    pending_global_frame: ?u32 = null,
    link_guard: bool = false,
    completion_prefix: []u8 = &.{},
    completion_match: []u8 = &.{},
    completion_index: usize = 0,
    completion_note: [96]u8 = @splat(0),
    completion_note_len: usize = 0,
    conversations: []convs_shark.Conversation = &.{},
    conversation_proto: []u8 = &.{},
    stream_filter: []u8 = &.{},
    stream_chunks: []streams_shark.Chunk = &.{},
    tailing: bool = false,
    tail_size: u64 = 0,
    tail_ticks: u8 = 0,
    hide_through_frame: u32 = 0,
    transfer_job: ?*transfer.Job = null,
    process_runner: ?process_mod.Runner = null,

    hsplit_main: hsplit.HSplit,
    hsplit_detail: hsplit.HSplit,
    vsplit_main: vsplit.VSplit,
    children_buf: [16]vxfw.SubSurface = undefined,
    flex_items: [4]vxfw.FlexItem = undefined,

    pub fn init(self: *AppModel, allocator: std.mem.Allocator, io: std.Io, opts: runtime_mod.RunOptions) !void {
        try self.initPrepared(allocator, io, opts);
        try self.startInitialLoad();
    }

    /// Same widgets and session wiring as `init`, without starting tshark.
    /// Command tests call `runCommand` on this model and never open a TTY.
    pub fn initOffline(self: *AppModel, allocator: std.mem.Allocator, io: std.Io, opts: runtime_mod.RunOptions) !void {
        try self.initPrepared(allocator, io, opts);
    }

    fn startInitialLoad(self: *AppModel) !void {
        switch (self.session.source) {
            .file, .fifo, .stdin => try self.loader.requestPsml(self.session),
            .interfaces => try self.startLiveCapture(),
        }
    }

    fn initPrepared(self: *AppModel, allocator: std.mem.Allocator, io: std.Io, opts: runtime_mod.RunOptions) !void {
        self.* = undefined;
        self.allocator = allocator;
        self.io = io;
        self.config = opts.config;
        self.tools = opts.tools;
        self.session = opts.session;
        self.loader = opts.loader;
        self.paths = opts.paths;
        self.cli_opts = opts.cli;

        self.theme = theme_mod.resolve(self.config.dark_mode);
        self.theme = self.loadConfiguredTheme() catch self.theme;
        self.focus = .packets;
        self.overlay = .none;
        self.layout_stacked = self.config.layout == .stacked;
        self.quit_confirm = false;
        self.pending_z = false;
        self.copy_mode = false;
        self.zoomed = null;
        self.detail_bundle = null;
        self.overlay_body_owned = &.{};
        self.detail_frame = null;
        self.detail_requested_frame = null;
        self.empty_pcap = &.{};
        self.search = .{};
        self.awaiting_mark = false;
        self.awaiting_jump = false;
        self.live_capture = false;
        self.live_refresh_ticks = 0;
        self.fields = &.{};
        self.fields_worker = null;
        self.fields_ready = .init(false);
        self.fields_cancelled = .init(false);
        self.fields_tshark_path = try self.allocator.dupe(u8, self.tools.tshark);
        self.byte_search_offset = 0;
        self.pending_global_frame = null;
        self.link_guard = false;
        self.completion_prefix = &.{};
        self.completion_match = &.{};
        self.completion_index = 0;
        self.completion_note = @splat(0);
        self.completion_note_len = 0;
        self.conversations = &.{};
        self.conversation_proto = &.{};
        self.stream_filter = &.{};
        self.stream_chunks = &.{};
        self.tailing = false;
        self.tail_size = 0;
        self.tail_ticks = 0;
        self.hide_through_frame = 0;
        self.transfer_job = null;
        self.process_runner = null;

        self.packet_table = .{
            .theme = self.theme,
            .packet_colors = self.config.packet_colors,
            .userdata = self,
            .onSelect = onPacketSelect,
            .onSort = onPacketSort,
            .onFocus = onPacketFocus,
        };
        self.protocol_tree = protocol_tree.ProtocolTree.init(allocator, self.theme);
        self.protocol_tree.userdata = self;
        self.protocol_tree.onSelect = onTreeSelect;
        self.protocol_tree.onFocus = onTreeFocus;
        self.hex = .{
            .theme = self.theme,
            .userdata = self,
            .onCursor = onHexCursor,
            .onFocus = onHexFocus,
        };
        self.filter = filter_bar.FilterBar.init(allocator, self.theme);
        self.filter.userdata = self;
        self.filter.onSubmit = onFilterSubmit;
        self.filter.onRecent = onRecentFilters;
        self.filter.onFocus = onFilterFocus;
        if (opts.cli.display_filter) |df| try self.filter.setText(df);
        self.status = .{ .theme = self.theme };
        self.header = .{
            .theme = self.theme,
            .userdata = self,
            .onMenu = onHeaderMenu,
        };
        self.command = command_palette.CommandPalette.init(allocator, self.theme);
        self.command.userdata = self;
        self.command.onRun = onCommand;
        self.help_overlay = .{ .title = "Help", .body = help_view.text, .theme = self.theme };
        self.msg_overlay = .{ .title = "Message", .body = "", .theme = self.theme };
        const divider_style: vaxis.Style = .{
            .fg = self.theme.pane_border,
            .bg = self.theme.bg,
        };
        self.hsplit_detail = .{
            .top = self.protocol_tree.widget(),
            .bottom = self.hex.widget(),
            .ratio = self.config.detail_ratio,
            .divider_style = divider_style,
        };
        self.hsplit_main = .{
            .top = self.packet_table.widget(),
            .bottom = self.hsplit_detail.widget(),
            .ratio = self.config.packet_list_ratio,
            .divider_style = divider_style,
        };
        self.vsplit_main = .{
            .left = self.packet_table.widget(),
            .right = self.hsplit_detail.widget(),
            .ratio = self.config.packet_list_ratio,
            .divider_style = divider_style,
        };

        self.empty_pcap = try self.paths.emptyPcapPath(allocator);
        self.syncFromSession();
    }

    pub fn deinit(self: *AppModel) void {
        if (self.overlay_body_owned.len != 0) self.allocator.free(self.overlay_body_owned);
        if (self.detail_bundle) |*b| b.deinit(self.allocator);
        if (self.empty_pcap.len != 0) self.allocator.free(self.empty_pcap);
        self.fields_cancelled.store(true, .release);
        if (self.fields_worker) |worker| worker.join();
        for (self.fields) |field| self.allocator.free(field);
        if (self.fields.len != 0) self.allocator.free(self.fields);
        if (self.fields_tshark_path.len != 0) self.allocator.free(self.fields_tshark_path);
        self.search.deinit(self.allocator);
        self.clearConversations();
        if (self.conversation_proto.len != 0) self.allocator.free(self.conversation_proto);
        if (self.stream_filter.len != 0) self.allocator.free(self.stream_filter);
        self.clearStreamChunks();
        if (self.transfer_job) |job| job.destroy();
        if (self.completion_prefix.len != 0) self.allocator.free(self.completion_prefix);
        if (self.completion_match.len != 0) self.allocator.free(self.completion_match);
        self.protocol_tree.deinit();
        self.filter.deinit();
        self.command.deinit();
    }

    fn syncFromSession(self: *AppModel) void {
        self.packet_table.rows = self.session.packets;
        self.packet_table.headers = self.session.list_headers;
        if (self.session.selected_index) |idx| {
            self.packet_table.selected = idx;
        }
        self.status.packet_count = self.session.packets.len;
        self.status.selected_frame = self.session.selectedFrame();
        self.status.loading = self.session.loading;
        self.status.filter = self.session.display_filter;
        self.status.source = switch (self.session.source) {
            .file => |p| p,
            .fifo => |p| p,
            .stdin => "(stdin)",
            .interfaces => "(live)",
        };
        self.header.source = self.status.source;
    }

    fn onPacketSelect(userdata: ?*anyopaque, idx: usize) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        _ = self.session.select(idx);
        self.syncFromSession();
        self.loadDetailForSelection() catch {};
    }

    fn onPacketSort(userdata: ?*anyopaque, column: usize, ascending: bool) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        self.session.setSort(column, ascending);
        self.syncFromSession();
    }

    fn selectFrame(self: *AppModel, frame: u32) bool {
        for (self.session.packets, 0..) |summary, index| {
            if (summary.frame == frame) {
                _ = self.session.select(index);
                self.packet_table.selected = index;
                self.syncFromSession();
                return true;
            }
        }
        return false;
    }

    fn jumpGlobalMark(self: *AppModel, label: u8) !bool {
        const mark = self.config.getGlobalMark(label) orelse return false;
        if (self.capturePath()) |current_path| {
            if (std.mem.eql(u8, current_path, mark.path)) return self.selectFrame(mark.frame);
        }
        self.pending_global_frame = mark.frame;
        try self.openCapture(mark.path);
        return true;
    }

    pub fn applyMark(self: *AppModel, label: u8, global: bool, jump: bool) !void {
        if (!jump) {
            if (global) {
                self.session.markGlobal(label);
                if (self.capturePath()) |path| {
                    if (self.session.selectedFrame()) |frame| {
                        try self.config.setGlobalMark(label, path, frame);
                        self.persistConfig();
                    }
                }
            } else {
                self.session.markLocal(label);
            }
            try self.showMessage("Mark set");
            return;
        }
        const found = if (global)
            try self.jumpGlobalMark(label)
        else
            self.session.jumpToMark(label, false);
        if (found) {
            self.syncFromSession();
            try self.loadDetailForSelection();
        } else {
            try self.showMessage("Mark not set");
        }
    }

    fn runProcess(self: *AppModel, argv: []const []const u8) !process_mod.RunOutput {
        if (self.process_runner) |run| return run(self.allocator, self.io, argv);
        return process_mod.runCapture(self.allocator, self.io, argv);
    }

    fn onHeaderMenu(userdata: ?*anyopaque, menu: header_bar.HeaderBar.Menu) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        switch (menu) {
            .analysis => self.showMessage(
                "Analysis\n\n" ++
                    ":streams [tcp|udp] [index]\n" ++
                    ":convs [tcp|udp|ip|ipv6|eth]\n" ++
                    ":capinfo\n" ++
                    "Ctrl-F search",
            ) catch {},
            .view => self.showMessage(
                "View\n\n" ++
                    "| toggle layout\n" ++
                    "+/- resize packet list\n" ++
                    "</> resize detail panes\n" ++
                    ":columns\n" ++
                    ":theme",
            ) catch {},
            .help => {
                self.help_overlay.visible = true;
                self.help_overlay.scroll_top = 0;
                self.overlay = .help;
            },
        }
    }

    fn onPacketFocus(userdata: ?*anyopaque) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        self.focus = .packets;
    }

    fn onTreeFocus(userdata: ?*anyopaque) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        self.focus = .protocol;
    }

    fn onHexFocus(userdata: ?*anyopaque) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        self.focus = .hex;
    }

    fn onFilterFocus(userdata: ?*anyopaque) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        self.focus = .filter;
    }

    fn onTreeSelect(userdata: ?*anyopaque, pos: usize, size: usize) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        self.hex.setHighlight(pos, size);
        if (self.link_guard) return;
        self.link_guard = true;
        self.hex.setCursor(pos, false);
        self.link_guard = false;
    }

    fn onHexCursor(userdata: ?*anyopaque, offset: usize) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        if (self.link_guard) return;
        self.link_guard = true;
        self.protocol_tree.selectCovering(offset);
        self.link_guard = false;
    }

    fn onFilterSubmit(userdata: ?*anyopaque, text: []const u8) anyerror!void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        const expanded = try macros_feature.expand(self.allocator, self.config, text);
        defer self.allocator.free(expanded);
        self.filter.state = .neutral;
        const ok = try filter_mod.validateDisplayFilterRun(
            self.allocator,
            self.io,
            self.tools.tshark,
            self.empty_pcap,
            expanded,
            self.process_runner,
        );
        self.filter.state = if (ok) .ok else .bad;
        if (!ok) return;
        try self.session.setFilter(expanded, null);
        try recents.pushFilter(self.config, expanded);
        self.clearDetail();
        try self.loader.requestPsml(self.session);
        self.syncFromSession();
    }

    fn onRecentFilters(userdata: ?*anyopaque) anyerror!void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        try self.showRecents();
    }

    fn onCommand(userdata: ?*anyopaque, cmd: []const u8, args: []const u8) anyerror!void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        try self.runCommand(cmd, args);
    }

    fn loadDetailForSelection(self: *AppModel) !void {
        const frame = self.session.selectedFrame() orelse return;
        if (self.detail_frame == frame or self.detail_requested_frame == frame) return;
        self.detail_requested_frame = frame;
        try self.loader.requestDetail(self.session, frame);
    }

    fn clearDetail(self: *AppModel) void {
        self.protocol_tree.setRoot(null);
        self.hex.raw = &.{};
        self.hex.setHighlight(0, 0);
        if (self.detail_bundle) |*bundle| bundle.deinit(self.allocator);
        self.detail_bundle = null;
        self.detail_frame = null;
        self.detail_requested_frame = null;
    }

    fn startLiveCapture(self: *AppModel) !void {
        const interfaces = switch (self.session.source) {
            .interfaces => |values| values,
            else => return,
        };
        const output_path = if (self.cli_opts.write_file) |path|
            try self.allocator.dupe(u8, path)
        else blk: {
            const cache_dir = try self.paths.pcapCacheDir(self.allocator);
            defer self.allocator.free(cache_dir);
            const timestamp = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{s}/capture-{d}.pcap",
                .{ cache_dir, timestamp },
            );
        };
        defer self.allocator.free(output_path);

        try self.loader.startLiveCapture(
            self.io,
            self.session,
            interfaces,
            output_path,
        );
        self.live_capture = true;
        self.syncFromSession();
    }

    fn refreshLiveCapture(self: *AppModel) !void {
        if (!self.live_capture or self.session.capture_path.len == 0) return;
        const cwd = std.Io.Dir.cwd();
        cwd.access(self.io, self.session.capture_path, .{}) catch return;
        try self.loader.requestPsml(self.session);
        self.session.loading = .capturing;
        self.syncFromSession();
    }

    fn loadFieldCompletions(self: *AppModel) !void {
        const cache_path = try self.paths.fieldsCachePath(self.allocator);
        defer self.allocator.free(cache_path);
        const cwd = std.Io.Dir.cwd();
        const contents = cwd.readFileAlloc(
            self.io,
            cache_path,
            self.allocator,
            .unlimited,
        ) catch blk: {
            var argv = try process_mod.argvFieldsDump(self.allocator, self.fields_tshark_path);
            defer argv.deinit(self.allocator);
            var output = try process_mod.runCapture(self.allocator, self.io, argv.slice());
            defer output.deinit(self.allocator);
            if (!output.term.success()) return error.FieldsUnavailable;
            try cwd.writeFile(self.io, .{
                .sub_path = cache_path,
                .data = output.stdout,
            });
            break :blk try self.allocator.dupe(u8, output.stdout);
        };
        defer self.allocator.free(contents);
        var names: std.ArrayList([]u8) = .empty;
        errdefer {
            for (names.items) |name| self.allocator.free(name);
            names.deinit(self.allocator);
        }
        var lines = std.mem.splitScalar(u8, contents, '\n');
        while (lines.next()) |line| {
            if (self.fields_cancelled.load(.acquire)) return error.Cancelled;
            var parts = std.mem.splitScalar(u8, line, '\t');
            const kind = parts.next() orelse continue;
            if (!std.mem.eql(u8, kind, "F")) continue;
            _ = parts.next() orelse continue;
            const name = parts.next() orelse continue;
            try names.append(self.allocator, try self.allocator.dupe(u8, name));
        }
        self.fields = try names.toOwnedSlice(self.allocator);
    }

    pub fn completeFilter(self: *AppModel, forward: bool) !bool {
        if (!self.fields_ready.load(.acquire) or self.fields.len == 0) return false;
        const text = try self.filter.copyText(self.allocator);
        defer self.allocator.free(text);
        var start = text.len;
        while (start > 0) {
            const char = text[start - 1];
            if (std.ascii.isAlphanumeric(char) or char == '_' or char == '.' or char == '-') {
                start -= 1;
            } else break;
        }
        const token = text[start..];
        if (token.len == 0) return false;

        // A cycle continues only while the token is still the last insertion.
        // Editing to a new stem, even one that shares the old prefix, starts over.
        const continuing = self.completion_match.len != 0 and std.mem.eql(u8, token, self.completion_match);
        const stem = if (continuing) self.completion_prefix else token;
        if (!continuing) {
            const prefix = try self.allocator.dupe(u8, token);
            if (self.completion_prefix.len != 0) self.allocator.free(self.completion_prefix);
            self.completion_prefix = prefix;
            self.completion_index = 0;
        }

        var total: usize = 0;
        for (self.fields) |field| {
            if (std.mem.startsWith(u8, field, stem)) total += 1;
        }
        if (total == 0) return false;
        if (continuing) {
            if (forward) {
                self.completion_index = (self.completion_index + 1) % total;
            } else if (self.completion_index == 0) {
                self.completion_index = total - 1;
            } else {
                self.completion_index -= 1;
            }
        } else if (!forward) {
            self.completion_index = total - 1;
        } else if (self.completion_index >= total) {
            self.completion_index = 0;
        }

        var seen: usize = 0;
        var chosen: []const u8 = stem;
        for (self.fields) |field| {
            if (!std.mem.startsWith(u8, field, stem)) continue;
            if (seen == self.completion_index) {
                chosen = field;
                break;
            }
            seen += 1;
        }
        const completed = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ text[0..start], chosen });
        defer self.allocator.free(completed);
        try self.filter.setText(completed);
        const match = try self.allocator.dupe(u8, chosen);
        if (self.completion_match.len != 0) self.allocator.free(self.completion_match);
        self.completion_match = match;
        const note = std.fmt.bufPrint(&self.completion_note, " complete {d}/{d}", .{
            self.completion_index + 1,
            total,
        }) catch self.completion_note[0..0];
        self.completion_note_len = note.len;
        self.status.mode = self.completion_note[0..self.completion_note_len];
        return true;
    }

    fn ensureFieldCompletions(self: *AppModel) !void {
        if (self.fields_ready.load(.acquire) or self.fields_worker != null) return;
        self.fields_worker = try std.Thread.spawn(.{}, loadFieldCompletionsWorker, .{self});
    }

    fn resetFieldCompletions(self: *AppModel) !void {
        self.fields_cancelled.store(true, .release);
        if (self.fields_worker) |worker| worker.join();
        self.fields_worker = null;
        for (self.fields) |field| self.allocator.free(field);
        if (self.fields.len != 0) self.allocator.free(self.fields);
        self.fields = &.{};
        if (self.fields_tshark_path.len != 0) self.allocator.free(self.fields_tshark_path);
        self.fields_tshark_path = try self.allocator.dupe(u8, self.tools.tshark);
        self.fields_ready.store(false, .release);
        self.fields_cancelled.store(false, .release);
    }

    pub fn processLoaderEvents(self: *AppModel) !void {
        const events = try self.loader.drainEvents();
        defer self.allocator.free(events);
        for (events) |*ev| {
            switch (ev.*) {
                .packets_loaded => |*table| {
                    const selected_frame = self.session.selectedFrame();
                    self.session.setListHeaders(table.headers);
                    table.headers = &.{};
                    if (self.hide_through_frame != 0) {
                        table.packets = try packet.retainFramesAfter(
                            self.allocator,
                            table.packets,
                            self.hide_through_frame,
                        );
                    }
                    self.session.setPackets(table.packets);
                    table.packets = &.{};
                    if (selected_frame) |frame| {
                        for (self.session.packets, 0..) |summary, index| {
                            if (summary.frame == frame) {
                                _ = self.session.select(index);
                                break;
                            }
                        }
                    } else if (self.live_capture and self.config.auto_scroll and self.session.packets.len > 0) {
                        _ = self.session.select(self.session.packets.len - 1);
                    }
                    if (self.pending_global_frame) |frame| {
                        _ = self.selectFrame(frame);
                        self.pending_global_frame = null;
                    }
                    self.session.loading = if (self.live_capture) .capturing else .idle;
                    self.syncFromSession();
                    ev.* = .done;
                },
                .detail_loaded => |*bundle| {
                    if (self.detail_bundle) |*old| old.deinit(self.allocator);
                    self.detail_bundle = bundle.*;
                    const stored = &self.detail_bundle.?;
                    self.detail_frame = stored.pdml.frame;
                    self.detail_requested_frame = null;
                    self.session.loading = if (self.live_capture) .capturing else .idle;
                    self.protocol_tree.setRoot(&stored.pdml.root);
                    self.hex.raw = stored.bytes.raw;
                    self.hex.scroll_top = 0;
                    const hl = self.protocol_tree.selectedHighlight();
                    self.hex.setHighlight(hl.pos, hl.size);
                    self.syncFromSession();
                    ev.* = .done;
                },
                .error_msg => |msg| {
                    self.detail_requested_frame = null;
                    log_mod.err("loader", "{s}", .{msg});
                    try self.session.setError(msg);
                    try self.showMessage(msg);
                },
                .capture_progress => {},
                .done => {},
            }
            ev.deinit(self.allocator);
        }
        try self.loadDetailForSelection();
    }

    fn capturePath(self: *const AppModel) ?[]const u8 {
        return switch (self.session.source) {
            .file => |p| p,
            .fifo => |p| p,
            .interfaces => if (self.session.capture_path.len != 0) self.session.capture_path else null,
            .stdin => null,
        };
    }

    fn openCapture(self: *AppModel, path: []const u8) !void {
        if (self.live_capture) self.loader.stopLiveCapture(self.io);
        try self.session.setFileSource(path);
        self.hide_through_frame = 0;
        self.noteTail(path);
        try recents.pushRecent(self.config, path);
        self.live_capture = false;
        self.clearDetail();
        self.loader.clearDetailCache(self.io);
        try self.loader.requestPsml(self.session);
        self.syncFromSession();
    }

    fn showMessage(self: *AppModel, msg: []const u8) !void {
        if (self.overlay_body_owned.len != 0) self.allocator.free(self.overlay_body_owned);
        self.overlay_body_owned = try self.allocator.dupe(u8, msg);
        self.msg_overlay.body = self.overlay_body_owned;
        self.msg_overlay.visible = true;
        self.msg_overlay.scroll_top = 0;
        self.overlay = .message;
    }

    fn showRecents(self: *AppModel) !void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);
        try buffer.appendSlice(self.allocator, "Recent files:\n");
        for (self.config.recent_files.items, 0..) |file, index| {
            const line = try std.fmt.allocPrint(self.allocator, "  {d}. {s}\n", .{
                index + 1,
                file,
            });
            defer self.allocator.free(line);
            try buffer.appendSlice(self.allocator, line);
        }
        try buffer.appendSlice(self.allocator, "\nRecent filters:\n");
        for (self.config.recent_filters.items, 0..) |filter, index| {
            const line = try std.fmt.allocPrint(self.allocator, "  {d}. {s}\n", .{
                index + 1,
                filter,
            });
            defer self.allocator.free(line);
            try buffer.appendSlice(self.allocator, line);
        }
        try self.showMessage(buffer.items);
    }

    fn showMarks(self: *AppModel) !void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);
        try buffer.appendSlice(
            self.allocator,
            "Local marks: m[a-z] set, '[a-z] jump\n\nGlobal marks:\n",
        );
        for (self.config.global_marks.items) |mark| {
            const line = try std.fmt.allocPrint(self.allocator, "  {c}: frame {d} in {s}\n", .{
                mark.label,
                mark.frame,
                mark.path,
            });
            defer self.allocator.free(line);
            try buffer.appendSlice(self.allocator, line);
        }
        try self.showMessage(buffer.items);
    }

    pub fn runCommand(self: *AppModel, cmd: []const u8, args: []const u8) !void {
        if (std.mem.eql(u8, cmd, "quit")) {
            self.quit_confirm = true;
            self.overlay = .quit;
            self.help_overlay.title = "Quit?";
            self.help_overlay.body = "Press y to quit, n or Esc to cancel.";
            self.help_overlay.visible = true;
        } else if (std.mem.eql(u8, cmd, "help")) {
            self.overlay = .help;
            self.help_overlay.title = "Help";
            self.help_overlay.body = help_view.text;
            self.help_overlay.pick = false;
            self.help_overlay.visible = true;
        } else if (std.mem.eql(u8, cmd, "filter")) {
            self.focus = .filter;
        } else if (std.mem.eql(u8, cmd, "decode-as")) {
            if (args.len == 0) {
                try self.showMessage("Usage: :decode-as layer==selector,protocol");
                return;
            }
            try self.session.addDecodeAs(args);
            self.clearDetail();
            self.loader.clearDetailCache(self.io);
            try self.loader.requestPsml(self.session);
        } else if (std.mem.eql(u8, cmd, "timestamp")) {
            if (args.len == 0) {
                try self.showMessage("Usage: :timestamp a|ad|adoy|d|dd|e|r|u|ud|udoy");
                return;
            }
            try self.session.setTimestampFormat(args);
            try self.loader.requestPsml(self.session);
        } else if (std.mem.eql(u8, cmd, "search")) {
            if (args.len == 0) {
                try self.showMessage("Usage: :search <text>");
                return;
            }
            self.search.case_sensitive = self.config.search_case_sensitive;
            self.search.kind = .string;
            self.search.target = switch (self.focus) {
                .protocol => .details,
                .hex => .bytes,
                else => .list,
            };
            try self.search.setNeedle(self.allocator, args);
            self.byte_search_offset = 0;
            if (!try self.findNextSearch(true)) try self.showMessage("No search match");
        } else if (std.mem.eql(u8, cmd, "search-regex")) {
            if (args.len == 0) {
                try self.showMessage("Usage: :search-regex <pattern>");
                return;
            }
            self.search.case_sensitive = self.config.search_case_sensitive;
            self.search.kind = .regex;
            self.search.target = switch (self.focus) {
                .protocol => .details,
                .hex => .bytes,
                else => .list,
            };
            try self.search.setNeedle(self.allocator, args);
            self.byte_search_offset = 0;
            if (!try self.findNextSearch(true)) try self.showMessage("No regex match");
        } else if (std.mem.eql(u8, cmd, "search-hex")) {
            if (args.len == 0) {
                try self.showMessage("Usage: :search-hex <hex bytes>");
                return;
            }
            self.search.kind = .hex;
            self.search.target = .bytes;
            try self.search.setNeedle(self.allocator, args);
            self.byte_search_offset = 0;
            if (!try self.findNextSearch(true)) try self.showMessage("No hex match");
        } else if (std.mem.eql(u8, cmd, "search-filter")) {
            if (args.len == 0) {
                try self.showMessage("Usage: :search-filter <display filter>");
                return;
            }
            try self.searchByDisplayFilter(args);
        } else if (std.mem.eql(u8, cmd, "clear-filter")) {
            try self.filter.setText("");
            try self.session.setFilter("", null);
            self.filter.state = .ok;
            self.clearDetail();
            try self.loader.requestPsml(self.session);
            self.syncFromSession();
        } else if (std.mem.eql(u8, cmd, "clear-packets")) {
            var newest: u32 = self.hide_through_frame;
            for (self.session.packets) |summary| newest = @max(newest, summary.frame);
            if (self.live_capture or self.tailing) self.hide_through_frame = newest;
            self.session.clearPackets();
            self.clearDetail();
            self.syncFromSession();
        } else if (std.mem.eql(u8, cmd, "load")) {
            if (args.len != 0) try self.openCapture(args);
        } else if (std.mem.eql(u8, cmd, "streams")) {
            const path = self.capturePath() orelse {
                try self.showMessage("No capture file loaded");
                return;
            };
            var proto: []const u8 = "tcp";
            var mode: []const u8 = if (self.config.stream_view.len != 0) self.config.stream_view else "ascii";
            var index: u32 = 0;
            var explicit_index = false;
            var stream_args = std.mem.tokenizeAny(u8, args, " \t");
            if (stream_args.next()) |first| {
                if (std.ascii.eqlIgnoreCase(first, "tcp") or std.ascii.eqlIgnoreCase(first, "udp")) {
                    proto = first;
                    if (stream_args.next()) |second| {
                        index = std.fmt.parseInt(u32, second, 10) catch 0;
                        explicit_index = true;
                    }
                    if (stream_args.next()) |third| mode = third;
                } else {
                    index = std.fmt.parseInt(u32, first, 10) catch 0;
                    explicit_index = true;
                    if (stream_args.next()) |second| mode = second;
                }
            }
            if (!std.ascii.eqlIgnoreCase(mode, "ascii") and
                !std.ascii.eqlIgnoreCase(mode, "hex") and
                !std.ascii.eqlIgnoreCase(mode, "raw"))
            {
                try self.showMessage("Stream mode must be ascii, hex, or raw");
                return;
            }
            if (!explicit_index) {
                if (self.streamFromDetail()) |found| {
                    proto = found.proto;
                    index = found.index;
                }
            }
            const body = try streams_view.loadFollow(
                self.allocator,
                self.io,
                self.tools.tshark,
                path,
                index,
                proto,
                mode,
                self.process_runner,
            );
            defer self.allocator.free(body);
            try self.showStream(proto, index, body);
        } else if (std.mem.eql(u8, cmd, "convs")) {
            const path = self.capturePath() orelse {
                try self.showMessage("No capture file loaded");
                return;
            };
            const ctype = if (args.len != 0) args else "tcp";
            try self.showConversations(path, ctype);
        } else if (std.mem.eql(u8, cmd, "capinfo")) {
            const path = self.capturePath() orelse {
                try self.showMessage("No capture file loaded");
                return;
            };
            const body = try capinfo_view.load(self.allocator, self.io, self.tools.capinfos, path);
            defer self.allocator.free(body);
            try self.showMessage(body);
            self.overlay = .capinfo;
        } else if (std.mem.eql(u8, cmd, "marks")) {
            try self.showMarks();
        } else if (std.mem.eql(u8, cmd, "columns")) {
            try self.applyColumns(args);
        } else if (std.mem.eql(u8, cmd, "tail")) {
            self.tailing = !self.tailing;
            if (self.tailing) self.tail_size = 0;
            try self.showMessage(if (self.tailing)
                "Tailing the capture. New packets appear as the file grows."
            else
                "Stopped tailing the capture.");
        } else if (std.mem.eql(u8, cmd, "config")) {
            const config_path = try self.paths.configFile(self.allocator);
            defer self.allocator.free(config_path);
            const message = try std.fmt.allocPrint(
                self.allocator,
                "Config: {s}\nProfile: {s}\ntshark: {s}\ndumpcap: {s}\n" ++
                    "layout: {s}\npacket colors: {}\nlist ratio: {d:.2}\ndetail ratio: {d:.2}",
                .{
                    config_path,
                    self.config.profile,
                    self.config.tshark,
                    self.config.dumpcap,
                    @tagName(self.config.layout),
                    self.config.packet_colors,
                    self.config.packet_list_ratio,
                    self.config.detail_ratio,
                },
            );
            defer self.allocator.free(message);
            try self.showMessage(message);
        } else if (std.mem.eql(u8, cmd, "logs")) {
            const contents = std.Io.Dir.cwd().readFileAlloc(
                self.io,
                self.paths.log_path,
                self.allocator,
                .limited(1024 * 1024),
            ) catch {
                try self.showMessage(self.paths.log_path);
                return;
            };
            defer self.allocator.free(contents);
            try self.showMessage(contents);
        } else if (std.mem.eql(u8, cmd, "set")) {
            try self.runSetCommand(args);
        } else if (std.mem.eql(u8, cmd, "profile")) {
            try self.runProfileCommand(args);
        } else if (std.mem.eql(u8, cmd, "theme")) {
            if (std.mem.eql(u8, args, "list")) {
                try self.showThemeList();
                return;
            }
            if (args.len != 0) {
                try self.config.setThemeName(args);
                const loaded = self.loadConfiguredTheme() catch {
                    try self.config.setThemeName("default");
                    try self.showMessage("Theme file not found in the zigshark themes directory");
                    return;
                };
                self.applyTheme(loaded);
            } else {
                self.config.dark_mode = !self.config.dark_mode;
                self.applyTheme(self.loadConfiguredTheme() catch theme_mod.resolve(self.config.dark_mode));
            }
        } else if (std.mem.eql(u8, cmd, "no-theme")) {
            try self.config.setThemeName("default");
            self.applyTheme(theme_mod.resolve(self.config.dark_mode));
        } else if (std.mem.eql(u8, cmd, "recents")) {
            try self.showRecents();
        } else if (std.mem.eql(u8, cmd, "recent")) {
            const number = std.fmt.parseInt(usize, args, 10) catch {
                try self.showMessage("Usage: :recent <number>");
                return;
            };
            if (number == 0 or number > self.config.recent_files.items.len) {
                try self.showMessage("Recent file number is out of range");
                return;
            }
            const path = try self.allocator.dupe(u8, self.config.recent_files.items[number - 1]);
            defer self.allocator.free(path);
            try self.openCapture(path);
        } else if (std.mem.eql(u8, cmd, "recent-filter")) {
            const number = std.fmt.parseInt(usize, args, 10) catch {
                try self.showMessage("Usage: :recent-filter <number>");
                return;
            };
            if (number == 0 or number > self.config.recent_filters.items.len) {
                try self.showMessage("Recent filter number is out of range");
                return;
            }
            const filter = self.config.recent_filters.items[number - 1];
            try self.filter.setText(filter);
            try onFilterSubmit(self, filter);
        } else if (std.mem.eql(u8, cmd, "wormhole")) {
            const path = switch (self.session.source) {
                .file => |p| p,
                else => args,
            };
            if (path.len == 0) {
                try self.showMessage("Usage: :wormhole <file>");
                return;
            }
            if (self.transfer_job) |job| job.destroy();
            self.transfer_job = transfer.Job.start(self.allocator, self.io, path) catch |err| {
                switch (err) {
                    error.WormholeNotFound => try self.showMessage("wormhole CLI not found"),
                    else => try self.showMessage("Could not start wormhole"),
                }
                return;
            };
            try self.showMessage("Sending via wormhole…");
        } else {
            try self.showMessage("Unknown command");
        }
    }

    fn findNextSearch(self: *AppModel, forward: bool) !bool {
        switch (self.search.target) {
            .list => {
                const hit = search_mod.findNextList(self.session, &self.search, forward) orelse return false;
                _ = self.session.select(hit.packet_index);
                self.syncFromSession();
                try self.loadDetailForSelection();
                return true;
            },
            .details => return self.protocol_tree.findPattern(
                self.search.needle,
                self.search.kind == .regex,
                forward,
            ),
            .bytes => {
                const bundle = &(self.detail_bundle orelse return false);
                var hit: ?usize = null;
                if (forward) {
                    hit = search_mod.findNextBytes(
                        &bundle.bytes,
                        &self.search,
                        self.byte_search_offset,
                    );
                } else {
                    var cursor: usize = 0;
                    while (search_mod.findNextBytes(&bundle.bytes, &self.search, cursor)) |candidate| {
                        if (candidate >= self.byte_search_offset) break;
                        hit = candidate;
                        cursor = candidate + 1;
                    }
                }
                const offset = hit orelse return false;
                self.byte_search_offset = if (forward) offset + 1 else offset;
                const length = if (self.search.kind == .hex)
                    hexNeedleLength(self.search.needle)
                else
                    self.search.needle.len;
                self.hex.setHighlight(offset, @max(length, 1));
                self.hex.scroll_top = offset / @max(self.hex.bytes_per_line, 1);
                return true;
            },
        }
    }

    fn searchByDisplayFilter(self: *AppModel, filter: []const u8) !void {
        const path = self.capturePath() orelse {
            try self.showMessage("Display-filter search requires a seekable capture file");
            return;
        };
        if (!try filter_mod.validateDisplayFilterRun(
            self.allocator,
            self.io,
            self.tools.tshark,
            self.empty_pcap,
            filter,
            self.process_runner,
        )) {
            try self.showMessage("Invalid display filter");
            return;
        }

        var argv: process_mod.Argv = .{};
        defer argv.deinit(self.allocator);
        const filter_args = [_][]const u8{
            self.tools.tshark,
            "-r",
            path,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-Y",
            filter,
        };
        for (&filter_args) |arg| {
            try argv.append(self.allocator, arg);
        }
        if (self.session.wireshark_profile.len != 0) {
            try argv.append(self.allocator, "-C");
            try argv.append(self.allocator, self.session.wireshark_profile);
        }
        for (self.session.decode_as_args.items) |decode_as| {
            try argv.append(self.allocator, "-d");
            try argv.append(self.allocator, decode_as);
        }

        var output = try self.runProcess(argv.slice());
        defer output.deinit(self.allocator);
        if (!output.term.success()) {
            try self.showMessage(if (output.stderr.len != 0) output.stderr else "Filter search failed");
            return;
        }

        const current = self.session.selectedFrame() orelse 0;
        var first: ?u32 = null;
        var next: ?u32 = null;
        var lines = std.mem.splitAny(u8, output.stdout, "\r\n");
        while (lines.next()) |line| {
            const frame = std.fmt.parseInt(u32, std.mem.trim(u8, line, " \t"), 10) catch continue;
            if (first == null) first = frame;
            if (frame > current and next == null) next = frame;
        }
        const target = next orelse first orelse {
            try self.showMessage("No packets matched the display filter");
            return;
        };
        for (self.session.packets, 0..) |summary, index| {
            if (summary.frame == target) {
                _ = self.session.select(index);
                self.packet_table.selected = index;
                self.syncFromSession();
                try self.loadDetailForSelection();
                return;
            }
        }
        try self.showMessage("The matched frame is hidden by the active list filter");
    }

    fn runSetCommand(self: *AppModel, args: []const u8) !void {
        const trimmed = std.mem.trim(u8, args, " \t");
        if (trimmed.len == 0) {
            const text = try self.config.formatSettings(self.allocator);
            defer self.allocator.free(text);
            try self.showMessage(text);
            return;
        }
        const separator = std.mem.indexOfScalar(u8, trimmed, ' ') orelse {
            try self.showMessage("Usage: :set <key> <value>   (:set alone lists every key)");
            return;
        };
        const name = std.mem.trim(u8, trimmed[0..separator], " \t");
        const value = std.mem.trim(u8, trimmed[separator + 1 ..], " \t");
        self.config.applySetting(name, value) catch |err| switch (err) {
            error.UnknownSetting => {
                try self.showMessage("Unknown setting. :set lists them.");
                return;
            },
            error.InvalidValue => {
                try self.showMessage("That value is not valid for the setting.");
                return;
            },
            else => return err,
        };
        if (std.mem.eql(u8, name, "packet-colors")) {
            self.packet_table.packet_colors = self.config.packet_colors;
        } else if (std.mem.eql(u8, name, "dark-mode") or std.mem.eql(u8, name, "theme")) {
            self.applyTheme(self.loadConfiguredTheme() catch theme_mod.resolve(self.config.dark_mode));
        } else if (std.mem.eql(u8, name, "packet-list-ratio")) {
            self.hsplit_main.ratio = self.config.packet_list_ratio;
            self.vsplit_main.ratio = self.config.packet_list_ratio;
        } else if (std.mem.eql(u8, name, "detail-ratio")) {
            self.hsplit_detail.ratio = self.config.detail_ratio;
        } else if (std.mem.eql(u8, name, "layout")) {
            self.layout_stacked = self.config.layout != .side_by_side;
        } else if (std.mem.eql(u8, name, "wireshark-profile")) {
            try self.session.setWiresharkProfile(value);
            self.clearDetail();
            self.loader.clearDetailCache(self.io);
            try self.loader.requestPsml(self.session);
        } else if (std.mem.eql(u8, name, "tshark-args")) {
            self.loader.config.tshark_args = self.config.tshark_args;
        } else if (std.mem.eql(u8, name, "pcap-bundle-size")) {
            self.loader.config.bundle_size = self.config.pcap_bundle_size;
        } else if (std.mem.eql(u8, name, "pcap-cache-size")) {
            self.loader.config.cache_size = self.config.pcap_cache_size;
        } else if (std.mem.eql(u8, name, "search-case-sensitive")) {
            self.search.case_sensitive = self.config.search_case_sensitive;
        }
        self.persistConfig();
        try self.showMessage("Option updated");
    }

    fn applyColumns(self: *AppModel, args: []const u8) !void {
        const trimmed = std.mem.trim(u8, args, " \t");
        if (trimmed.len == 0 or std.mem.eql(u8, trimmed, "show")) {
            const current = if (self.config.column_format.len != 0) self.config.column_format else process_mod.default_column_format;
            const message = try std.fmt.allocPrint(
                self.allocator,
                "Columns\n{s}\n\n:columns default\n:columns delta\n:columns absolute\n:columns set gui.column.format:\"No.\",\"%m\",...\nClick a heading to sort.",
                .{current},
            );
            defer self.allocator.free(message);
            try self.showMessage(message);
            return;
        }
        if (std.mem.eql(u8, trimmed, "default")) {
            try self.config.setColumnFormat("");
        } else if (std.mem.eql(u8, trimmed, "delta")) {
            try self.config.setColumnFormat(process_mod.delta_column_format);
        } else if (std.mem.eql(u8, trimmed, "absolute")) {
            try self.config.setColumnFormat(process_mod.absolute_column_format);
        } else if (std.mem.startsWith(u8, trimmed, "set ")) {
            try self.config.setColumnFormat(std.mem.trim(u8, trimmed["set ".len..], " \t"));
        } else {
            try self.showMessage("Usage: :columns [default|delta|absolute|set <gui.column.format:...>]");
            return;
        }
        self.loader.config.column_format = self.config.column_format;
        self.persistConfig();
        self.clearDetail();
        try self.loader.requestPsml(self.session);
        try self.showMessage("Column layout updated");
    }

    fn noteTail(self: *AppModel, path: []const u8) void {
        self.tailing = false;
        self.tail_size = 0;
        const cwd = std.Io.Dir.cwd();
        const stat = cwd.statFile(self.io, path, .{}) catch return;
        self.tail_size = stat.size;
        self.tailing = stat.kind == .named_pipe;
    }

    fn refreshTailedFile(self: *AppModel) !void {
        const path = self.capturePath() orelse return;
        const cwd = std.Io.Dir.cwd();
        const stat = cwd.statFile(self.io, path, .{}) catch return;
        if (stat.size == self.tail_size) return;
        self.tail_size = stat.size;
        try self.loader.requestPsml(self.session);
    }

    fn pollTransfer(self: *AppModel) void {
        const job = self.transfer_job orelse return;
        const text = job.snapshot(self.allocator) catch return;
        if (job.isFinished()) {
            if (self.overlay_body_owned.len != 0) self.allocator.free(self.overlay_body_owned);
            self.overlay_body_owned = text;
            self.msg_overlay.body = self.overlay_body_owned;
            self.msg_overlay.visible = true;
            self.overlay = .message;
            job.destroy();
            self.transfer_job = null;
            return;
        }
        if (std.mem.eql(u8, text, self.overlay_body_owned)) {
            self.allocator.free(text);
            return;
        }
        if (self.overlay_body_owned.len != 0) self.allocator.free(self.overlay_body_owned);
        self.overlay_body_owned = text;
        self.msg_overlay.body = self.overlay_body_owned;
        self.msg_overlay.title = "Wormhole";
        self.msg_overlay.visible = true;
        self.overlay = .message;
    }

    fn persistConfig(self: *AppModel) void {
        const path = self.paths.configFile(self.allocator) catch return;
        defer self.allocator.free(path);
        self.config.save(self.io, path) catch {};
    }

    fn clearStreamChunks(self: *AppModel) void {
        for (self.stream_chunks) |*chunk| chunk.deinit(self.allocator);
        if (self.stream_chunks.len != 0) self.allocator.free(self.stream_chunks);
        self.stream_chunks = &.{};
    }

    fn clearConversations(self: *AppModel) void {
        for (self.conversations) |*conversation| conversation.deinit(self.allocator);
        if (self.conversations.len != 0) self.allocator.free(self.conversations);
        self.conversations = &.{};
    }

    fn showPick(self: *AppModel, title: []const u8, body: []const u8, kind: OverlayKind) !void {
        if (self.overlay_body_owned.len != 0) self.allocator.free(self.overlay_body_owned);
        self.overlay_body_owned = try self.allocator.dupe(u8, body);
        self.help_overlay.title = title;
        self.help_overlay.body = self.overlay_body_owned;
        self.help_overlay.visible = true;
        self.help_overlay.pick = true;
        self.help_overlay.selected = 0;
        self.help_overlay.scroll_top = 0;
        self.help_overlay.line_count = std.mem.count(u8, body, "\n") + if (body.len > 0 and !std.mem.endsWith(u8, body, "\n")) @as(usize, 1) else 0;
        self.msg_overlay.visible = false;
        self.overlay = kind;
    }

    fn showStream(self: *AppModel, proto: []const u8, index: u32, body: []const u8) !void {
        if (self.stream_filter.len != 0) self.allocator.free(self.stream_filter);
        self.stream_filter = try std.fmt.allocPrint(self.allocator, "{s}.stream == {d}", .{ proto, index });
        var parsed = streams_shark.parse(self.allocator, body) catch {
            try self.showPick("Stream", body, .streams);
            return;
        };
        self.clearStreamChunks();
        self.stream_chunks = parsed.chunks;
        parsed.chunks = &.{};
        defer parsed.deinit(self.allocator);
        if (parsed.filter.len != 0) {
            self.allocator.free(self.stream_filter);
            self.stream_filter = try self.allocator.dupe(u8, parsed.filter);
        }
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        if (parsed.chunks.len == 0) {
            try text.writer.writeAll(body);
        } else {
            for (parsed.chunks, 0..) |chunk, i| {
                if (i != 0) try text.writer.writeByte('\n');
                const preview = std.mem.sliceTo(chunk.data, 0);
                const shown = if (preview.len > 48) preview[0..48] else preview;
                try text.writer.print("{d: >3}  {s}  {d} bytes  {s}", .{
                    i,
                    if (chunk.direction == .client) "client -> server" else "server -> client",
                    chunk.data.len,
                    shown,
                });
            }
        }
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick("Stream  Enter jumps to that chunk", owned, .streams);
    }

    fn showConversations(self: *AppModel, path: []const u8, proto: []const u8) !void {
        var argv = try process_mod.argvConversations(self.allocator, self.tools.tshark, path, proto);
        defer argv.deinit(self.allocator);
        var out = try self.runProcess(argv.slice());
        defer out.deinit(self.allocator);
        self.clearConversations();
        if (self.conversation_proto.len != 0) self.allocator.free(self.conversation_proto);
        self.conversation_proto = try self.allocator.dupe(u8, proto);
        self.conversations = convs_shark.parse(self.allocator, out.stdout) catch {
            try self.showPick("Conversations", if (out.stdout.len != 0) out.stdout else out.stderr, .convs);
            return;
        };
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        if (self.conversations.len == 0) {
            try text.writer.print("No {s} conversations\n{s}", .{ proto, out.stderr });
        }
        for (self.conversations, 0..) |conversation, i| {
            if (i != 0) try text.writer.writeByte('\n');
            try text.writer.print("{d: >3}  {s}", .{ i + 1, conversation.addr_a });
            if (conversation.port_a) |port| try text.writer.print(":{d}", .{port});
            try text.writer.print(" <-> {s}", .{conversation.addr_b});
            if (conversation.port_b) |port| try text.writer.print(":{d}", .{port});
            try text.writer.print("   {d} frames  {d} bytes", .{ conversation.frames_total, conversation.bytes_total });
        }
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick("Conversations  Enter filters the list", owned, .convs);
    }

    pub fn activatePick(self: *AppModel) !void {
        switch (self.overlay) {
            .convs => {
                const index = self.help_overlay.selected;
                if (index >= self.conversations.len) return;
                const filter = try convs_shark.displayFilter(
                    self.allocator,
                    self.conversations[index],
                    self.conversation_proto,
                );
                defer self.allocator.free(filter);
                self.dismissOverlays();
                try self.filter.setText(filter);
                try onFilterSubmit(self, filter);
            },
            .streams => {
                const index = self.help_overlay.selected;
                const filter = if (index < self.stream_chunks.len and self.stream_chunks[index].data.len > 0) blk: {
                    const contains = try streams_shark.frameContainsFilter(
                        self.allocator,
                        self.stream_chunks[index].data,
                    );
                    defer self.allocator.free(contains);
                    break :blk try std.fmt.allocPrint(
                        self.allocator,
                        "({s}) and ({s})",
                        .{ self.stream_filter, contains },
                    );
                } else try self.allocator.dupe(u8, self.stream_filter);
                defer self.allocator.free(filter);
                if (filter.len == 0) return;
                self.dismissOverlays();
                try self.searchByDisplayFilter(filter);
            },
            else => {},
        }
    }

    fn showThemeList(self: *AppModel) !void {
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        try text.writer.writeAll("Themes: default, or a .toml name from themes/ or the config themes directory\n");
        try text.writer.writeAll("midnight\npaper\n");
        const themes_dir = self.paths.themesDir(self.allocator) catch null;
        if (themes_dir) |dir_path| {
            defer self.allocator.free(dir_path);
            var dir = std.Io.Dir.cwd().openDir(self.io, dir_path, .{ .iterate = true }) catch null;
            if (dir) |*opened| {
                defer opened.close(self.io);
                var it = opened.iterate();
                while (it.next(self.io) catch null) |entry| {
                    if (!std.mem.endsWith(u8, entry.name, ".toml")) continue;
                    try text.writer.print("{s}\n", .{entry.name[0 .. entry.name.len - 5]});
                }
            }
        }
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showMessage(owned);
    }

    fn runProfileCommand(self: *AppModel, args: []const u8) !void {
        if (args.len == 0 or std.mem.eql(u8, args, "list")) {
            try self.showProfileList();
            return;
        }
        const separator = std.mem.indexOfScalar(u8, args, ' ') orelse {
            try self.showMessage("Usage: :profile list | create <name> | use <name> | delete <name>");
            return;
        };
        const action = std.mem.trim(u8, args[0..separator], " \t");
        const name = std.mem.trim(u8, args[separator + 1 ..], " \t");
        if (name.len == 0) {
            try self.showMessage("Profile name is required");
            return;
        }
        if (std.mem.eql(u8, action, "create")) {
            try profiles_feature.saveProfile(self.config, self.io, self.paths, name);
            try self.showMessage("Profile created");
            return;
        }
        if (std.mem.eql(u8, action, "delete")) {
            profiles_feature.deleteProfile(self.allocator, self.io, self.paths, name) catch {
                try self.showMessage("Could not delete that profile");
                return;
            };
            try self.showMessage("Profile deleted");
            return;
        }
        if (!std.mem.eql(u8, action, "use")) {
            try self.showMessage("Usage: :profile list | create <name> | use <name> | delete <name>");
            return;
        }

        var new_config = try profiles_feature.loadProfile(
            self.allocator,
            self.io,
            self.paths,
            name,
        );
        var config_moved = false;
        errdefer if (!config_moved) new_config.deinit();
        try new_config.setProfileName(name);
        var new_tools = try tools_mod.discover(self.allocator, self.io, .{
            .tshark = new_config.tshark,
            .dumpcap = new_config.dumpcap,
            .capinfos = new_config.capinfos,
        });
        var tools_moved = false;
        errdefer if (!tools_moved) new_tools.deinit();

        self.config.deinit();
        self.config.* = new_config;
        config_moved = true;
        self.tools.deinit();
        self.tools.* = new_tools;
        tools_moved = true;
        self.loader.config.tshark_args = self.config.tshark_args;
        try self.resetFieldCompletions();
        self.applyTheme(self.loadConfiguredTheme() catch theme_mod.resolve(self.config.dark_mode));
        self.packet_table.packet_colors = self.config.packet_colors;
        self.hsplit_main.ratio = self.config.packet_list_ratio;
        self.vsplit_main.ratio = self.config.packet_list_ratio;
        self.hsplit_detail.ratio = self.config.detail_ratio;
        self.clearDetail();
        self.loader.clearDetailCache(self.io);
        try self.loader.requestPsml(self.session);
        try self.showMessage("Profile loaded");
    }

    fn cycleFocus(self: *AppModel) void {
        self.focus = switch (self.focus) {
            .filter => .packets,
            .packets => .protocol,
            .protocol => .hex,
            .hex => .filter,
        };
    }

    fn applyTheme(self: *AppModel, theme: theme_mod.Theme) void {
        self.theme = theme;
        self.packet_table.theme = theme;
        self.protocol_tree.theme = theme;
        self.hex.theme = theme;
        self.filter.theme = theme;
        self.status.theme = theme;
        self.header.theme = theme;
        self.command.theme = theme;
        self.help_overlay.theme = theme;
        self.msg_overlay.theme = theme;
    }

    fn loadConfiguredTheme(self: *AppModel) !theme_mod.Theme {
        const base = theme_mod.resolve(self.config.dark_mode);
        if (self.config.theme.len == 0 or std.mem.eql(u8, self.config.theme, "default")) {
            return base;
        }
        const themes_dir = try self.paths.themesDir(self.allocator);
        defer self.allocator.free(themes_dir);
        const filename = try std.fmt.allocPrint(
            self.allocator,
            "{s}.toml",
            .{self.config.theme},
        );
        defer self.allocator.free(filename);
        const path = try std.fs.path.join(self.allocator, &.{ themes_dir, filename });
        defer self.allocator.free(path);
        const cwd = std.Io.Dir.cwd();
        const contents = cwd.readFileAlloc(self.io, path, self.allocator, .limited(64 * 1024)) catch blk: {
            const bundled = try std.fmt.allocPrint(self.allocator, "themes/{s}.toml", .{self.config.theme});
            defer self.allocator.free(bundled);
            break :blk try cwd.readFileAlloc(self.io, bundled, self.allocator, .limited(64 * 1024));
        };
        defer self.allocator.free(contents);
        return theme_mod.parseToml(contents, base);
    }

    fn fieldShow(node: *const packet.DetailNode, name: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, node.name, name) and node.show.len != 0) return node.show;
        for (node.children) |*child| {
            if (fieldShow(child, name)) |show| return show;
        }
        return null;
    }

    fn streamFromDetail(self: *const AppModel) ?struct { proto: []const u8, index: u32 } {
        const bundle = self.detail_bundle orelse return null;
        if (fieldShow(&bundle.pdml.root, "tcp.stream")) |show| {
            return .{ .proto = "tcp", .index = std.fmt.parseInt(u32, show, 10) catch return null };
        }
        if (fieldShow(&bundle.pdml.root, "udp.stream")) |show| {
            return .{ .proto = "udp", .index = std.fmt.parseInt(u32, show, 10) catch return null };
        }
        return null;
    }

    fn showProfileList(self: *AppModel) !void {
        const names = try profiles_feature.listProfiles(self.allocator, self.io, self.paths);
        defer {
            for (names) |name| self.allocator.free(name);
            self.allocator.free(names);
        }
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        try text.writer.writeAll("Profiles\n");
        if (names.len == 0) try text.writer.writeAll("(none yet — :profile create <name>)\n");
        for (names) |name| try text.writer.print("{s}\n", .{name});
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showMessage(owned);
    }

    fn copyFocused(self: *AppModel, ctx: *vxfw.EventContext) !void {
        switch (self.focus) {
            .filter => {
                const text = try self.filter.copyText(self.allocator);
                defer self.allocator.free(text);
                try copy_feature.copyText(
                    self.allocator,
                    self.io,
                    ctx,
                    self.config.copy_command,
                    text,
                );
            },
            .packets => {
                const text = try self.packet_table.formatSelected(self.allocator);
                defer self.allocator.free(text);
                try copy_feature.copyText(
                    self.allocator,
                    self.io,
                    ctx,
                    self.config.copy_command,
                    text,
                );
            },
            .protocol => {
                const text = if (self.copy_mode)
                    try self.protocol_tree.formatSubtree(self.allocator)
                else
                    try self.allocator.dupe(u8, self.protocol_tree.selectedText());
                defer self.allocator.free(text);
                try copy_feature.copyText(
                    self.allocator,
                    self.io,
                    ctx,
                    self.config.copy_command,
                    text,
                );
            },
            .hex => {
                const text = try self.hex.formatSelection(self.allocator);
                defer self.allocator.free(text);
                try copy_feature.copyText(
                    self.allocator,
                    self.io,
                    ctx,
                    self.config.copy_command,
                    text,
                );
            },
        }
        try ctx.sendNotification("zigshark", "Copied selection");
    }

    fn dismissOverlays(self: *AppModel) void {
        self.help_overlay.visible = false;
        self.help_overlay.pick = false;
        self.msg_overlay.visible = false;
        self.command.visible = false;
        self.overlay = .none;
        self.quit_confirm = false;
    }

    pub fn widget(self: *AppModel) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = AppModel.typeErasedEventHandler,
            .drawFn = AppModel.typeErasedDrawFn,
        };
    }

    fn typeErasedEventHandler(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *AppModel = @ptrCast(@alignCast(ptr));
        try self.handleEvent(ctx, event);
    }

    fn typeErasedDrawFn(ptr: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const self: *AppModel = @ptrCast(@alignCast(ptr));
        return self.draw(ctx);
    }

    pub fn handleEvent(self: *AppModel, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        switch (event) {
            .init => {
                try ctx.tick(100, self.widget());
                try self.requestFocus(ctx);
            },
            .tick => {
                if (signals.quitRequested()) {
                    ctx.quit = true;
                    return;
                }
                try self.processLoaderEvents();
                if (self.live_capture) {
                    self.live_refresh_ticks +%= 1;
                    if (self.live_refresh_ticks >= 10) {
                        self.live_refresh_ticks = 0;
                        try self.refreshLiveCapture();
                    }
                } else if (self.tailing) {
                    self.tail_ticks +%= 1;
                    if (self.tail_ticks >= 10) {
                        self.tail_ticks = 0;
                        self.refreshTailedFile() catch {};
                    }
                }
                self.pollTransfer();
                try ctx.tick(100, self.widget());
                ctx.redraw = true;
            },
            .key_press => |key| {
                if (self.quit_confirm) {
                    if (key.matches('y', .{}) or key.matches('Y', .{})) {
                        ctx.quit = true;
                        return;
                    }
                    if (key.matches('n', .{}) or key.matches(vaxis.Key.escape, .{})) {
                        self.dismissOverlays();
                        return ctx.consumeAndRedraw();
                    }
                }
                if (self.command.visible) {
                    return;
                }
                if (self.help_overlay.visible or self.msg_overlay.visible) {
                    if (key.matches('q', .{}) or key.matches(vaxis.Key.escape, .{})) {
                        self.dismissOverlays();
                        return ctx.consumeAndRedraw();
                    }
                    if (self.help_overlay.visible and self.help_overlay.pick and key.matches(vaxis.Key.enter, .{})) {
                        try self.activatePick();
                        return ctx.consumeAndRedraw();
                    }
                    if (self.help_overlay.visible) {
                        try self.help_overlay.widget().handleEvent(ctx, event);
                    } else {
                        try self.msg_overlay.widget().handleEvent(ctx, event);
                    }
                    return;
                }
                if (key.matches(vaxis.Key.escape, .{})) {
                    if (self.copy_mode) {
                        self.copy_mode = false;
                        self.status.mode = "";
                        return ctx.consumeAndRedraw();
                    }
                    self.dismissOverlays();
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('z', .{ .ctrl = true })) {
                    signals.suspendJob();
                    try ctx.queueRefresh();
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('q', .{})) {
                    if (self.help_overlay.visible or self.msg_overlay.visible or self.command.visible) {
                        self.dismissOverlays();
                        return ctx.consumeAndRedraw();
                    }
                    self.quit_confirm = true;
                    self.help_overlay.title = "Quit?";
                    self.help_overlay.body = "Press y to quit, n or Esc to cancel.";
                    self.help_overlay.visible = true;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('z', .{})) {
                    if (self.pending_z) {
                        ctx.quit = true;
                        return;
                    }
                    self.pending_z = true;
                    return ctx.consumeEvent();
                }
                if (key.matches('Z', .{ .shift = true })) {
                    if (self.pending_z) {
                        ctx.quit = true;
                        return;
                    }
                    self.pending_z = true;
                    return ctx.consumeEvent();
                }
                self.pending_z = false;
                if (key.matches('/', .{})) {
                    try self.ensureFieldCompletions();
                    self.focus = .filter;
                    try ctx.requestFocus(self.filter.widget());
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(':', .{})) {
                    try self.command.setText("");
                    self.command.visible = true;
                    try ctx.requestFocus(self.command.widget());
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('?', .{ .shift = true })) {
                    self.help_overlay.visible = true;
                    self.help_overlay.scroll_top = 0;
                    self.overlay = .help;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('|', .{ .shift = true })) {
                    self.layout_stacked = !self.layout_stacked;
                    self.config.layout = if (self.layout_stacked) .stacked else .side_by_side;
                    self.hsplit_main.ratio = self.config.packet_list_ratio;
                    self.vsplit_main.ratio = self.config.packet_list_ratio;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('\\', .{})) {
                    if (self.focus != .filter) {
                        self.zoomed = if (self.zoomed == self.focus) null else self.focus;
                    }
                    return ctx.consumeAndRedraw();
                }
                if ((key.matches('+', .{}) or key.matches('=', .{})) and self.focus == .packets) {
                    self.config.packet_list_ratio = @min(
                        @as(f32, 0.85),
                        self.config.packet_list_ratio + 0.05,
                    );
                    self.hsplit_main.ratio = self.config.packet_list_ratio;
                    self.vsplit_main.ratio = self.config.packet_list_ratio;
                    return ctx.consumeAndRedraw();
                }
                if ((key.matches('-', .{}) or key.matches('_', .{ .shift = true })) and self.focus == .packets) {
                    self.config.packet_list_ratio = @max(
                        @as(f32, 0.15),
                        self.config.packet_list_ratio - 0.05,
                    );
                    self.hsplit_main.ratio = self.config.packet_list_ratio;
                    self.vsplit_main.ratio = self.config.packet_list_ratio;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('>', .{}) or key.matches('.', .{ .shift = true })) {
                    self.config.detail_ratio = @min(
                        @as(f32, 0.85),
                        self.config.detail_ratio + 0.05,
                    );
                    self.hsplit_detail.ratio = self.config.detail_ratio;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('<', .{}) or key.matches(',', .{ .shift = true })) {
                    self.config.detail_ratio = @max(
                        @as(f32, 0.15),
                        self.config.detail_ratio - 0.05,
                    );
                    self.hsplit_detail.ratio = self.config.detail_ratio;
                    return ctx.consumeAndRedraw();
                }
                if (key.matches(vaxis.Key.tab, .{ .shift = true })) {
                    if (self.focus == .filter) {
                        try self.ensureFieldCompletions();
                        if (try self.completeFilter(false)) return ctx.consumeAndRedraw();
                    }
                }
                if (key.matches(vaxis.Key.tab, .{})) {
                    if (self.focus == .filter) try self.ensureFieldCompletions();
                    if (self.focus == .filter and try self.completeFilter(true)) {
                        return ctx.consumeAndRedraw();
                    }
                    self.cycleFocus();
                    try self.requestFocus(ctx);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('w', .{ .ctrl = true })) {
                    self.cycleFocus();
                    try self.requestFocus(ctx);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('l', .{ .ctrl = true })) {
                    try ctx.queueRefresh();
                    return;
                }
                if (key.matches('c', .{ .ctrl = true })) {
                    if (self.copy_mode) {
                        try self.copyFocused(ctx);
                        self.copy_mode = false;
                        self.status.mode = "";
                        return ctx.consumeAndRedraw();
                    }
                    // Clean exit — never leave raw mode / panic dump on screen.
                    ctx.quit = true;
                    return ctx.consumeEvent();
                }
                if (key.matches('c', .{})) {
                    self.copy_mode = !self.copy_mode;
                    self.status.mode = if (self.copy_mode)
                        " COPY MODE — Ctrl-C copy, Esc cancel │"
                    else
                        "";
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('f', .{ .ctrl = true })) {
                    self.command.visible = true;
                    try self.command.setText(if (self.focus == .hex) "search-hex " else "search ");
                    try ctx.requestFocus(self.command.widget());
                    return ctx.consumeAndRedraw();
                }
                if (self.awaiting_mark or self.awaiting_jump) {
                    const raw: ?u8 = if (key.codepoint <= 0x7f) @intCast(key.codepoint) else null;
                    const lower = if (raw) |char| std.ascii.toLower(char) else 0;
                    if (lower >= 'a' and lower <= 'z') {
                        const is_global = key.mods.shift or (raw.? >= 'A' and raw.? <= 'Z');
                        const ch = if (is_global) std.ascii.toUpper(lower) else lower;
                        try self.applyMark(ch, is_global, self.awaiting_jump);
                        self.awaiting_mark = false;
                        self.awaiting_jump = false;
                        return ctx.consumeAndRedraw();
                    }
                    self.awaiting_mark = false;
                    self.awaiting_jump = false;
                }
                if (key.matches('m', .{})) {
                    self.awaiting_mark = true;
                    return ctx.consumeEvent();
                }
                if (key.matches('\'', .{})) {
                    self.awaiting_jump = true;
                    return ctx.consumeEvent();
                }
                if (key.matches('n', .{})) {
                    _ = try self.findNextSearch(true);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('N', .{ .shift = true })) {
                    _ = try self.findNextSearch(false);
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }

        if (self.help_overlay.visible or self.msg_overlay.visible) {
            try self.help_overlay.widget().handleEvent(ctx, event);
            try self.msg_overlay.widget().handleEvent(ctx, event);
            return;
        }
    }

    fn requestFocus(self: *AppModel, ctx: *vxfw.EventContext) !void {
        const w = switch (self.focus) {
            .filter => self.filter.widget(),
            .packets => self.packet_table.widget(),
            .protocol => self.protocol_tree.widget(),
            .hex => self.hex.widget(),
        };
        try ctx.requestFocus(w);
    }

    pub fn draw(self: *AppModel, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
        const size = ctx.max.size();
        self.packet_table.focused = self.focus == .packets;
        self.protocol_tree.focused = self.focus == .protocol;
        self.hex.focused = self.focus == .hex;
        self.status.pane = switch (self.focus) {
            .packets => "list",
            .protocol => "tree",
            .hex => "hex",
            .filter => "filter",
        };
        const header_h: u16 = 1;
        const filter_h: u16 = 1;
        const status_h: u16 = 1;
        const divider_h: u16 = 1;
        const use_stacked = self.layout_stacked or size.width < 90;

        var idx: usize = 0;
        var row: u16 = 0;

        const header_surf = try self.header.draw(ctx.withConstraints(.{ .height = header_h }, .{ .width = size.width, .height = header_h }));
        self.children_buf[idx] = .{ .origin = .{ .row = row, .col = 0 }, .surface = header_surf };
        idx += 1;
        row += header_h;

        const filter_surf = try self.filter.draw(ctx.withConstraints(.{ .height = filter_h }, .{ .width = size.width, .height = filter_h }));
        self.children_buf[idx] = .{ .origin = .{ .row = row, .col = 0 }, .surface = filter_surf };
        idx += 1;
        row += filter_h;

        const main_top = row;
        const main_h = size.height -| header_h -| filter_h -| status_h;

        if (use_stacked) {
            idx = try self.drawStacked(ctx, size.width, main_top, main_h, divider_h, idx);
        } else {
            idx = try self.drawSideBySide(ctx, size.width, main_top, main_h, divider_h, idx);
        }

        const status_surf = try self.status.draw(ctx.withConstraints(.{ .height = status_h }, .{ .width = size.width, .height = status_h }));
        self.children_buf[idx] = .{ .origin = .{ .row = size.height -| status_h, .col = 0 }, .surface = status_surf };
        idx += 1;

        if (self.help_overlay.visible) {
            const ov = try self.help_overlay.draw(ctx);
            self.children_buf[idx] = .{ .origin = .{ .row = 0, .col = 0 }, .surface = ov, .z_index = 10 };
            idx += 1;
        }
        if (self.msg_overlay.visible) {
            const ov = try self.msg_overlay.draw(ctx);
            self.children_buf[idx] = .{ .origin = .{ .row = 0, .col = 0 }, .surface = ov, .z_index = 11 };
            idx += 1;
        }
        if (self.command.visible) {
            const pal = try self.command.draw(ctx);
            self.children_buf[idx] = .{ .origin = .{ .row = 0, .col = 0 }, .surface = pal, .z_index = 12 };
            idx += 1;
        }

        return .{
            .size = size,
            .widget = self.widget(),
            .buffer = &.{},
            .children = self.children_buf[0..idx],
        };
    }

    fn drawStacked(
        self: *AppModel,
        ctx: vxfw.DrawContext,
        width: u16,
        origin_row: u16,
        usable: u16,
        divider_h: u16,
        start_idx: usize,
    ) std.mem.Allocator.Error!usize {
        var packet_h: u16 = 0;
        var tree_h: u16 = 0;
        var hex_h: u16 = 0;
        const chrome = divider_h + divider_h;
        const body = usable -| chrome;
        if (self.zoomed) |focus| {
            switch (focus) {
                .packets => packet_h = body,
                .protocol => tree_h = body,
                .hex => hex_h = body,
                .filter => {
                    packet_h = body / 2;
                    tree_h = body -| packet_h;
                },
            }
        } else {
            const list_ratio = std.math.clamp(self.config.packet_list_ratio, 0.25, 0.65);
            const tree_ratio = std.math.clamp(self.config.detail_ratio, 0.25, 0.7);
            packet_h = @max(@as(u16, @intFromFloat(@as(f32, @floatFromInt(body)) * list_ratio)), 3);
            if (packet_h >= body) packet_h = body -| 2;
            const rest = body -| packet_h;
            tree_h = @max(@as(u16, @intFromFloat(@as(f32, @floatFromInt(rest)) * tree_ratio)), 2);
            if (tree_h >= rest) tree_h = rest -| 1;
            hex_h = rest -| tree_h;
        }

        var idx = start_idx;
        var row = origin_row;

        if (packet_h > 0) {
            const packets = try self.packet_table.draw(ctx.withConstraints(.{ .height = packet_h }, .{ .width = width, .height = packet_h }));
            self.children_buf[idx] = .{ .origin = .{ .row = row, .col = 0 }, .surface = packets };
            idx += 1;
            row += packet_h;
        }

        if (tree_h > 0 or hex_h > 0) {
            const div1 = try drawDivider(ctx, width, self.theme);
            self.children_buf[idx] = .{ .origin = .{ .row = row, .col = 0 }, .surface = div1 };
            idx += 1;
            row += divider_h;
        }

        if (tree_h > 0) {
            idx = try self.drawTreePane(ctx, width, row, tree_h, idx);
            row += tree_h;
        }

        if (hex_h > 0) {
            const div2 = try drawDivider(ctx, width, self.theme);
            self.children_buf[idx] = .{ .origin = .{ .row = row, .col = 0 }, .surface = div2 };
            idx += 1;
            row += divider_h;

            const hex = try self.hex.draw(ctx.withConstraints(.{ .height = hex_h }, .{ .width = width, .height = hex_h }));
            self.children_buf[idx] = .{ .origin = .{ .row = row, .col = 0 }, .surface = hex };
            idx += 1;
        }
        return idx;
    }

    fn drawSideBySide(
        self: *AppModel,
        ctx: vxfw.DrawContext,
        width: u16,
        origin_row: u16,
        usable: u16,
        divider_h: u16,
        start_idx: usize,
    ) std.mem.Allocator.Error!usize {
        const list_ratio = std.math.clamp(self.config.packet_list_ratio, 0.25, 0.7);
        var left_w: u16 = @max(@as(u16, @intFromFloat(@as(f32, @floatFromInt(width)) * list_ratio)), 30);
        if (left_w >= width -| 20) left_w = width -| 20;
        const right_w = width -| left_w -| 1;
        const right_col = left_w + 1;

        var idx = start_idx;
        const packets = try self.packet_table.draw(ctx.withConstraints(.{ .height = usable }, .{ .width = left_w, .height = usable }));
        self.children_buf[idx] = .{ .origin = .{ .row = origin_row, .col = 0 }, .surface = packets };
        idx += 1;

        var vdiv = try vxfw.Surface.init(ctx.arena, inertWidget(), .{ .width = 1, .height = usable });
        const vstyle: vaxis.Style = .{ .fg = self.theme.pane_border, .bg = self.theme.bg };
        var r: u16 = 0;
        while (r < usable) : (r += 1) {
            vdiv.writeCell(0, r, .{ .char = .{ .grapheme = "│", .width = 1 }, .style = vstyle });
        }
        self.children_buf[idx] = .{ .origin = .{ .row = origin_row, .col = left_w }, .surface = vdiv };
        idx += 1;

        const tree_ratio = std.math.clamp(self.config.detail_ratio, 0.3, 0.75);
        var tree_h: u16 = @max(@as(u16, @intFromFloat(@as(f32, @floatFromInt(usable -| divider_h)) * tree_ratio)), 3);
        if (tree_h >= usable -| divider_h) tree_h = usable -| divider_h -| 1;
        const hex_h = usable -| tree_h -| divider_h;

        idx = try self.drawTreePaneAt(ctx, right_col, right_w, origin_row, tree_h, idx);
        const div = try drawDivider(ctx, right_w, self.theme);
        self.children_buf[idx] = .{ .origin = .{ .row = origin_row + tree_h, .col = right_col }, .surface = div };
        idx += 1;
        if (hex_h > 0) {
            const hex = try self.hex.draw(ctx.withConstraints(.{ .height = hex_h }, .{ .width = right_w, .height = hex_h }));
            self.children_buf[idx] = .{ .origin = .{ .row = origin_row + tree_h + divider_h, .col = right_col }, .surface = hex };
            idx += 1;
        }
        return idx;
    }

    fn drawTreePane(
        self: *AppModel,
        ctx: vxfw.DrawContext,
        width: u16,
        row: u16,
        tree_h: u16,
        start_idx: usize,
    ) std.mem.Allocator.Error!usize {
        return self.drawTreePaneAt(ctx, 0, width, row, tree_h, start_idx);
    }

    fn drawTreePaneAt(
        self: *AppModel,
        ctx: vxfw.DrawContext,
        col: u16,
        width: u16,
        row: u16,
        tree_h: u16,
        start_idx: usize,
    ) std.mem.Allocator.Error!usize {
        if (tree_h == 0) return start_idx;
        var idx = start_idx;
        const tree = try self.protocol_tree.draw(ctx.withConstraints(.{ .height = tree_h }, .{ .width = width, .height = tree_h }));
        self.children_buf[idx] = .{ .origin = .{ .row = row, .col = col }, .surface = tree };
        idx += 1;
        return idx;
    }
};

var inert_userdata: u8 = 0;

fn inertDraw(_: *anyopaque, ctx: vxfw.DrawContext) std.mem.Allocator.Error!vxfw.Surface {
    return vxfw.Surface.init(ctx.arena, inertWidget(), ctx.max.size());
}

fn inertWidget() vxfw.Widget {
    return .{
        .userdata = &inert_userdata,
        .drawFn = inertDraw,
    };
}

fn drawDivider(ctx: vxfw.DrawContext, width: u16, theme: theme_mod.Theme) std.mem.Allocator.Error!vxfw.Surface {
    var surf = try vxfw.Surface.init(ctx.arena, inertWidget(), .{ .width = width, .height = 1 });
    const style: vaxis.Style = .{ .fg = theme.pane_border, .bg = theme.bg };
    var col: u16 = 0;
    while (col < width) : (col += 1) {
        surf.writeCell(col, 0, .{
            .char = .{ .grapheme = "─", .width = 1 },
            .style = style,
        });
    }
    return surf;
}
