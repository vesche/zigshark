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
const convs_view = @import("views/convs.zig");
const convs_shark = @import("../shark/convs.zig");
const streams_shark = @import("../shark/streams.zig");
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
const field_filter = @import("field_filter.zig");
const expert_mod = @import("expert.zig");
const related_mod = @import("related.zig");
const time_ref = @import("time_ref.zig");
const columns_mod = @import("../shark/columns.zig");
const stats_mod = @import("../shark/stats.zig");
const profiles_feature = @import("../features/profiles.zig");
const runtime_mod = @import("runtime.zig");
const commands = @import("commands.zig");

pub const Focus = enum { filter, packets, protocol, hex };

const FilterVerdictBox = struct {
    text: []u8,
    ok: bool,
    detail: []u8,
};

pub const OverlayKind = enum {
    none,
    help,
    quit,
    message,
    streams,
    convs,
    capinfo,
    menu,
    field_filter,
    conv_filter,
    saved_filters,
    recent_filters,
    expert,
    hierarchy,
    endpoints,
    iograph,
    dns,
    http,
    compare,
    decode_selector,
    decode_protocol,
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
    /// While true, new packets move the selection to the end.
    follow_tail: bool = false,
    /// The live packet list is one long-running tshark, not a fresh read per tick.
    live_list_started: bool = false,
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
    filter_recall: ?usize = null,
    /// List generation whose `.done` event has been applied. A matching filter does not reload again.
    list_settled_generation: u64 = 0,
    previous_filter: []u8 = &.{},
    has_previous_filter: bool = false,
    unfiltered_total: ?usize = null,
    filter_seen: []u8 = &.{},
    filter_checked: []u8 = &.{},
    filter_seen_ticks: u8 = 0,
    filter_check_inflight: std.atomic.Value(bool) = .init(false),
    filter_check_worker: ?std.Thread = null,
    filter_check_mutex: std.Io.Mutex = .init,
    filter_check_box: ?FilterVerdictBox = null,
    filter_error_text: []u8 = &.{},
    macro_preview: []u8 = &.{},
    expert_items: []expert_mod.Item = &.{},
    time_reference_frame: ?u32 = null,
    time_reference_seconds: ?f64 = null,
    hierarchy_names: [][]u8 = &.{},
    endpoint_filters: [][]u8 = &.{},
    stat_filters: [][]u8 = &.{},
    decode_choices: [][]u8 = &.{},
    decode_selector: []u8 = &.{},
    export_request: []u8 = &.{},
    export_confirm: bool = false,
    dropdown: overlay_mod.Dropdown = .{},
    header_menu: ?header_bar.HeaderBar.Menu = null,
    dropdown_col: u16 = 0,
    dropdown_width: u16 = 0,
    dropdown_height: u16 = 0,
    dialog_row: u16 = 0,
    dialog_col: u16 = 0,
    dialog_w: u16 = 0,
    dialog_h: u16 = 0,
    palette_row: u16 = 0,
    palette_col: u16 = 0,
    palette_w: u16 = 0,
    palette_h: u16 = 0,
    goto_prompt: bool = false,
    goto_buf: [24]u8 = undefined,
    goto_len: usize = 0,
    goto_line: [48]u8 = undefined,
    goto_line_len: usize = 0,
    /// Tests run the display-filter check on the caller thread.
    filter_check_sync: bool = false,
    history_note: [256]u8 = @splat(0),
    history_note_len: usize = 0,
    menu_analysis: bool = false,
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
        self.follow_tail = false;
        self.live_list_started = false;
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
        self.filter_recall = null;
        self.list_settled_generation = 0;
        self.previous_filter = &.{};
        self.has_previous_filter = false;
        self.unfiltered_total = null;
        self.filter_seen = &.{};
        self.filter_checked = &.{};
        self.filter_seen_ticks = 0;
        self.filter_check_inflight = .init(false);
        self.filter_check_worker = null;
        self.filter_check_mutex = .init;
        self.filter_check_box = null;
        self.filter_error_text = &.{};
        self.macro_preview = &.{};
        self.expert_items = &.{};
        self.time_reference_frame = null;
        self.time_reference_seconds = null;
        self.hierarchy_names = &.{};
        self.endpoint_filters = &.{};
        self.stat_filters = &.{};
        self.decode_choices = &.{};
        self.decode_selector = &.{};
        self.export_request = &.{};
        self.export_confirm = false;
        self.header_menu = null;
        self.goto_prompt = false;
        self.goto_len = 0;
        self.filter_check_sync = false;
        self.history_note = @splat(0);
        self.history_note_len = 0;
        self.menu_analysis = false;
        self.transfer_job = null;
        self.process_runner = null;

        self.packet_table = .{
            .theme = self.theme,
            .packet_colors = self.config.packet_colors,
            .userdata = self,
            .onSelect = onPacketSelect,
            .onSort = onPacketSort,
            .onFocus = onPacketFocus,
            .onUserScroll = onPacketScroll,
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
        self.filter.onClear = onFilterClear;
        self.filter.onRecent = onRecentFilters;
        self.filter.onHistory = onFilterHistory;
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
        self.help_overlay.userdata = self;
        self.help_overlay.on_activate = onHelpActivate;
        self.help_overlay.on_dismiss = onHelpDismiss;
        self.dropdown = .{
            .theme = self.theme,
            .userdata = self,
            .on_activate = onHeaderItem,
        };
        self.header_menu = null;
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
        if (self.filter_check_worker) |worker| worker.join();
        if (self.filter_check_box) |*box| {
            self.allocator.free(box.text);
            self.allocator.free(box.detail);
        }
        if (self.previous_filter.len != 0) self.allocator.free(self.previous_filter);
        if (self.filter_seen.len != 0) self.allocator.free(self.filter_seen);
        if (self.filter_checked.len != 0) self.allocator.free(self.filter_checked);
        if (self.filter_error_text.len != 0) self.allocator.free(self.filter_error_text);
        if (self.macro_preview.len != 0) self.allocator.free(self.macro_preview);
        self.clearExpert();
        self.freeStringList(&self.hierarchy_names);
        self.freeStringList(&self.endpoint_filters);
        self.freeStringList(&self.stat_filters);
        self.freeStringList(&self.decode_choices);
        if (self.decode_selector.len != 0) self.allocator.free(self.decode_selector);
        if (self.export_request.len != 0) self.allocator.free(self.export_request);
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

    pub fn syncFromSession(self: *AppModel) void {
        self.packet_table.rows = self.session.packets;
        self.packet_table.headers = self.session.list_headers;
        if (self.session.selected_index) |idx| {
            self.packet_table.selected = idx;
        }
        self.status.packet_count = self.session.packets.len;
        self.status.selected_index = self.session.selected_index;
        self.status.selected_frame = self.session.selectedFrame();
        self.status.loading = self.session.loading;
        self.status.filter = self.session.display_filter;
        self.status.packet_total = self.unfiltered_total;
        self.status.names = self.session.name_resolution.len != 0;
        self.status.tailing = self.tailing;
        self.status.live = self.live_capture;
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
        if (self.live_capture) {
            const count = self.session.packets.len;
            self.follow_tail = self.config.auto_scroll and count != 0 and idx + 1 == count;
        }
        self.syncFromSession();
        self.loadDetailForSelection() catch {};
    }

    fn onPacketScroll(userdata: ?*anyopaque) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        if (self.live_capture) self.follow_tail = false;
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
                        try self.config.setGlobalMark(label, path, frame, null);
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

    pub fn gotoFrame(self: *AppModel, args: []const u8) !void {
        const text = std.mem.trim(u8, args, " \t");
        const frame = std.fmt.parseInt(u32, text, 10) catch {
            try self.showMessage("Usage: :goto <frame>");
            return;
        };
        if (self.selectFrame(frame)) {
            self.syncFromSession();
            try self.loadDetailForSelection();
            return;
        }
        const message = try std.fmt.allocPrint(self.allocator, "Frame {d} is not in the list", .{frame});
        defer self.allocator.free(message);
        try self.showMessage(message);
    }

    pub fn restorePreviousFilter(self: *AppModel) !void {
        if (!self.has_previous_filter) {
            try self.showMessage("No previous filter");
            return;
        }
        const back = try self.allocator.dupe(u8, self.previous_filter);
        defer self.allocator.free(back);
        try self.reloadDisplayFilter(back);
    }

    pub fn jumpRelated(self: *AppModel, kind: related_mod.Kind, forward: bool) !void {
        const index = self.session.selected_index orelse {
            try self.showMessage("Select a packet first");
            return;
        };
        const found = related_mod.find(self.session.packets, self.session.list_headers, index, kind, forward) orelse {
            try self.showMessage("No related packet");
            return;
        };
        _ = self.session.select(found);
        self.packet_table.selected = found;
        self.syncFromSession();
        try self.loadDetailForSelection();
    }

    pub fn runRelatedCommand(self: *AppModel, args: []const u8) !void {
        var kind: related_mod.Kind = .conversation;
        var forward = true;
        var tokens = std.mem.tokenizeAny(u8, args, " \t");
        while (tokens.next()) |token| {
            if (std.mem.eql(u8, token, "conv") or std.mem.eql(u8, token, "conversation")) {
                kind = .conversation;
            } else if (std.mem.eql(u8, token, "addr") or std.mem.eql(u8, token, "address")) {
                kind = .address;
            } else if (std.mem.eql(u8, token, "pair") or std.mem.eql(u8, token, "exchange")) {
                kind = .exchange;
            } else if (std.mem.eql(u8, token, "next")) {
                forward = true;
            } else if (std.mem.eql(u8, token, "prev") or std.mem.eql(u8, token, "previous")) {
                forward = false;
            } else {
                try self.showMessage("Usage: :related [conv|addr|pair] [next|prev]");
                return;
            }
        }
        try self.jumpRelated(kind, forward);
    }

    pub fn runMarkCommand(self: *AppModel, args: []const u8) !void {
        const trimmed = std.mem.trim(u8, args, " \t");
        if (trimmed.len == 0 or !std.ascii.isAlphabetic(trimmed[0])) {
            try self.showMessage("Usage: :mark <a-z or A-Z> [note]");
            return;
        }
        if (self.session.selectedFrame() == null) {
            try self.showMessage("Select a packet before marking it");
            return;
        }
        const label = trimmed[0];
        const note = std.mem.trim(u8, trimmed[1..], " \t");
        const global = std.ascii.isUpper(label);
        try self.applyMark(label, global, false);
        if (global) {
            if (self.capturePath()) |path| {
                if (self.session.selectedFrame()) |frame| {
                    try self.config.setGlobalMark(label, path, frame, note);
                    self.persistConfig();
                }
            }
        } else {
            try self.session.marks.setNote(label, note);
        }
        try self.showMarks();
    }

    pub fn commitFilter(self: *AppModel, text: []const u8, apply: bool) !void {
        self.filter_recall = null;
        if (!apply) {
            try self.armFilterText(text);
            self.focus = .filter;
            self.status.mode = "prepared";
            return;
        }
        try self.reloadDisplayFilter(text);
    }

    pub fn recallRecent(self: *AppModel, older: bool) !void {
        const items = self.config.recent_filters.items;
        if (items.len == 0) {
            self.status.mode = "no recent filters";
            return;
        }
        const current = try self.filter.copyText(self.allocator);
        defer self.allocator.free(current);
        const starting = current.len == 0 or self.filter_recall == null or
            self.filter_recall.? >= items.len or
            !std.mem.eql(u8, current, items[self.filter_recall.?]);
        const index = if (starting) blk: {
            break :blk if (older) @as(usize, 0) else items.len - 1;
        } else if (older) blk: {
            const current_index = self.filter_recall.?;
            break :blk if (current_index + 1 < items.len) current_index + 1 else 0;
        } else blk: {
            const current_index = self.filter_recall.?;
            break :blk if (current_index == 0) items.len - 1 else current_index - 1;
        };
        self.filter_recall = index;
        try self.reloadDisplayFilter(items[index]);
        self.filter_recall = index;
        self.writeHistoryNote(index, starting and current.len == 0);
    }

    fn writeHistoryNote(self: *AppModel, index: usize, show_list: bool) void {
        const items = self.config.recent_filters.items;
        const head = std.fmt.bufPrint(self.history_note[0..], "recent {d}/{d}", .{
            index + 1,
            items.len,
        }) catch {
            self.history_note_len = 0;
            self.status.mode = "";
            return;
        };
        var end = head.len;
        if (show_list) {
            for (items, 0..) |item, item_index| {
                const prefix: []const u8 = if (item_index == 0) "  " else " · ";
                const piece = std.fmt.bufPrint(self.history_note[end..], "{s}{s}", .{ prefix, item }) catch break;
                end += piece.len;
            }
        }
        self.history_note_len = end;
        self.status.mode = self.history_note[0..end];
    }

    fn openHeaderMenu(self: *AppModel, menu: header_bar.HeaderBar.Menu) void {
        if (self.header_menu == menu) {
            self.closeHeaderMenu();
            return;
        }
        self.header_menu = menu;
        self.header.open_menu = menu;
        self.menu_analysis = menu == .analysis;
        self.dropdown.body = switch (menu) {
            .analysis => header_bar.analysis_menu,
            .misc => header_bar.misc_menu,
            .help => header_bar.help_menu,
        };
        self.dropdown.selected = 0;
        self.dropdown.line_count = overlay_mod.Dropdown.measure(self.dropdown.body).lines;
        self.dropdown.theme = self.theme;
    }

    fn closeHeaderMenu(self: *AppModel) void {
        self.header_menu = null;
        self.header.open_menu = null;
        self.dropdown.body = "";
        self.dropdown.line_count = 0;
    }

    fn activateHeaderItem(self: *AppModel, index: usize) void {
        const menu = self.header_menu orelse return;
        self.closeHeaderMenu();
        switch (menu) {
            .analysis, .misc => self.runMenuChoice(index) catch {},
            .help => self.openHelp() catch {},
        }
    }

    fn openHelp(self: *AppModel) !void {
        self.goto_prompt = false;
        self.overlay = .help;
        self.help_overlay.title = "Help";
        self.help_overlay.body = help_view.text;
        self.help_overlay.pick = false;
        self.help_overlay.scroll_top = 0;
        self.help_overlay.selected = 0;
        self.help_overlay.visible = true;
    }

    fn openGoto(self: *AppModel) void {
        self.goto_prompt = true;
        self.goto_len = 0;
        self.refreshGotoLine();
        self.overlay = .message;
        self.help_overlay.title = "Go to frame";
        self.help_overlay.body = self.goto_line[0..self.goto_line_len];
        self.help_overlay.pick = false;
        self.help_overlay.scroll_top = 0;
        self.help_overlay.visible = true;
        self.msg_overlay.visible = false;
    }

    fn refreshGotoLine(self: *AppModel) void {
        const typed = self.goto_buf[0..self.goto_len];
        const line = std.fmt.bufPrint(&self.goto_line, "Frame number: {s}_", .{typed}) catch {
            self.help_overlay.body = "Frame number: _";
            return;
        };
        self.goto_line_len = line.len;
        self.help_overlay.body = self.goto_line[0..self.goto_line_len];
    }

    fn handleGotoKey(self: *AppModel, ctx: *vxfw.EventContext, key: vaxis.Key) !void {
        if (key.matches(vaxis.Key.escape, .{}) or key.matches('q', .{})) {
            self.goto_prompt = false;
            self.dismissOverlays();
            return ctx.consumeAndRedraw();
        }
        if (key.matches(vaxis.Key.enter, .{})) {
            var text: [24]u8 = undefined;
            const len = @min(self.goto_len, text.len);
            @memcpy(text[0..len], self.goto_buf[0..len]);
            self.goto_prompt = false;
            self.dismissOverlays();
            try self.gotoFrame(text[0..len]);
            return ctx.consumeAndRedraw();
        }
        if (key.matches(vaxis.Key.backspace, .{})) {
            self.goto_len -|= 1;
            self.refreshGotoLine();
            return ctx.consumeAndRedraw();
        }
        if (key.codepoint >= '0' and key.codepoint <= '9' and self.goto_len < self.goto_buf.len) {
            self.goto_buf[self.goto_len] = @intCast(key.codepoint);
            self.goto_len += 1;
            self.refreshGotoLine();
            return ctx.consumeAndRedraw();
        }
        return ctx.consumeAndRedraw();
    }

    fn onHeaderItem(userdata: ?*anyopaque, index: usize) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        self.activateHeaderItem(index);
    }

    fn onHelpActivate(userdata: ?*anyopaque) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        self.activatePick() catch {};
    }

    fn onHelpDismiss(userdata: ?*anyopaque) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        self.dismissOverlays();
    }

    fn openFieldFilter(self: *AppModel) !void {
        if (self.protocol_tree.selectedField() == null) {
            try self.showMessage("Select a protocol field first");
            return;
        }
        try self.showPick("Field filter",
            \\Apply ==
            \\Apply !=
            \\Apply and
            \\Apply or
            \\Apply not
            \\Apply contains
            \\Prepare ==
            \\Prepare !=
            \\Prepare and
            \\Prepare or
            \\Prepare not
            \\Prepare contains
        , .field_filter);
    }

    fn openConversationFilter(self: *AppModel) !void {
        const probe = self.conversationExpression() catch {
            try self.showMessage("The selected row has no address pair");
            return;
        };
        self.allocator.free(probe);
        try self.showPick("Conversation filter",
            \\Apply
            \\Prepare
        , .conv_filter);
    }

    fn conversationExpression(self: *AppModel) ![]u8 {
        const index = self.session.selected_index orelse return error.NoAddress;
        if (index >= self.session.packets.len) return error.NoAddress;
        const row = self.session.packets[index];
        return field_filter.conversation(
            self.allocator,
            self.listColumn(row, .proto),
            self.listColumn(row, .source),
            self.listColumn(row, .dest),
        );
    }

    fn containsIgnore(haystack: []const u8, needle: []const u8) bool {
        if (needle.len == 0 or needle.len > haystack.len) return false;
        var index: usize = 0;
        while (index + needle.len <= haystack.len) : (index += 1) {
            if (std.ascii.eqlIgnoreCase(haystack[index..][0..needle.len], needle)) return true;
        }
        return false;
    }

    fn listColumn(self: *AppModel, row: packet.PacketSummary, which: enum { source, dest, proto }) []const u8 {
        const headers = self.session.list_headers;
        if (headers.len != 0) {
            for (headers, 0..) |header, column| {
                if (column >= row.columns.len) break;
                const match = switch (which) {
                    .source => containsIgnore(header, "source") or containsIgnore(header, "src"),
                    .dest => containsIgnore(header, "dest") or containsIgnore(header, "dst"),
                    .proto => containsIgnore(header, "proto"),
                };
                if (match) return row.columns[column];
            }
        }
        const has_delta = row.columns.len >= 8;
        const column: usize = switch (which) {
            .source => if (has_delta) 3 else 2,
            .dest => if (has_delta) 4 else 3,
            .proto => if (has_delta) 5 else 4,
        };
        return if (column < row.columns.len) row.columns[column] else "";
    }

    pub fn chooseFieldFilter(self: *AppModel, index: usize) !void {
        const field = self.protocol_tree.selectedField() orelse {
            try self.showMessage("Select a protocol field first");
            return;
        };
        const ops = [_]field_filter.Op{ .eq, .ne, .both, .either, .not_eq, .contains };
        if (index >= ops.len * 2) return;
        const text = try field_filter.expression(
            self.allocator,
            self.session.display_filter,
            field.name,
            field.show,
            ops[index % ops.len],
        );
        defer self.allocator.free(text);
        self.dismissOverlays();
        try self.commitFilter(text, index < ops.len);
    }

    pub fn runFiltersCommand(self: *AppModel, args: []const u8) !void {
        const trimmed = std.mem.trim(u8, args, " \t");
        if (trimmed.len == 0) {
            try self.showSavedFilters();
            return;
        }
        if (std.mem.startsWith(u8, trimmed, "save ")) {
            const name = std.mem.trim(u8, trimmed["save ".len..], " \t");
            if (name.len == 0) {
                try self.showMessage("Usage: :filters save <name>");
                return;
            }
            const typed = try self.filter.copyText(self.allocator);
            defer self.allocator.free(typed);
            const value = if (typed.len != 0) typed else self.session.display_filter;
            if (value.len == 0) {
                try self.showMessage("There is no filter to save");
                return;
            }
            try self.config.upsertNamedFilter(name, value);
            self.persistConfig();
            try self.showMessage("Filter saved");
            return;
        }
        if (std.mem.startsWith(u8, trimmed, "delete ")) {
            const name = std.mem.trim(u8, trimmed["delete ".len..], " \t");
            if (!self.config.deleteNamedFilter(name)) {
                try self.showMessage("No saved filter with that name");
                return;
            }
            self.persistConfig();
            try self.showMessage("Filter deleted");
            return;
        }
        const value = self.config.findNamedFilter(trimmed) orelse {
            try self.showMessage("No saved filter with that name");
            return;
        };
        const owned = try self.allocator.dupe(u8, value);
        defer self.allocator.free(owned);
        try self.commitFilter(owned, true);
    }

    fn showSavedFilters(self: *AppModel) !void {
        if (self.config.named_filters.items.len == 0) {
            try self.showMessage("No saved filters. :filters save <name> stores the current one.");
            return;
        }
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        for (self.config.named_filters.items, 0..) |filter, index| {
            if (index != 0) try text.writer.writeByte('\n');
            try text.writer.print("{s}  {s}", .{ filter.name, filter.value });
        }
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick("Saved filters  Enter applies", owned, .saved_filters);
    }

    fn runProcess(self: *AppModel, argv: []const []const u8) !process_mod.RunOutput {
        if (self.process_runner) |run| return run(self.allocator, self.io, argv);
        return process_mod.runCapture(self.allocator, self.io, argv);
    }

    fn runProcessLimited(self: *AppModel, argv: []const []const u8, limit: usize) !process_mod.RunOutput {
        if (self.process_runner) |run| {
            var out = try run(self.allocator, self.io, argv);
            if (try process_mod.clipStdout(self.allocator, &out.stdout, limit)) out.truncated = true;
            return out;
        }
        return process_mod.runCaptureLimited(self.allocator, self.io, argv, limit);
    }

    fn onHeaderMenu(userdata: ?*anyopaque, menu: header_bar.HeaderBar.Menu) void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        self.openHeaderMenu(menu);
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

    pub fn onFilterSubmit(userdata: ?*anyopaque, text: []const u8) anyerror!void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        const expanded = try macros_feature.expand(self.allocator, self.config, text);
        defer self.allocator.free(expanded);
        if (expanded.len != 0) {
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
        }
        try self.reloadDisplayFilter(text);
    }

    /// Remember the bar text so a stale validation cannot apply a previous expression.
    fn armFilterText(self: *AppModel, raw: []const u8) !void {
        try self.filter.setText(raw);
        const seen = try self.allocator.dupe(u8, raw);
        errdefer self.allocator.free(seen);
        const checked = try self.allocator.dupe(u8, raw);
        if (self.filter_seen.len != 0) self.allocator.free(self.filter_seen);
        if (self.filter_checked.len != 0) self.allocator.free(self.filter_checked);
        self.filter_seen = seen;
        self.filter_checked = checked;
        self.filter_seen_ticks = 0;
        self.dropFilterVerdict();
        self.updateMacroPreview(raw);
    }

    fn dropFilterVerdict(self: *AppModel) void {
        self.filter_check_mutex.lockUncancelable(self.io);
        defer self.filter_check_mutex.unlock(self.io);
        if (self.filter_check_box) |*box| {
            self.allocator.free(box.text);
            self.allocator.free(box.detail);
            self.filter_check_box = null;
        }
    }

    /// Put `raw` in the bar and reload the packet list for its expansion.
    /// An empty expression clears the display filter. The same expression does
    /// not start another load while that load is running or already on screen.
    fn reloadDisplayFilter(self: *AppModel, raw: []const u8) !void {
        const owned = try self.allocator.dupe(u8, raw);
        defer self.allocator.free(owned);
        try self.armFilterText(owned);
        const expanded = try macros_feature.expand(self.allocator, self.config, owned);
        defer self.allocator.free(expanded);
        self.filter.state = if (expanded.len == 0) .neutral else .ok;
        self.setFilterError("");
        const same = std.mem.eql(u8, expanded, self.session.display_filter);
        const generation = self.loader.list_generation.load(.acquire);
        const settled = generation != 0 and generation == self.list_settled_generation and self.session.loading != .error_state;
        if (same and (self.session.loading == .loading_list or settled)) {
            self.syncFromSession();
            return;
        }
        if (!same) {
            const kept = try self.allocator.dupe(u8, self.session.display_filter);
            if (self.previous_filter.len != 0) self.allocator.free(self.previous_filter);
            self.previous_filter = kept;
            self.has_previous_filter = true;
        }
        try self.session.setFilter(expanded, null);
        self.filter_recall = null;
        if (expanded.len != 0) try recents.pushFilter(self.config, expanded);
        self.clearDetail();
        try self.loader.requestPsml(self.session);
        self.syncFromSession();
    }

    fn onFilterClear(userdata: ?*anyopaque) anyerror!void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        try self.clearDisplayFilter();
    }

    pub fn clearDisplayFilter(self: *AppModel) !void {
        try self.reloadDisplayFilter("");
    }

    fn onRecentFilters(userdata: ?*anyopaque) anyerror!void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        try self.openRecentFilters();
    }

    pub fn openRecentFilters(self: *AppModel) !void {
        const items = self.config.recent_filters.items;
        if (items.len == 0) {
            try self.showMessage("No recent filters yet. Apply one and it will be listed here.");
            return;
        }
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        for (items, 0..) |filter, index| {
            if (index != 0) try text.writer.writeByte('\n');
            try text.writer.writeAll(filter);
        }
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick("Recent filters  Enter applies", owned, .recent_filters);
    }

    fn onFilterHistory(userdata: ?*anyopaque, older: bool) anyerror!void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        try self.recallRecent(older);
    }

    fn onCommand(userdata: ?*anyopaque, cmd: []const u8, args: []const u8) anyerror!void {
        const self: *AppModel = @ptrCast(@alignCast(userdata.?));
        try self.runCommand(cmd, args);
    }

    fn loadDetailForSelection(self: *AppModel) !void {
        if (self.session.loading == .loading_list) return;
        const frame = self.session.selectedFrame() orelse return;
        if (self.detail_frame == frame or self.detail_requested_frame == frame) return;
        self.detail_requested_frame = frame;
        try self.loader.requestDetail(self.session, frame);
    }

    pub fn clearDetail(self: *AppModel) void {
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

        self.loader.startLiveCapture(
            self.io,
            self.session,
            interfaces,
            output_path,
        ) catch |err| {
            const detail = switch (err) {
                error.AccessDenied, error.PermissionDenied => "permission denied. Remove a root-owned file at that path, or choose a directory you can write.",
                else => @errorName(err),
            };
            const message = try std.fmt.allocPrint(self.allocator, "Cannot create {s}: {s}", .{ output_path, detail });
            defer self.allocator.free(message);
            try self.showMessage(message);
            return;
        };
        self.live_capture = true;
        self.follow_tail = self.config.auto_scroll;
        self.live_list_started = false;
        self.syncFromSession();
        try self.refreshLiveCapture();
    }

    fn refreshLiveCapture(self: *AppModel) !void {
        if (!self.live_capture or self.session.capture_path.len == 0 or self.live_list_started) return;
        try self.loader.startLiveList(self.session);
        self.live_list_started = true;
        self.session.loading = .capturing;
        self.syncFromSession();
    }

    pub fn stopCapture(self: *AppModel) !void {
        if (!self.live_capture) {
            try self.showMessage("No capture is running");
            return;
        }
        const saved = try self.allocator.dupe(u8, self.session.capture_path);
        defer self.allocator.free(saved);
        self.loader.stopLiveCapture(self.io);
        self.live_capture = false;
        self.follow_tail = false;
        self.live_list_started = false;
        self.session.loading = .idle;
        self.syncFromSession();
        const message = if (saved.len == 0)
            try self.allocator.dupe(u8, "Capture stopped.")
        else
            try std.fmt.allocPrint(self.allocator, "Capture stopped. Saved {s}", .{saved});
        defer self.allocator.free(message);
        try self.showMessage(message);
        try self.loadDetailForSelection();
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
                    if (table.generation == 0 or table.generation == self.loader.list_generation.load(.acquire)) {
                    const follow_live = self.live_capture and self.follow_tail and self.config.auto_scroll;
                    const previous = if (follow_live) null else self.session.selectedFrame();
                    if (table.headers.len != 0) {
                        self.session.setListHeaders(table.headers);
                        table.headers = &.{};
                    }
                    if (self.hide_through_frame != 0) {
                        table.packets = try packet.retainFramesAfter(
                            self.allocator,
                            table.packets,
                            self.hide_through_frame,
                        );
                    }
                    const appending = table.append and self.session.packets.len != 0;
                    if (appending) {
                        try self.session.appendPackets(table.packets);
                    } else {
                        self.session.setPackets(table.packets);
                    }
                    table.packets = &.{};
                    if (follow_live and self.session.packets.len > 0) {
                        _ = self.session.select(self.session.packets.len - 1);
                        self.packet_table.scroll_free = false;
                    } else if (previous) |frame| {
                        for (self.session.packets, 0..) |summary, index| {
                            if (summary.frame == frame) {
                                _ = self.session.select(index);
                                break;
                            }
                        }
                    }
                    if (self.pending_global_frame) |frame| {
                        _ = self.selectFrame(frame);
                        self.pending_global_frame = null;
                    }
                    self.session.loading = if (self.live_capture) .capturing else .loading_list;
                    self.syncFromSession();
                    ev.* = .done;
                    }
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
                .done => if (self.live_capture) {
                    self.session.loading = .capturing;
                    self.syncFromSession();
                } else if (self.session.loading == .loading_list or self.session.loading == .capturing) {
                    self.list_settled_generation = self.loader.list_generation.load(.acquire);
                    if (self.session.display_filter.len == 0) self.unfiltered_total = self.session.packets.len;
                    self.session.loading = .idle;
                    self.syncFromSession();
                },
            }
            ev.deinit(self.allocator);
        }
        if (!(self.live_capture and self.follow_tail)) try self.loadDetailForSelection();
    }

    pub fn capturePath(self: *const AppModel) ?[]const u8 {
        return switch (self.session.source) {
            .file => |p| p,
            .fifo => |p| p,
            .interfaces => if (self.session.capture_path.len != 0) self.session.capture_path else null,
            .stdin => null,
        };
    }

    pub fn openCapture(self: *AppModel, path: []const u8) !void {
        if (self.live_capture) self.loader.stopLiveCapture(self.io);
        try self.session.setFileSource(path);
        self.hide_through_frame = 0;
        self.unfiltered_total = null;
        self.noteTail(path);
        try self.config.addRecentFile(path);
        self.live_capture = false;
        self.follow_tail = false;
        self.live_list_started = false;
        self.clearDetail();
        self.loader.clearDetailCache(self.io);
        try self.loader.requestPsml(self.session);
        self.syncFromSession();
    }

    pub fn showMessage(self: *AppModel, msg: []const u8) !void {
        if (self.overlay_body_owned.len != 0) self.allocator.free(self.overlay_body_owned);
        self.overlay_body_owned = try self.allocator.dupe(u8, msg);
        self.msg_overlay.body = self.overlay_body_owned;
        self.msg_overlay.visible = true;
        self.msg_overlay.scroll_top = 0;
        self.overlay = .message;
    }

    pub fn showRecents(self: *AppModel) !void {
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

    pub fn showMarks(self: *AppModel) !void {
        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);
        try buffer.appendSlice(self.allocator, "Local marks: m[a-z] set, '[a-z] jump. :mark <label> <note>\n");
        var letter: u8 = 'a';
        while (letter <= 'z') : (letter += 1) {
            const frame = self.session.marks.getLocal(letter) orelse continue;
            const note = self.session.marks.getNote(letter) orelse "";
            const line = try std.fmt.allocPrint(self.allocator, "  {c}: frame {d}  {s}\n", .{ letter, frame, note });
            defer self.allocator.free(line);
            try buffer.appendSlice(self.allocator, line);
        }
        try buffer.appendSlice(self.allocator, "\nGlobal marks:\n");
        for (self.config.global_marks.items) |mark| {
            const line = try std.fmt.allocPrint(self.allocator, "  {c}: frame {d} in {s}  {s}\n", .{
                mark.label,
                mark.frame,
                mark.path,
                mark.note,
            });
            defer self.allocator.free(line);
            try buffer.appendSlice(self.allocator, line);
        }
        try self.showMessage(buffer.items);
    }

    pub fn runCommand(self: *AppModel, cmd: []const u8, args: []const u8) !void {
        return commands.run(self, cmd, args);
    }


    pub fn findNextSearch(self: *AppModel, forward: bool) !bool {
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

    pub fn searchByDisplayFilter(self: *AppModel, filter: []const u8) !void {
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

    pub fn runSetCommand(self: *AppModel, args: []const u8) !void {
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
            self.loader.setCacheSize(self.config.pcap_cache_size);
        } else if (std.mem.eql(u8, name, "search-case-sensitive")) {
            self.search.case_sensitive = self.config.search_case_sensitive;
        } else if (std.mem.eql(u8, name, "tls-keylog-file")) {
            try self.session.setTlsKeylog(self.config.tls_keylog_file);
            self.clearDetail();
            self.loader.clearDetailCache(self.io);
            try self.loader.requestPsml(self.session);
        } else if (std.mem.eql(u8, name, "name-resolution")) {
            try self.session.setNameResolution(self.config.name_resolution);
            self.clearDetail();
            self.loader.clearDetailCache(self.io);
            try self.loader.requestPsml(self.session);
            self.syncFromSession();
        }
        self.persistConfig();
        try self.showMessage("Option updated");
    }

    fn selectedColumnField(self: *AppModel) ?[]const u8 {
        const field = self.protocol_tree.selectedField() orelse return null;
        if (field.name.len == 0 or std.mem.eql(u8, field.name, "__packet_root")) return null;
        return field.name;
    }

    fn clearExpert(self: *AppModel) void {
        for (self.expert_items) |*item| item.deinit(self.allocator);
        if (self.expert_items.len != 0) self.allocator.free(self.expert_items);
        self.expert_items = &.{};
    }

    pub fn showExpert(self: *AppModel) !void {
        const bundle = self.detail_bundle orelse {
            try self.showMessage("Select a packet to see its expert info");
            return;
        };
        self.clearExpert();
        self.expert_items = try expert_mod.collect(self.allocator, &bundle.pdml.root);
        if (self.expert_items.len == 0) {
            try self.showMessage("This packet has no expert info");
            return;
        }
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        for (self.expert_items, 0..) |item, index| {
            if (index != 0) try text.writer.writeByte('\n');
            try text.writer.print("{s}  {s}  {s}", .{ expert_mod.label(item.severity), item.group, item.message });
        }
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick("Expert  Enter opens the field", owned, .expert);
    }

    pub fn toggleTimeReference(self: *AppModel) !void {
        const frame = self.session.selectedFrame() orelse {
            try self.showMessage("Select a packet first");
            return;
        };
        if (self.time_reference_frame) |current| if (current == frame) {
            self.time_reference_frame = null;
            self.time_reference_seconds = null;
            self.packet_table.time_base = null;
            return;
        };
        const index = self.session.selected_index orelse return;
        const cell = time_ref.timeText(self.session.list_headers, self.session.packets[index].columns) orelse {
            try self.showMessage("This list has no time column");
            return;
        };
        const seconds = time_ref.parseSeconds(cell) orelse {
            try self.showMessage("The time column is not a number of seconds");
            return;
        };
        self.time_reference_frame = frame;
        self.time_reference_seconds = seconds;
        self.packet_table.time_base = seconds;
    }

    fn freeStringList(self: *AppModel, list: *[][]u8) void {
        for (list.*) |item| self.allocator.free(item);
        if (list.len != 0) self.allocator.free(list.*);
        list.* = &.{};
    }

    pub fn showIoGraph(self: *AppModel, args: []const u8) !void {
        const requested = if (args.len == 0) "1" else std.mem.trim(u8, args, " \t");
        const seconds = std.fmt.parseFloat(f64, requested) catch {
            try self.showMessage("Usage: :iograph [seconds]");
            return;
        };
        if (!(seconds > 0) or seconds > 3600) {
            try self.showMessage("Interval must be between 0 and 3600 seconds");
            return;
        }
        const interval = try std.fmt.allocPrint(self.allocator, "{d}", .{seconds});
        defer self.allocator.free(interval);
        const path = self.capturePath() orelse {
            try self.showMessage("No capture file loaded");
            return;
        };
        var argv = try process_mod.argvIoStat(self.allocator, self.tools.tshark, path, interval);
        defer argv.deinit(self.allocator);
        var out = try self.runProcessLimited(argv.slice(), process_mod.view_stdout_cap);
        defer out.deinit(self.allocator);
        if (!out.term.success() and out.stdout.len == 0) {
            try self.showMessage(if (out.stderr.len != 0) out.stderr else "IO graph failed");
            return;
        }
        const buckets = try stats_mod.parseIoStat(self.allocator, out.stdout);
        defer self.allocator.free(buckets);
        const shown = @min(buckets.len, process_mod.view_row_cap);
        var max_frames: u64 = 0;
        for (buckets[0..shown]) |bucket| max_frames = @max(max_frames, bucket.frames);
        self.freeStringList(&self.stat_filters);
        const filters = try self.allocator.alloc([]u8, shown);
        var filled: usize = 0;
        errdefer {
            for (filters[0..filled]) |filter| self.allocator.free(filter);
            self.allocator.free(filters);
        }
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        if (shown == 0) try text.writer.writeAll("No IO statistics");
        for (buckets[0..shown], 0..) |bucket, index| {
            filters[index] = try std.fmt.allocPrint(
                self.allocator,
                "frame.time_relative >= {d} and frame.time_relative < {d}",
                .{ bucket.start, bucket.end },
            );
            filled += 1;
            if (index != 0) try text.writer.writeByte('\n');
            var marks: [16]u8 = @splat(' ');
            const count = stats_mod.ioMarks(bucket.frames, max_frames, marks.len);
            for (marks[0..count]) |*cell| cell.* = '#';
            try text.writer.print("{d:.1}-{d:.1}  {s}  {d}  {d} bytes", .{
                bucket.start,
                bucket.end,
                marks,
                bucket.frames,
                bucket.bytes,
            });
        }
        try writeCapNote(&text.writer, out.truncated, shown < buckets.len);
        self.stat_filters = filters;
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick("IO graph  Enter filters that interval", owned, .iograph);
    }

    pub fn showDns(self: *AppModel) !void {
        try self.showFieldTable(
            &.{ "frame.number", "dns.qry.name", "dns.flags.rcode" },
            "",
            stats_mod.parseDnsTable,
            "DNS  Enter filters that name",
            .dns,
        );
    }

    pub fn showHttp(self: *AppModel) !void {
        try self.showFieldTable(
            &.{ "frame.number", "http.request.method", "http.host", "http.request.uri", "http.response.code" },
            "http",
            stats_mod.parseHttpTable,
            "HTTP  Enter filters that row",
            .http,
        );
    }

    fn showFieldTable(
        self: *AppModel,
        fields: []const []const u8,
        display_filter: []const u8,
        parse: *const fn (std.mem.Allocator, []const u8) anyerror![]stats_mod.TableRow,
        title: []const u8,
        kind: OverlayKind,
    ) !void {
        const path = self.capturePath() orelse {
            try self.showMessage("No capture file loaded");
            return;
        };
        var argv = try process_mod.argvFieldDump(self.allocator, self.tools.tshark, path, display_filter, fields);
        defer argv.deinit(self.allocator);
        var out = try self.runProcessLimited(argv.slice(), process_mod.view_stdout_cap);
        defer out.deinit(self.allocator);
        if (!out.term.success() and out.stdout.len == 0) {
            try self.showMessage(if (out.stderr.len != 0) out.stderr else "Field table failed");
            return;
        }
        const rows = try parse(self.allocator, out.stdout);
        defer {
            for (rows) |*row| {
                var copy = row.*;
                copy.deinit(self.allocator);
            }
            self.allocator.free(rows);
        }
        try self.installStatRows(rows, out.truncated, title, kind);
    }

    pub fn showCompare(self: *AppModel, args: []const u8) !void {
        const other = std.mem.trim(u8, args, " \t");
        if (other.len == 0) {
            try self.showMessage("Usage: :compare <file.pcap>");
            return;
        }
        const path = self.capturePath() orelse {
            try self.showMessage("No capture file loaded");
            return;
        };
        const fields = [_][]const u8{ "frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len" };
        var here_argv = try process_mod.argvFieldDump(self.allocator, self.tools.tshark, path, "", &fields);
        defer here_argv.deinit(self.allocator);
        var there_argv = try process_mod.argvFieldDump(self.allocator, self.tools.tshark, other, "", &fields);
        defer there_argv.deinit(self.allocator);
        var here = try self.runProcessLimited(here_argv.slice(), process_mod.view_stdout_cap);
        defer here.deinit(self.allocator);
        var there = try self.runProcessLimited(there_argv.slice(), process_mod.view_stdout_cap);
        defer there.deinit(self.allocator);
        if ((!here.term.success() and here.stdout.len == 0) or (!there.term.success() and there.stdout.len == 0)) {
            const err = if (there.stderr.len != 0) there.stderr else here.stderr;
            try self.showMessage(if (err.len != 0) err else "Compare failed");
            return;
        }
        const rows = try stats_mod.compareIdentities(self.allocator, here.stdout, there.stdout);
        defer {
            for (rows) |*row| {
                var copy = row.*;
                copy.deinit(self.allocator);
            }
            self.allocator.free(rows);
        }
        const shown = @min(rows.len, process_mod.view_row_cap);
        try self.installStatRows(rows[0..shown], here.truncated or there.truncated or shown < rows.len, "Compare  Enter selects a frame from this file", .compare);
    }

    fn installStatRows(self: *AppModel, rows: []const stats_mod.TableRow, truncated: bool, title: []const u8, kind: OverlayKind) !void {
        self.freeStringList(&self.stat_filters);
        const filters = try self.allocator.alloc([]u8, rows.len);
        var filled: usize = 0;
        errdefer {
            for (filters[0..filled]) |filter| self.allocator.free(filter);
            self.allocator.free(filters);
        }
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        if (rows.len == 0) try text.writer.writeAll("Nothing to show");
        for (rows, 0..) |row, index| {
            filters[index] = try self.allocator.dupe(u8, row.filter);
            filled += 1;
            if (index != 0) try text.writer.writeByte('\n');
            try text.writer.writeAll(row.label);
        }
        if (truncated) try writeCapNote(&text.writer, false, true);
        self.stat_filters = filters;
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick(title, owned, kind);
    }

    pub fn runColorCommand(self: *AppModel, args: []const u8) !void {
        const trimmed = std.mem.trim(u8, args, " \t");
        if (trimmed.len == 0) {
            var text: std.Io.Writer.Allocating = .init(self.allocator);
            defer text.deinit();
            if (self.config.color_rules.items.len == 0) try text.writer.writeAll("No coloring rules. :color <name> <filter>|#fg|#bg");
            for (self.config.color_rules.items, 0..) |rule, index| {
                if (index != 0) try text.writer.writeByte('\n');
                try text.writer.print("{s}  {s}", .{ rule.name, rule.filter });
            }
            const owned = try text.toOwnedSlice();
            defer self.allocator.free(owned);
            try self.showMessage(owned);
            return;
        }
        if (std.mem.startsWith(u8, trimmed, "delete ")) {
            const name = std.mem.trim(u8, trimmed["delete ".len..], " \t");
            if (!self.config.deleteColorRule(name)) {
                try self.showMessage("No coloring rule with that name");
                return;
            }
            self.persistConfig();
            try self.showMessage("Coloring rule deleted");
            return;
        }
        const space = std.mem.indexOfScalar(u8, trimmed, ' ') orelse {
            try self.showMessage("Usage: :color <name> <filter>|#fg|#bg");
            return;
        };
        const name = std.mem.trim(u8, trimmed[0..space], " \t");
        const value = std.mem.trim(u8, trimmed[space + 1 ..], " \t");
        if (name.len == 0 or std.mem.indexOfScalar(u8, value, '|') == null) {
            try self.showMessage("Usage: :color <name> <filter>|#fg|#bg");
            return;
        }
        try self.config.upsertColorRule(name, value);
        self.persistConfig();
        try self.showMessage("Coloring rule saved");
    }

    pub fn runCommentCommand(self: *AppModel, args: []const u8) !void {
        const path = self.capturePath() orelse {
            try self.showMessage("No capture file loaded");
            return;
        };
        const frame = self.session.selectedFrame() orelse {
            try self.showMessage("Select a packet first");
            return;
        };
        const note = std.mem.trim(u8, args, " \t");
        if (note.len == 0) {
            const filter = try std.fmt.allocPrint(self.allocator, "frame.number == {d}", .{frame});
            defer self.allocator.free(filter);
            var argv = try process_mod.argvFieldDump(self.allocator, self.tools.tshark, path, filter, &.{ "frame.comment" });
            defer argv.deinit(self.allocator);
            var out = try self.runProcess(argv.slice());
            defer out.deinit(self.allocator);
            const text = std.mem.trim(u8, out.stdout, " \t\r\n");
            if (!out.term.success() and text.len == 0) {
                try self.showMessage(if (out.stderr.len != 0) out.stderr else "Could not read the packet comment");
                return;
            }
            try self.showMessage(if (text.len == 0) "(no comment)" else text);
            return;
        }
        if (std.mem.indexOfAny(u8, note, "\r\n") != null) {
            try self.showMessage("A packet comment is one line");
            return;
        }
        const dest = try std.fmt.allocPrint(self.allocator, "{s}.commented.pcapng", .{path});
        defer self.allocator.free(dest);
        var argv = try process_mod.argvEditcapComment(self.allocator, "editcap", path, dest, frame, note);
        defer argv.deinit(self.allocator);
        var out = try self.runProcess(argv.slice());
        defer out.deinit(self.allocator);
        if (!out.term.success()) {
            try self.showMessage(if (out.stderr.len != 0) out.stderr else "editcap could not write the comment. The mark note is still available.");
            return;
        }
        try self.openCapture(dest);
        const message = try std.fmt.allocPrint(self.allocator, "Wrote the comment and opened {s}", .{dest});
        defer self.allocator.free(message);
        try self.showMessage(message);
    }

    pub fn runLuaCommand(self: *AppModel, args: []const u8) !void {
        const script = std.mem.trim(u8, args, " \t");
        if (script.len == 0) {
            try self.showMessage("Usage: :lua <script.lua>");
            return;
        }
        const path = self.capturePath() orelse {
            try self.showMessage("No capture file loaded");
            return;
        };
        var argv = try process_mod.argvLua(self.allocator, self.tools.tshark, path, script);
        defer argv.deinit(self.allocator);
        var out = try self.runProcessLimited(argv.slice(), process_mod.view_stdout_cap);
        defer out.deinit(self.allocator);
        const body = if (out.stdout.len != 0) out.stdout else out.stderr;
        if (body.len == 0) {
            try self.showMessage(if (out.term.success()) "Lua script produced no output" else "Lua script failed");
            return;
        }
        const shown = try capText(self.allocator, body, out.truncated, false);
        defer self.allocator.free(shown);
        try self.showMessage(shown);
    }

    pub fn showHierarchy(self: *AppModel) !void {
        const path = self.capturePath() orelse {
            try self.showMessage("No capture file loaded");
            return;
        };
        var argv = try process_mod.argvHierarchy(self.allocator, self.tools.tshark, path);
        defer argv.deinit(self.allocator);
        var out = try self.runProcessLimited(argv.slice(), process_mod.view_stdout_cap);
        defer out.deinit(self.allocator);
        if (!out.term.success() and out.stdout.len == 0) {
            try self.showMessage(if (out.stderr.len != 0) out.stderr else "Protocol hierarchy failed");
            return;
        }
        const rows = try stats_mod.parseHierarchy(self.allocator, out.stdout);
        defer {
            for (rows) |*row| {
                var copy = row.*;
                copy.deinit(self.allocator);
            }
            self.allocator.free(rows);
        }
        self.freeStringList(&self.hierarchy_names);
        const names = try self.allocator.alloc([]u8, rows.len);
        var filled: usize = 0;
        errdefer {
            for (names[0..filled]) |name| self.allocator.free(name);
            self.allocator.free(names);
        }
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        if (rows.len == 0) try text.writer.writeAll("No protocol hierarchy");
        for (rows, 0..) |row, index| {
            names[index] = try self.allocator.dupe(u8, row.name);
            filled += 1;
            if (index != 0) try text.writer.writeByte('\n');
            try text.writer.print("{s}  {d} frames  {d} bytes", .{ row.name, row.frames, row.bytes });
        }
        self.hierarchy_names = names;
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick("Hierarchy  Enter filters that protocol", owned, .hierarchy);
    }

    pub fn showEndpoints(self: *AppModel, args: []const u8) !void {
        const kind_name = if (args.len == 0) "tcp" else std.mem.trim(u8, args, " \t");
        const kind = std.meta.stringToEnum(stats_mod.Kind, kind_name) orelse {
            try self.showMessage("Usage: :endpoints [tcp|udp|ip|ipv6|eth]");
            return;
        };
        const path = self.capturePath() orelse {
            try self.showMessage("No capture file loaded");
            return;
        };
        var argv = try process_mod.argvEndpoints(self.allocator, self.tools.tshark, path, kind_name);
        defer argv.deinit(self.allocator);
        var out = try self.runProcessLimited(argv.slice(), process_mod.view_stdout_cap);
        defer out.deinit(self.allocator);
        if (!out.term.success() and out.stdout.len == 0) {
            try self.showMessage(if (out.stderr.len != 0) out.stderr else "Endpoints failed");
            return;
        }
        const rows = try stats_mod.parseEndpoints(self.allocator, out.stdout, kind);
        defer {
            for (rows) |*row| {
                var copy = row.*;
                copy.deinit(self.allocator);
            }
            self.allocator.free(rows);
        }
        const shown = @min(rows.len, process_mod.view_row_cap);
        self.freeStringList(&self.endpoint_filters);
        const filters = try self.allocator.alloc([]u8, shown);
        var filled: usize = 0;
        errdefer {
            for (filters[0..filled]) |filter| self.allocator.free(filter);
            self.allocator.free(filters);
        }
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        if (shown == 0) try text.writer.print("No {s} endpoints", .{kind_name});
        for (rows[0..shown], 0..) |row, index| {
            filters[index] = try stats_mod.endpointFilter(self.allocator, kind, row);
            filled += 1;
            if (index != 0) try text.writer.writeByte('\n');
            try text.writer.print("{s}", .{row.address});
            if (row.port) |port| try text.writer.print(":{d}", .{port});
            try text.writer.print("  {d} packets  {d} bytes", .{ row.packets, row.bytes });
        }
        self.endpoint_filters = filters;
        try writeCapNote(&text.writer, out.truncated, shown < rows.len);
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick("Endpoints  Enter filters that address", owned, .endpoints);
    }

    fn appendDisplayFilter(self: *AppModel, atom: []const u8) !void {
        if (self.session.display_filter.len == 0) {
            try self.commitFilter(atom, true);
            return;
        }
        const next = try std.fmt.allocPrint(self.allocator, "({s}) and {s}", .{ self.session.display_filter, atom });
        defer self.allocator.free(next);
        try self.commitFilter(next, true);
    }

    pub fn showDecodeSelectors(self: *AppModel) !void {
        const bundle = self.detail_bundle orelse {
            try self.showMessage("Select a packet before decode-as");
            return;
        };
        self.freeStringList(&self.decode_choices);
        var choices: std.ArrayList([]u8) = .empty;
        errdefer {
            for (choices.items) |item| self.allocator.free(item);
            choices.deinit(self.allocator);
        }
        try collectDecodeSelectors(self.allocator, &bundle.pdml.root, &choices);
        if (choices.items.len == 0) {
            try self.showMessage("This packet has no tcp port, udp port, or ethertype. :decode-as layer==selector,protocol still works.");
            return;
        }
        self.decode_choices = try choices.toOwnedSlice(self.allocator);
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        for (self.decode_choices, 0..) |choice, index| {
            if (index != 0) try text.writer.writeByte('\n');
            try text.writer.writeAll(choice);
        }
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick("Decode as  choose a selector", owned, .decode_selector);
    }

    fn showDecodeProtocols(self: *AppModel) !void {
        var argv = try process_mod.argvProtocolList(self.allocator, self.tools.tshark);
        defer argv.deinit(self.allocator);
        var out = try self.runProcess(argv.slice());
        defer out.deinit(self.allocator);
        const names = try stats_mod.listedProtocols(self.allocator, out.stdout, &decode_protocol_names);
        if (names.len == 0) {
            try self.showMessage("tshark did not list a usable protocol");
            return;
        }
        self.freeStringList(&self.decode_choices);
        self.decode_choices = names;
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        for (names, 0..) |name, index| {
            if (index != 0) try text.writer.writeByte('\n');
            try text.writer.writeAll(name);
        }
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick("Decode as  choose a protocol", owned, .decode_protocol);
    }

    pub fn acceptExport(self: *AppModel) !void {
        const args = self.export_request;
        self.export_request = &.{};
        self.export_confirm = false;
        self.dismissOverlays();
        defer self.allocator.free(args);
        try self.runExport(args, true);
    }

    fn clearExportConfirm(self: *AppModel) void {
        self.export_confirm = false;
        if (self.export_request.len != 0) self.allocator.free(self.export_request);
        self.export_request = &.{};
    }

    pub fn runExport(self: *AppModel, args: []const u8, force: bool) !void {
        const trimmed = std.mem.trim(u8, args, " \t");
        if (trimmed.len == 0) {
            try self.showMessage("Usage: :export packets|packet|json|csv <path>    or    :export objects http|smb <dir>");
            return;
        }
        var parts = std.mem.tokenizeAny(u8, trimmed, " \t");
        const command = parts.next() orelse return;
        if (std.mem.eql(u8, command, "objects")) {
            const protocol = parts.next() orelse {
                try self.showMessage("Usage: :export objects http|smb <dir>");
                return;
            };
            const directory = parts.next() orelse {
                try self.showMessage("Usage: :export objects http|smb <dir>");
                return;
            };
            if (!std.mem.eql(u8, protocol, "http") and !std.mem.eql(u8, protocol, "smb")) {
                try self.showMessage("Object export supports http or smb");
                return;
            }
            try self.exportObjects(protocol, directory);
            return;
        }
        const out_path = parts.next() orelse {
            try self.showMessage("Usage: :export packets|packet|json|csv <path>");
            return;
        };
        if (!force and try self.pathExists(out_path)) {
            try self.askOverwrite(trimmed);
            return;
        }
        if (std.mem.eql(u8, command, "json")) {
            try self.writeDisplayed(out_path, true);
        } else if (std.mem.eql(u8, command, "csv")) {
            try self.writeDisplayed(out_path, false);
        } else if (std.mem.eql(u8, command, "packets")) {
            try self.exportPcap(out_path, null);
        } else if (std.mem.eql(u8, command, "packet")) {
            const frame = self.session.selectedFrame() orelse {
                try self.showMessage("Select a packet first");
                return;
            };
            try self.exportPcap(out_path, frame);
        } else {
            try self.showMessage("Usage: :export packets|packet|json|csv <path>    or    :export objects http|smb <dir>");
        }
    }

    fn askOverwrite(self: *AppModel, args: []const u8) !void {
        if (self.export_request.len != 0) self.allocator.free(self.export_request);
        self.export_request = try self.allocator.dupe(u8, args);
        self.export_confirm = true;
        const message = try std.fmt.allocPrint(self.allocator, "That file already exists.\nPress y to overwrite it, n to cancel.", .{});
        defer self.allocator.free(message);
        if (self.overlay_body_owned.len != 0) self.allocator.free(self.overlay_body_owned);
        self.overlay_body_owned = try self.allocator.dupe(u8, message);
        self.help_overlay.title = "Overwrite?";
        self.help_overlay.body = self.overlay_body_owned;
        self.help_overlay.visible = true;
        self.help_overlay.pick = false;
        self.msg_overlay.visible = false;
        self.overlay = .message;
    }

    fn pathExists(self: *AppModel, path: []const u8) !bool {
        const cwd = std.Io.Dir.cwd();
        if (cwd.access(self.io, path, .{})) |_| return true else |_| return false;
    }

    fn exportPcap(self: *AppModel, out_path: []const u8, frame: ?u32) !void {
        const path = self.capturePath() orelse {
            try self.showMessage("No capture file loaded");
            return;
        };
        var argv = try process_mod.argvExportPcap(
            self.allocator,
            self.tools.tshark,
            path,
            self.session.display_filter,
            out_path,
            frame,
        );
        defer argv.deinit(self.allocator);
        var out = try self.runProcess(argv.slice());
        defer out.deinit(self.allocator);
        if (!out.term.success()) {
            try self.showMessage(if (out.stderr.len != 0) out.stderr else "Export failed");
            return;
        }
        const message = try std.fmt.allocPrint(self.allocator, "Wrote {s}", .{out_path});
        defer self.allocator.free(message);
        try self.showMessage(message);
    }

    fn exportObjects(self: *AppModel, protocol: []const u8, directory: []const u8) !void {
        const path = self.capturePath() orelse {
            try self.showMessage("No capture file loaded");
            return;
        };
        std.Io.Dir.cwd().createDirPath(self.io, directory) catch {
            try self.showMessage("Could not create that directory");
            return;
        };
        var argv = try process_mod.argvExportObjects(
            self.allocator,
            self.tools.tshark,
            path,
            self.session.display_filter,
            protocol,
            directory,
        );
        defer argv.deinit(self.allocator);
        var out = try self.runProcess(argv.slice());
        defer out.deinit(self.allocator);
        if (!out.term.success()) {
            try self.showMessage(if (out.stderr.len != 0) out.stderr else "Export failed");
            return;
        }
        const message = try std.fmt.allocPrint(self.allocator, "Exported {s} objects to {s}", .{ protocol, directory });
        defer self.allocator.free(message);
        try self.showMessage(message);
    }

    fn writeDisplayed(self: *AppModel, path: []const u8, json: bool) !void {
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer text.deinit();
        const headers = self.session.list_headers;
        const packets = self.session.packets;
        if (json) {
            try text.writer.writeByte('[');
            for (packets, 0..) |row, row_index| {
                if (row_index != 0) try text.writer.writeByte(',');
                try text.writer.writeByte('{');
                for (row.columns, 0..) |column, column_index| {
                    if (column_index != 0) try text.writer.writeByte(',');
                    const key = if (column_index < headers.len) headers[column_index] else "column";
                    try writeJsonString(&text.writer, key);
                    try text.writer.writeByte(':');
                    try writeJsonString(&text.writer, column);
                }
                try text.writer.writeByte('}');
            }
            try text.writer.writeByte(']');
        } else {
            const width = if (packets.len == 0) headers.len else packets[0].columns.len;
            var column_index: usize = 0;
            while (column_index < width) : (column_index += 1) {
                if (column_index != 0) try text.writer.writeByte(',');
                const key = if (column_index < headers.len) headers[column_index] else "column";
                try writeCsvField(&text.writer, key);
            }
            if (width != 0) try text.writer.writeByte('\n');
            for (packets) |row| {
                for (row.columns, 0..) |column, index| {
                    if (index != 0) try text.writer.writeByte(',');
                    try writeCsvField(&text.writer, column);
                }
                try text.writer.writeByte('\n');
            }
        }
        const bytes = try text.toOwnedSlice();
        defer self.allocator.free(bytes);
        try std.Io.Dir.cwd().writeFile(self.io, .{ .sub_path = path, .data = bytes });
        const message = try std.fmt.allocPrint(self.allocator, "Wrote {s}", .{path});
        defer self.allocator.free(message);
        try self.showMessage(message);
    }

    pub fn applyColumns(self: *AppModel, args: []const u8) !void {
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
        } else if (std.mem.eql(u8, trimmed, "add") or std.mem.startsWith(u8, trimmed, "add ")) {
            const named = if (std.mem.startsWith(u8, trimmed, "add ")) std.mem.trim(u8, trimmed["add ".len..], " \t") else "";
            const field = if (named.len != 0) named else self.selectedColumnField() orelse {
                try self.showMessage("Select a protocol field, or :columns add <field>");
                return;
            };
            const base = if (self.config.column_format.len != 0) self.config.column_format else process_mod.default_column_format;
            const next = columns_mod.addCustomColumn(self.allocator, base, field) catch {
                try self.showMessage("That field name cannot be a column");
                return;
            };
            defer self.allocator.free(next);
            if (std.mem.eql(u8, next, base)) {
                try self.showMessage("That field is already a column");
                return;
            }
            try self.config.setColumnFormat(next);
        } else if (std.mem.eql(u8, trimmed, "drop") or std.mem.startsWith(u8, trimmed, "drop ")) {
            const named = if (std.mem.startsWith(u8, trimmed, "drop ")) std.mem.trim(u8, trimmed["drop ".len..], " \t") else "";
            const field = if (named.len != 0) named else self.selectedColumnField() orelse {
                try self.showMessage("Select a protocol field, or :columns drop <field>");
                return;
            };
            const base = if (self.config.column_format.len != 0) self.config.column_format else process_mod.default_column_format;
            const next = columns_mod.dropCustomColumn(self.allocator, base, field) catch {
                try self.showMessage("That field name cannot be a column");
                return;
            } orelse {
                try self.showMessage("That field is not a custom column");
                return;
            };
            defer self.allocator.free(next);
            try self.config.setColumnFormat(next);
        } else {
            try self.showMessage("Usage: :columns [default|delta|absolute|set <format>|add <field>|drop <field>]");
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

    pub fn pollFilterFeedback(self: *AppModel) void {
        if (self.filter_check_worker) |worker| {
            if (self.filter_check_inflight.load(.acquire)) return;
            worker.join();
            self.filter_check_worker = null;
        }
        self.applyFilterVerdict();
        if (self.filter_check_inflight.load(.acquire)) return;

        const text_const = self.filter.copyText(self.allocator) catch return;
        const text: []u8 = @constCast(text_const);
        self.updateMacroPreview(text);
        if (!std.mem.eql(u8, text, self.filter_seen)) {
            if (self.filter_seen.len != 0) self.allocator.free(self.filter_seen);
            self.filter_seen = text;
            self.filter_seen_ticks = 0;
            return;
        }
        self.allocator.free(text);
        if (std.mem.eql(u8, self.filter_seen, self.filter_checked)) return;
        self.filter_seen_ticks += 1;
        if (self.filter_seen_ticks < 3) return;

        if (self.filter_seen.len == 0) {
            self.filter.state = .neutral;
            self.setFilterError("");
            if (self.filter_checked.len != 0) self.allocator.free(self.filter_checked);
            self.filter_checked = &.{};
            self.reloadDisplayFilter("") catch |err| {
                log_mod.err("filter", "clear failed: {s}", .{@errorName(err)});
            };
            return;
        }

        const owned = self.allocator.dupe(u8, self.filter_seen) catch return;
        self.filter_check_inflight.store(true, .release);
        if (self.filter_check_sync) {
            self.runFilterCheck(owned);
            self.applyFilterVerdict();
            return;
        }
        self.filter_check_worker = std.Thread.spawn(.{}, filterCheckWorker, .{ self, owned }) catch {
            self.filter_check_inflight.store(false, .release);
            self.allocator.free(owned);
            return;
        };
    }

    fn filterCheckWorker(self: *AppModel, text: []u8) void {
        self.runFilterCheck(text);
    }

    fn runFilterCheck(self: *AppModel, text: []u8) void {
        defer self.filter_check_inflight.store(false, .release);
        const started = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        const expanded = macros_feature.expand(self.allocator, self.config, text) catch {
            self.allocator.free(text);
            return;
        };
        defer self.allocator.free(expanded);
        const verdict = filter_mod.explainDisplayFilter(
            self.allocator,
            self.io,
            self.tools.tshark,
            self.empty_pcap,
            expanded,
            self.process_runner,
        ) catch {
            self.allocator.free(text);
            return;
        };
        const elapsed_ms = @divTrunc(std.Io.Timestamp.now(self.io, .awake).nanoseconds -| started, std.time.ns_per_ms);
        log_mod.info("filter", "checked in {d} ms", .{elapsed_ms});
        self.filter_check_mutex.lockUncancelable(self.io);
        defer self.filter_check_mutex.unlock(self.io);
        if (self.filter_check_box) |*box| {
            self.allocator.free(box.text);
            self.allocator.free(box.detail);
        }
        self.filter_check_box = .{
            .text = text,
            .ok = verdict.ok,
            .detail = verdict.detail,
        };
    }

    fn applyFilterVerdict(self: *AppModel) void {
        self.filter_check_mutex.lockUncancelable(self.io);
        const box = self.filter_check_box orelse {
            self.filter_check_mutex.unlock(self.io);
            return;
        };
        self.filter_check_box = null;
        self.filter_check_mutex.unlock(self.io);

        if (!std.mem.eql(u8, box.text, self.filter_seen)) {
            self.allocator.free(box.text);
            self.allocator.free(box.detail);
            return;
        }
        self.filter.state = if (box.ok) .ok else .bad;
        self.setFilterError(if (box.ok) "" else box.detail);
        if (self.filter_checked.len != 0) self.allocator.free(self.filter_checked);
        self.filter_checked = box.text;
        self.allocator.free(box.detail);
        if (box.ok) {
            self.reloadDisplayFilter(self.filter_checked) catch |err| {
                log_mod.err("filter", "apply failed: {s}", .{@errorName(err)});
            };
        }
    }

    fn updateMacroPreview(self: *AppModel, text: []const u8) void {
        const expanded = macros_feature.expand(self.allocator, self.config, text) catch return;
        defer self.allocator.free(expanded);
        if (std.mem.eql(u8, expanded, text)) {
            if (self.macro_preview.len != 0) self.allocator.free(self.macro_preview);
            self.macro_preview = &.{};
            self.status.expansion = "";
            return;
        }
        if (std.mem.eql(u8, expanded, self.macro_preview)) return;
        const copy = self.allocator.dupe(u8, expanded) catch return;
        if (self.macro_preview.len != 0) self.allocator.free(self.macro_preview);
        self.macro_preview = copy;
        self.status.expansion = self.macro_preview;
    }

    fn setFilterError(self: *AppModel, detail: []const u8) void {
        if (detail.len == 0) {
            if (self.filter_error_text.len != 0) self.allocator.free(self.filter_error_text);
            self.filter_error_text = &.{};
            self.status.filter_error = "";
            return;
        }
        const copy = self.allocator.dupe(u8, detail) catch return;
        if (self.filter_error_text.len != 0) self.allocator.free(self.filter_error_text);
        self.filter_error_text = copy;
        self.status.filter_error = self.filter_error_text;
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

    pub fn showStream(self: *AppModel, proto: []const u8, index: u32, body: []const u8, capped: bool) !void {
        if (self.stream_filter.len != 0) self.allocator.free(self.stream_filter);
        self.stream_filter = try std.fmt.allocPrint(self.allocator, "{s}.stream == {d}", .{ proto, index });
        var parsed = streams_shark.parseYaml(self.allocator, body) catch streams_shark.parse(self.allocator, body) catch {
            const shown = try capText(self.allocator, body, capped, false);
            defer self.allocator.free(shown);
            try self.showPick("Stream", shown, .streams);
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
        const row_capped = try self.trimStreamChunks();
        var text: std.Io.Writer.Allocating = .init(self.allocator);
        defer text.deinit();
        if (self.stream_chunks.len == 0) {
            try text.writer.writeAll(body);
        } else {
            for (self.stream_chunks, 0..) |chunk, i| {
                if (i != 0) try text.writer.writeByte('\n');
                const preview = std.mem.sliceTo(chunk.data, 0);
                const shown = if (preview.len > 48) preview[0..48] else preview;
                const way = if (chunk.direction == .client) "client -> server" else "server -> client";
                if (chunk.frame) |frame| {
                    try text.writer.print("{d: >3}  frame {d}  {s}  {d} bytes  {s}", .{
                        i,
                        frame,
                        way,
                        chunk.data.len,
                        shown,
                    });
                } else {
                    try text.writer.print("{d: >3}  {s}  {d} bytes  {s}", .{
                        i,
                        way,
                        chunk.data.len,
                        shown,
                    });
                }
            }
        }
        try writeCapNote(&text.writer, capped, row_capped);
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        var known_frame = false;
        for (self.stream_chunks) |chunk| {
            if (chunk.frame != null) known_frame = true;
        }
        try self.showPick(if (known_frame)
            "Stream  Enter jumps to that frame"
        else
            "Stream  Enter guesses the packet", owned, .streams);
    }

    fn trimStreamChunks(self: *AppModel) !bool {
        if (self.stream_chunks.len <= process_mod.view_row_cap) return false;
        for (self.stream_chunks[process_mod.view_row_cap..]) |*chunk| chunk.deinit(self.allocator);
        const kept = try self.allocator.alloc(streams_shark.Chunk, process_mod.view_row_cap);
        @memcpy(kept, self.stream_chunks[0..process_mod.view_row_cap]);
        self.allocator.free(self.stream_chunks);
        self.stream_chunks = kept;
        return true;
    }

    pub fn showConversations(self: *AppModel, path: []const u8, proto: []const u8) !void {
        var argv = try process_mod.argvConversations(self.allocator, self.tools.tshark, path, proto);
        defer argv.deinit(self.allocator);
        var out = try self.runProcessLimited(argv.slice(), process_mod.view_stdout_cap);
        defer out.deinit(self.allocator);
        self.clearConversations();
        if (self.conversation_proto.len != 0) self.allocator.free(self.conversation_proto);
        self.conversation_proto = try self.allocator.dupe(u8, proto);
        self.conversations = convs_shark.parse(self.allocator, out.stdout) catch {
            const shown = try capText(self.allocator, if (out.stdout.len != 0) out.stdout else out.stderr, out.truncated, false);
            defer self.allocator.free(shown);
            try self.showPick("Conversations", shown, .convs);
            return;
        };
        const row_capped = try self.trimConversations();
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
            if (self.config.conv_absolute_time) {
                try text.writer.print("  start {d:.3}s", .{conversation.rel_start});
            }
        }
        try writeCapNote(&text.writer, out.truncated, row_capped);
        const owned = try text.toOwnedSlice();
        defer self.allocator.free(owned);
        try self.showPick("Conversations  Enter filters the list", owned, .convs);
    }

    fn trimConversations(self: *AppModel) !bool {
        if (self.conversations.len <= process_mod.view_row_cap) return false;
        for (self.conversations[process_mod.view_row_cap..]) |*conversation| conversation.deinit(self.allocator);
        const kept = try self.allocator.alloc(convs_shark.Conversation, process_mod.view_row_cap);
        @memcpy(kept, self.conversations[0..process_mod.view_row_cap]);
        self.allocator.free(self.conversations);
        self.conversations = kept;
        return true;
    }

    fn writeCapNote(writer: *std.Io.Writer, bytes: bool, rows: bool) !void {
        if (!bytes and !rows) return;
        try writer.writeByte('\n');
        if (rows) try writer.print("Stopped after {d} rows. ", .{process_mod.view_row_cap});
        if (bytes) try writer.writeAll("Stopped at the 1 MiB output cap. ");
        try writer.writeAll("The rest was not loaded.");
    }

    fn capText(allocator: std.mem.Allocator, body: []const u8, bytes: bool, rows: bool) ![]u8 {
        if (!bytes and !rows) return allocator.dupe(u8, body);
        var text: std.Io.Writer.Allocating = .init(allocator);
        errdefer text.deinit();
        try text.writer.writeAll(body);
        try writeCapNote(&text.writer, bytes, rows);
        return text.toOwnedSlice();
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
                if (index < self.stream_chunks.len) {
                    if (self.stream_chunks[index].frame) |frame| {
                        self.dismissOverlays();
                        if (self.selectFrame(frame)) {
                            self.syncFromSession();
                            try self.loadDetailForSelection();
                        } else {
                            const message = try std.fmt.allocPrint(self.allocator, "Frame {d} is not in the list", .{frame});
                            defer self.allocator.free(message);
                            try self.showMessage(message);
                        }
                        return;
                    }
                }
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
                self.status.mode = "guess";
                try self.searchByDisplayFilter(filter);
            },
            .field_filter => try self.chooseFieldFilter(self.help_overlay.selected),
            .conv_filter => {
                const text = self.conversationExpression() catch return;
                defer self.allocator.free(text);
                const apply = self.help_overlay.selected == 0;
                self.dismissOverlays();
                try self.commitFilter(text, apply);
            },
            .saved_filters => {
                const index = self.help_overlay.selected;
                if (index >= self.config.named_filters.items.len) return;
                const value = try self.allocator.dupe(u8, self.config.named_filters.items[index].value);
                defer self.allocator.free(value);
                self.dismissOverlays();
                try self.commitFilter(value, true);
            },
            .recent_filters => {
                const index = self.help_overlay.selected;
                if (index >= self.config.recent_filters.items.len) return;
                const value = try self.allocator.dupe(u8, self.config.recent_filters.items[index]);
                defer self.allocator.free(value);
                self.dismissOverlays();
                try self.commitFilter(value, true);
            },
            .expert => {
                const index = self.help_overlay.selected;
                if (index >= self.expert_items.len) return;
                const occurrence = self.expert_items[index].occurrence;
                self.dismissOverlays();
                self.focus = .protocol;
                if (!self.protocol_tree.selectNamed("_ws.expert", occurrence)) {
                    try self.showMessage("That expert field is not in the open packet");
                }
            },
            .hierarchy => {
                const index = self.help_overlay.selected;
                if (index >= self.hierarchy_names.len) return;
                const name = try self.allocator.dupe(u8, self.hierarchy_names[index]);
                defer self.allocator.free(name);
                self.dismissOverlays();
                try self.appendDisplayFilter(name);
            },
            .endpoints => {
                const index = self.help_overlay.selected;
                if (index >= self.endpoint_filters.len) return;
                const filter = try self.allocator.dupe(u8, self.endpoint_filters[index]);
                defer self.allocator.free(filter);
                self.dismissOverlays();
                try self.commitFilter(filter, true);
            },
            .iograph, .dns, .http, .compare => {
                const index = self.help_overlay.selected;
                if (index >= self.stat_filters.len) return;
                if (self.stat_filters[index].len == 0) {
                    self.dismissOverlays();
                    try self.showMessage("That packet is only in the other capture");
                    return;
                }
                const filter = try self.allocator.dupe(u8, self.stat_filters[index]);
                defer self.allocator.free(filter);
                self.dismissOverlays();
                try self.commitFilter(filter, true);
            },
            .decode_selector => {
                const index = self.help_overlay.selected;
                if (index >= self.decode_choices.len) return;
                if (self.decode_selector.len != 0) self.allocator.free(self.decode_selector);
                self.decode_selector = try self.allocator.dupe(u8, self.decode_choices[index]);
                try self.showDecodeProtocols();
            },
            .decode_protocol => {
                const index = self.help_overlay.selected;
                if (index >= self.decode_choices.len or self.decode_selector.len == 0) return;
                const rule = try std.fmt.allocPrint(self.allocator, "{s},{s}", .{
                    self.decode_selector,
                    self.decode_choices[index],
                });
                defer self.allocator.free(rule);
                self.dismissOverlays();
                try self.session.addDecodeAs(rule);
                self.clearDetail();
                self.loader.clearDetailCache(self.io);
                try self.loader.requestPsml(self.session);
            },
            .menu => try self.runMenuChoice(self.help_overlay.selected),
            else => {},
        }
    }

    fn runMenuChoice(self: *AppModel, index: usize) !void {
        if (self.menu_analysis) {
            switch (index) {
                0 => try self.openFieldFilter(),
                1 => self.openGoto(),
                2 => {
                    self.dismissOverlays();
                    try self.runCommand("streams", "");
                },
                3 => {
                    self.dismissOverlays();
                    try self.runCommand("convs", "");
                },
                4 => {
                    self.dismissOverlays();
                    try self.runCommand("capinfo", "");
                },
                5 => {
                    self.dismissOverlays();
                    try self.runCommand("expert", "");
                },
                6 => {
                    self.dismissOverlays();
                    try self.runCommand("hierarchy", "");
                },
                7 => {
                    self.dismissOverlays();
                    try self.runCommand("endpoints", "");
                },
                8 => {
                    self.dismissOverlays();
                    try self.command.setText("export ");
                    self.command.visible = true;
                },
                else => {},
            }
            return;
        }
        self.dismissOverlays();
        switch (index) {
            0 => try self.runCommand("columns", ""),
            1 => try self.runCommand("theme", ""),
            2 => try self.runCommand("profile", ""),
            3 => try self.runCommand("marks", ""),
            4 => try self.runCommand("tail", ""),
            else => {},
        }
    }

    pub fn showThemeList(self: *AppModel) !void {
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

    pub fn runProfileCommand(self: *AppModel, args: []const u8) !void {
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

    pub fn applyTheme(self: *AppModel, theme: theme_mod.Theme) void {
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
        self.dropdown.theme = theme;
    }

    pub fn loadConfiguredTheme(self: *AppModel) !theme_mod.Theme {
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

    pub fn streamFromDetail(self: *const AppModel) ?struct { proto: []const u8, index: u32 } {
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
                const subtree = if (self.copy_mode)
                    try self.protocol_tree.formatSubtree(self.allocator)
                else
                    try self.allocator.dupe(u8, self.protocol_tree.selectedText());
                defer self.allocator.free(subtree);
                const text = if (self.protocol_tree.selectedField()) |field|
                    try field_filter.formatFieldCopy(self.allocator, field.name, field.show, subtree)
                else
                    try self.allocator.dupe(u8, subtree);
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
        self.goto_prompt = false;
        self.closeHeaderMenu();
    }

    pub fn widget(self: *AppModel) vxfw.Widget {
        return .{
            .userdata = self,
            .eventHandler = AppModel.typeErasedEventHandler,
            .captureHandler = AppModel.typeErasedCapture,
            .drawFn = AppModel.typeErasedDrawFn,
        };
    }

    fn typeErasedCapture(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *AppModel = @ptrCast(@alignCast(ptr));
        switch (event) {
            .key_press => |key| {
                if (self.quit_confirm or self.export_confirm) return;
                if (key.matches('c', .{ .ctrl = true }) and !self.copy_mode) {
                    ctx.quit = true;
                    return ctx.consumeEvent();
                }
                if (self.command.visible) {
                    try ctx.requestFocus(self.command.widget());
                    try self.command.widget().handleEvent(ctx, event);
                    return ctx.consumeAndRedraw();
                }
                if (self.goto_prompt) {
                    try self.handleGotoKey(ctx, key);
                    return;
                }
                if (self.header_menu != null) {
                    try self.handleHeaderMenuKey(ctx, key);
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
                    return ctx.consumeAndRedraw();
                }
            },
            .mouse => |mouse| {
                if (mouse.type != .press or mouse.button != .left) return;
                if (self.header_menu != null) {
                    if (mouse.row == 0 and mouse.col >= 0) {
                        if (header_bar.menuAt(self.header.last_width, @intCast(mouse.col)) != null) return;
                    }
                    if (!self.dropdownContains(mouse.col, mouse.row)) {
                        self.closeHeaderMenu();
                        return ctx.consumeAndRedraw();
                    }
                    return;
                }
                if (self.command.visible and !self.boxContains(mouse.col, mouse.row, self.palette_col, self.palette_row, self.palette_w, self.palette_h)) {
                    self.command.visible = false;
                    return ctx.consumeAndRedraw();
                }
                if ((self.help_overlay.visible or self.msg_overlay.visible) and !self.boxContains(mouse.col, mouse.row, self.dialog_col, self.dialog_row, self.dialog_w, self.dialog_h)) {
                    self.dismissOverlays();
                    return ctx.consumeAndRedraw();
                }
            },
            else => {},
        }
    }

    fn handleHeaderMenuKey(self: *AppModel, ctx: *vxfw.EventContext, key: vaxis.Key) !void {
        if (key.matches(vaxis.Key.escape, .{}) or key.matches('q', .{})) {
            self.closeHeaderMenu();
            return ctx.consumeAndRedraw();
        }
        if (key.matches('j', .{}) or key.matches(vaxis.Key.down, .{})) {
            if (self.dropdown.line_count > 0 and self.dropdown.selected + 1 < self.dropdown.line_count) {
                self.dropdown.selected += 1;
            }
            return ctx.consumeAndRedraw();
        }
        if (key.matches('k', .{}) or key.matches(vaxis.Key.up, .{})) {
            self.dropdown.selected -|= 1;
            return ctx.consumeAndRedraw();
        }
        if (key.matches('l', .{}) or key.matches(vaxis.Key.right, .{})) {
            self.cycleHeaderMenu(true);
            return ctx.consumeAndRedraw();
        }
        if (key.matches('h', .{}) or key.matches(vaxis.Key.left, .{})) {
            self.cycleHeaderMenu(false);
            return ctx.consumeAndRedraw();
        }
        if (key.matches(vaxis.Key.enter, .{})) {
            self.activateHeaderItem(self.dropdown.selected);
            return ctx.consumeAndRedraw();
        }
        return ctx.consumeAndRedraw();
    }

    fn cycleHeaderMenu(self: *AppModel, next: bool) void {
        const order = [_]header_bar.HeaderBar.Menu{ .analysis, .misc, .help };
        const current = self.header_menu orelse return;
        var index: usize = 0;
        for (order, 0..) |menu, item| if (menu == current) {
            index = item;
        };
        const step: usize = if (next) 1 else order.len - 1;
        self.openHeaderMenu(order[(index + step) % order.len]);
    }

    fn dropdownContains(self: *const AppModel, col: i16, row: i16) bool {
        return self.boxContains(col, row, self.dropdown_col, 1, self.dropdown_width, self.dropdown_height);
    }

    fn boxContains(self: *const AppModel, col: i16, row: i16, origin_col: u16, origin_row: u16, width: u16, height: u16) bool {
        _ = self;
        if (col < 0 or row < 0 or width == 0 or height == 0) return false;
        const point_col: u16 = @intCast(col);
        const point_row: u16 = @intCast(row);
        return point_col >= origin_col and point_col < origin_col + width and point_row >= origin_row and point_row < origin_row + height;
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
                    try self.refreshLiveCapture();
                } else if (self.tailing) {
                    self.tail_ticks +%= 1;
                    if (self.tail_ticks >= 10) {
                        self.tail_ticks = 0;
                        self.refreshTailedFile() catch {};
                    }
                }
                self.pollTransfer();
                self.pollFilterFeedback();
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
                if (self.export_confirm) {
                    if (key.matches('y', .{}) or key.matches('Y', .{})) {
                        try self.acceptExport();
                        return ctx.consumeAndRedraw();
                    }
                    if (key.matches('n', .{}) or key.matches(vaxis.Key.escape, .{})) {
                        self.clearExportConfirm();
                        self.dismissOverlays();
                        return ctx.consumeAndRedraw();
                    }
                    return ctx.consumeAndRedraw();
                }
                if (self.help_overlay.visible or self.msg_overlay.visible) {
                    if (key.matches('q', .{}) or key.matches(vaxis.Key.escape, .{})) {
                        self.dismissOverlays();
                        return ctx.consumeAndRedraw();
                    }
                    if (self.help_overlay.visible and self.help_overlay.pick and key.matches(vaxis.Key.enter, .{})) {
                        try self.activatePick();
                        if (self.command.visible) try ctx.requestFocus(self.command.widget());
                        if (self.focus == .filter) try ctx.requestFocus(self.filter.widget());
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
                if (self.live_capture and self.focus != .filter and key.matches('s', .{})) {
                    try self.stopCapture();
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
                if (key.matches('=', .{})) {
                    if (self.focus == .protocol) try self.openFieldFilter() else if (self.focus == .packets) try self.openConversationFilter();
                    return ctx.consumeAndRedraw();
                }
                if (self.focus != .filter and (key.matches('{', .{}) or key.matches('[', .{ .shift = true }))) {
                    try self.jumpRelated(.address, false);
                    return ctx.consumeAndRedraw();
                }
                if (self.focus != .filter and (key.matches('}', .{}) or key.matches(']', .{ .shift = true }))) {
                    try self.jumpRelated(.address, true);
                    return ctx.consumeAndRedraw();
                }
                if (self.focus != .filter and key.matches('[', .{})) {
                    try self.jumpRelated(.conversation, false);
                    return ctx.consumeAndRedraw();
                }
                if (self.focus != .filter and key.matches(']', .{})) {
                    try self.jumpRelated(.conversation, true);
                    return ctx.consumeAndRedraw();
                }
                if (self.focus == .packets and key.matches('p', .{})) {
                    try self.jumpRelated(.exchange, true);
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('p', .{ .ctrl = true })) {
                    try self.restorePreviousFilter();
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('g', .{}) and self.focus != .filter) {
                    try self.command.setText("goto ");
                    self.command.visible = true;
                    try ctx.requestFocus(self.command.widget());
                    return ctx.consumeAndRedraw();
                }
                if (key.matches('t', .{ .ctrl = true })) {
                    try self.toggleTimeReference();
                    return ctx.consumeAndRedraw();
                }
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
        self.filter.focused = self.focus == .filter;
        self.protocol_tree.focused = self.focus == .protocol;
        self.hex.focused = self.focus == .hex;
        self.status.pane = switch (self.focus) {
            .packets => "list",
            .protocol => "tree",
            .hex => "hex",
            .filter => "filter",
        };
        self.status.hint = switch (self.focus) {
            .packets => "= conv   g goto",
            .protocol => "= field filter",
            .hex => "hjkl byte",
            .filter => "Enter applies   Up recent   Tab name",
        };
        if (self.live_capture) {
            self.status.hint = if (self.follow_tail) "s/:stop ends   scroll pauses tail" else "s/:stop ends   End resumes tail";
        }
        if (self.header_menu != null) self.status.hint = "j/k move   Enter   Esc";
        self.status.selected_index = self.session.selected_index;
        self.status.tailing = self.tailing;
        self.status.live = self.live_capture;
        self.status.filter_error = self.filter_error_text;
        self.status.expansion = self.macro_preview;
        self.status.expert_count = if (self.detail_bundle) |*bundle| expert_mod.count(&bundle.pdml.root) else 0;
        self.status.tls_keys = self.session.tls_keylog_file.len != 0;
        self.status.time_zero = self.time_reference_frame;
        self.packet_table.color_rules = self.config.color_rules.items;
        self.packet_table.time_base = self.time_reference_seconds;
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
            const dialog_row = (size.height -| ov.size.height) / 2;
            const dialog_col = (size.width -| ov.size.width) / 2;
            self.dialog_row = dialog_row;
            self.dialog_col = dialog_col;
            self.dialog_h = ov.size.height;
            self.dialog_w = ov.size.width;
            self.children_buf[idx] = .{ .origin = .{ .row = dialog_row, .col = dialog_col }, .surface = ov, .z_index = 10 };
            idx += 1;
        }
        if (self.msg_overlay.visible) {
            const ov = try self.msg_overlay.draw(ctx);
            const dialog_row = (size.height -| ov.size.height) / 2;
            const dialog_col = (size.width -| ov.size.width) / 2;
            self.dialog_row = dialog_row;
            self.dialog_col = dialog_col;
            self.dialog_h = ov.size.height;
            self.dialog_w = ov.size.width;
            self.children_buf[idx] = .{ .origin = .{ .row = dialog_row, .col = dialog_col }, .surface = ov, .z_index = 11 };
            idx += 1;
        }
        if (self.command.visible) {
            const box_w: u16 = @min(size.width -| 4, 64);
            const box_h: u16 = @min(size.height -| 4, 14);
            const pal = try self.command.draw(ctx.withConstraints(
                .{ .width = box_w, .height = box_h },
                .{ .width = box_w, .height = box_h },
            ));
            const pal_row: u16 = 2;
            const pal_col = (size.width -| pal.size.width) / 2;
            self.palette_row = pal_row;
            self.palette_col = pal_col;
            self.palette_h = pal.size.height;
            self.palette_w = pal.size.width;
            self.children_buf[idx] = .{ .origin = .{ .row = pal_row, .col = pal_col }, .surface = pal, .z_index = 12 };
            idx += 1;
        }
        if (self.header_menu) |menu| {
            const measured = overlay_mod.Dropdown.measure(self.dropdown.body);
            var col = header_bar.menuAnchor(size.width, menu);
            if (col + measured.width > size.width) col = size.width -| measured.width;
            self.dropdown_col = col;
            self.dropdown_width = measured.width;
            self.dropdown_height = measured.height;
            const menu_surf = try self.dropdown.draw(ctx.withConstraints(
                .{ .width = measured.width, .height = measured.height },
                .{ .width = measured.width, .height = measured.height },
            ));
            self.children_buf[idx] = .{
                .origin = .{ .row = 1, .col = col },
                .surface = menu_surf,
                .z_index = 20,
            };
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

const decode_protocol_names = [_][]const u8{ "http", "tls", "dns", "quic", "dhcp", "ntp", "ssh", "smb" };

fn collectDecodeSelectors(
    allocator: std.mem.Allocator,
    node: *const packet.DetailNode,
    choices: *std.ArrayList([]u8),
) !void {
    const layer: ?[]const u8 = if (std.mem.eql(u8, node.name, "tcp.srcport") or std.mem.eql(u8, node.name, "tcp.dstport"))
        "tcp.port"
    else if (std.mem.eql(u8, node.name, "udp.srcport") or std.mem.eql(u8, node.name, "udp.dstport"))
        "udp.port"
    else if (std.mem.eql(u8, node.name, "eth.type"))
        "ethertype"
    else
        null;
    if (layer) |name| {
        const value = std.mem.trim(u8, node.show, " \t");
        if (value.len != 0) {
            const spec = try std.fmt.allocPrint(allocator, "{s}=={s}", .{ name, value });
            var seen = false;
            for (choices.items) |existing| {
                if (std.mem.eql(u8, existing, spec)) seen = true;
            }
            if (seen) allocator.free(spec) else try choices.append(allocator, spec);
        }
    }
    for (node.children) |*child| try collectDecodeSelectors(allocator, child, choices);
}

fn writeJsonString(writer: *std.Io.Writer, text: []const u8) !void {
    try writer.writeByte('"');
    for (text) |char| switch (char) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        else => try writer.writeByte(char),
    };
    try writer.writeByte('"');
}

fn writeCsvField(writer: *std.Io.Writer, text: []const u8) !void {
    try writer.writeByte('"');
    for (text) |char| {
        if (char == '"') try writer.writeByte('"');
        try writer.writeByte(char);
    }
    try writer.writeByte('"');
}
