const std = @import("std");
const theme_mod = @import("theme.zig");
const help_view = @import("views/help.zig");
const streams_view = @import("views/streams.zig");
const streams_shark = @import("../shark/streams.zig");
const capinfo_view = @import("views/capinfo.zig");
const transfer = @import("../features/transfer.zig");

const AppModel = @import("app.zig").AppModel;

pub fn run(self: *AppModel, cmd: []const u8, args: []const u8) !void {
    const analysis = @import("views/analysis.zig");
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
        const expression = std.mem.trim(u8, args, " \t");
        if (expression.len == 0) {
            self.focus = .filter;
        } else {
            try self.commitFilter(expression, true);
        }
    } else if (std.mem.eql(u8, cmd, "expert")) {
        try analysis.showExpert(self, args);
    } else if (std.mem.eql(u8, cmd, "time-ref")) {
        try self.toggleTimeReference();
    } else if (std.mem.eql(u8, cmd, "goto")) {
        try self.gotoFrame(args);
    } else if (std.mem.eql(u8, cmd, "decode-as")) {
        if (args.len == 0) {
            try self.showDecodeSelectors();
            return;
        }
        try self.session.addDecodeAs(args);
        self.clearDetail();
        self.loader.clearDetailCache(self.io);
        try self.loader.requestPsml(self.session);
    } else if (std.mem.eql(u8, cmd, "hierarchy")) {
        try analysis.showHierarchy(self);
    } else if (std.mem.eql(u8, cmd, "endpoints")) {
        try analysis.showEndpoints(self, args);
    } else if (std.mem.eql(u8, cmd, "iograph")) {
        try analysis.showIoGraph(self, args);
    } else if (std.mem.eql(u8, cmd, "dns")) {
        try analysis.showDns(self);
    } else if (std.mem.eql(u8, cmd, "http")) {
        try analysis.showHttp(self);
    } else if (std.mem.eql(u8, cmd, "compare")) {
        try analysis.showCompare(self, args);
    } else if (std.mem.eql(u8, cmd, "color")) {
        try analysis.runColorCommand(self, args);
    } else if (std.mem.eql(u8, cmd, "comment")) {
        try analysis.runCommentCommand(self, args);
    } else if (std.mem.eql(u8, cmd, "lua")) {
        try analysis.runLuaCommand(self, args);
    } else if (std.mem.eql(u8, cmd, "export")) {
        try analysis.runExport(self, args, false);
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
        try self.clearDisplayFilter();
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
        if (std.mem.eql(u8, std.mem.trim(u8, args, " \t"), "filter")) {
            try analysis.applyOpenStreamFilter(self);
            return;
        }
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
        const yaml = try streams_view.loadFollow(
            self.allocator,
            self.io,
            self.tools.tshark,
            path,
            index,
            proto,
            "yaml",
            self.process_runner,
        );
        defer self.allocator.free(yaml.body);
        var follow_result = streams_shark.parseYaml(self.allocator, yaml.body);
        if (follow_result) |*follow| {
            follow.deinit(self.allocator);
            try analysis.showStream(self, proto, index, yaml.body, yaml.capped);
        } else |_| {
            const loaded = try streams_view.loadFollow(
                self.allocator,
                self.io,
                self.tools.tshark,
                path,
                index,
                proto,
                mode,
                self.process_runner,
            );
            defer self.allocator.free(loaded.body);
            try analysis.showStream(self, proto, index, loaded.body, loaded.capped);
        }
    } else if (std.mem.eql(u8, cmd, "convs")) {
        const path = self.capturePath() orelse {
            try self.showMessage("No capture file loaded");
            return;
        };
        const ctype = if (args.len != 0) args else "tcp";
        try analysis.showConversations(self, path, ctype);
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
    } else if (std.mem.eql(u8, cmd, "mark")) {
        try self.runMarkCommand(args);
    } else if (std.mem.eql(u8, cmd, "related")) {
        try self.runRelatedCommand(args);
    } else if (std.mem.eql(u8, cmd, "back")) {
        try self.restorePreviousFilter();
    } else if (std.mem.eql(u8, cmd, "columns")) {
        try self.applyColumns(args);
    } else if (std.mem.eql(u8, cmd, "stop")) {
        try self.stopCapture();
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
    } else if (std.mem.eql(u8, cmd, "filters")) {
        try self.runFiltersCommand(args);
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
        try AppModel.onFilterSubmit(self, filter);
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
        self.transfer_job = transfer.Job.startWith(self.allocator, self.io, path, .{
            .code_length = self.config.wormhole_length,
            .relay_url = self.config.wormhole_rendezvous_url,
            .transit_helper = self.config.wormhole_transit_relay,
        }) catch |err| {
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
