const std = @import("std");

pub const Layout = enum { stacked, side_by_side, focus };

pub const Config = struct {
    allocator: std.mem.Allocator,

    tshark: []u8 = &.{},
    dumpcap: []u8 = &.{},
    capinfos: []u8 = &.{},
    capture_command: []u8 = &.{},
    tail_command: []u8 = &.{},
    tshark_args: []u8 = &.{},

    always_keep_pcap: bool = false,
    auto_scroll: bool = true,
    pcap_bundle_size: u32 = 1000,
    pcap_cache_size: u32 = 64,
    disk_cache_size_mb: u32 = 64,
    ui_cache_size: u32 = 1000,
    stream_cache_size: u32 = 32,

    dark_mode: bool = true,
    packet_colors: bool = true,
    layout: Layout = .stacked,
    disable_shark_fin: bool = false,
    stream_view: []u8 = &.{},
    theme: []u8 = &.{},

    column_format: []u8 = &.{},
    conv_types: []u8 = &.{},
    conv_absolute_time: bool = false,
    conv_resolve_names: bool = true,
    conv_use_filter: bool = true,

    search_type: []u8 = &.{},
    search_target: []u8 = &.{},
    search_case_sensitive: bool = false,

    copy_command: []u8 = &.{},
    copy_command_timeout: u32 = 5,
    browse_command: []u8 = &.{},
    pager: []u8 = &.{},
    wormhole_length: u32 = 2,
    wormhole_rendezvous_url: []u8 = &.{},
    wormhole_transit_relay: []u8 = &.{},

    recent_files: std.ArrayList([]u8) = .empty,
    recent_filters: std.ArrayList([]u8) = .empty,
    macros: std.ArrayList(Macro) = .empty,
    global_marks: std.ArrayList(GlobalMark) = .empty,
    profile: []u8 = &.{},
    wireshark_profile: []u8 = &.{},

    packet_list_ratio: f32 = 0.40,
    detail_ratio: f32 = 0.45,

    pub const Macro = struct {
        name: []u8,
        value: []u8,
    };

    pub const GlobalMark = struct {
        label: u8,
        path: []u8,
        frame: u32,
    };

    pub fn deinit(self: *Config) void {
        self.freeOwned();
        for (self.recent_files.items) |s| self.allocator.free(s);
        self.recent_files.deinit(self.allocator);
        for (self.recent_filters.items) |s| self.allocator.free(s);
        self.recent_filters.deinit(self.allocator);
        for (self.macros.items) |m| {
            self.allocator.free(m.name);
            self.allocator.free(m.value);
        }
        self.macros.deinit(self.allocator);
        for (self.global_marks.items) |mark| self.allocator.free(mark.path);
        self.global_marks.deinit(self.allocator);
    }

    fn freeOwned(self: *Config) void {
        const fields = .{
            "tshark",                  "dumpcap",                "capinfos",
            "capture_command",         "tail_command",           "tshark_args",
            "stream_view",             "theme",                  "column_format",
            "conv_types",              "search_type",            "search_target",
            "copy_command",            "browse_command",         "pager",
            "wormhole_rendezvous_url", "wormhole_transit_relay", "profile",
            "wireshark_profile",
        };
        inline for (fields) |name| {
            const ptr = &@field(self, name);
            if (ptr.len != 0) {
                self.allocator.free(ptr.*);
                ptr.* = &.{};
            }
        }
    }

    pub fn defaults(allocator: std.mem.Allocator) !Config {
        var cfg = Config{ .allocator = allocator };
        cfg.tshark = try allocator.dupe(u8, "tshark");
        cfg.dumpcap = try allocator.dupe(u8, "dumpcap");
        cfg.capinfos = try allocator.dupe(u8, "capinfos");
        cfg.tail_command = try allocator.dupe(u8, "tail");
        cfg.stream_view = try allocator.dupe(u8, "hex");
        cfg.search_type = try allocator.dupe(u8, "filter");
        cfg.search_target = try allocator.dupe(u8, "list");
        cfg.conv_types = try allocator.dupe(u8, "eth,ip,ipv6,tcp,udp");
        cfg.theme = try allocator.dupe(u8, "default");
        cfg.profile = try allocator.dupe(u8, "default");
        return cfg;
    }

    pub fn loadOrDefault(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Config {
        var cfg = try defaults(allocator);
        errdefer cfg.deinit();

        const cwd = std.Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, path, allocator, .limited(1024 * 1024)) catch {
            try cfg.save(io, path);
            return cfg;
        };
        defer allocator.free(content);
        try cfg.parseToml(content);
        return cfg;
    }

    pub fn save(self: *Config, io: std.Io, path: []const u8) !void {
        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();
        const w = &aw.writer;

        try w.writeAll("# zigshark configuration\n\n[main]\n");
        try w.print("tshark = \"{s}\"\n", .{self.tshark});
        try w.print("dumpcap = \"{s}\"\n", .{self.dumpcap});
        try w.print("capinfos = \"{s}\"\n", .{self.capinfos});
        try w.print("always-keep-pcap = {}\n", .{self.always_keep_pcap});
        try w.print("auto-scroll = {}\n", .{self.auto_scroll});
        try w.print("pcap-bundle-size = {d}\n", .{self.pcap_bundle_size});
        try w.print("pcap-cache-size = {d}\n", .{self.pcap_cache_size});
        try w.print("disk-cache-size-mb = {d}\n", .{self.disk_cache_size_mb});
        try w.print("ui-cache-size = {d}\n", .{self.ui_cache_size});
        try w.print("stream-cache-size = {d}\n", .{self.stream_cache_size});
        try w.print("disable-shark-fin = {}\n", .{self.disable_shark_fin});
        try w.print("stream-view = \"{s}\"\n", .{self.stream_view});
        try w.print("conv-absolute-time = {}\n", .{self.conv_absolute_time});
        if (self.tshark_args.len != 0) try w.print("tshark-args = \"{s}\"\n", .{self.tshark_args});
        if (self.capture_command.len != 0) try w.print("capture-command = \"{s}\"\n", .{self.capture_command});
        if (self.tail_command.len != 0) try w.print("tail-command = \"{s}\"\n", .{self.tail_command});
        if (self.wormhole_rendezvous_url.len != 0) try w.print("wormhole-rendezvous-url = \"{s}\"\n", .{self.wormhole_rendezvous_url});
        if (self.wormhole_transit_relay.len != 0) try w.print("wormhole-transit-relay = \"{s}\"\n", .{self.wormhole_transit_relay});
        try w.print("dark-mode = {}\n", .{self.dark_mode});
        try w.print("packet-colors = {}\n", .{self.packet_colors});
        try w.print("layout = \"{s}\"\n", .{@tagName(self.layout)});
        try w.print("theme = \"{s}\"\n", .{self.theme});
        try w.print("packet-list-ratio = {d:.2}\n", .{self.packet_list_ratio});
        try w.print("detail-ratio = {d:.2}\n", .{self.detail_ratio});
        try w.print("search-type = \"{s}\"\n", .{self.search_type});
        try w.print("search-target = \"{s}\"\n", .{self.search_target});
        try w.print("search-case-sensitive = {}\n", .{self.search_case_sensitive});
        try w.print("conv-types = \"{s}\"\n", .{self.conv_types});
        try w.print("conv-resolve-names = {}\n", .{self.conv_resolve_names});
        try w.print("conv-use-filter = {}\n", .{self.conv_use_filter});
        try w.print("copy-command-timeout = {d}\n", .{self.copy_command_timeout});
        try w.print("wormhole-length = {d}\n", .{self.wormhole_length});
        try w.print("profile = \"{s}\"\n", .{self.profile});
        if (self.column_format.len != 0) try w.print("column-format = \"{s}\"\n", .{self.column_format});
        if (self.copy_command.len != 0) try w.print("copy-command = \"{s}\"\n", .{self.copy_command});
        if (self.browse_command.len != 0) try w.print("browse-command = \"{s}\"\n", .{self.browse_command});
        if (self.pager.len != 0) try w.print("pager = \"{s}\"\n", .{self.pager});
        if (self.wireshark_profile.len != 0) try w.print("wireshark-profile = \"{s}\"\n", .{self.wireshark_profile});

        try w.writeAll("\n[recents]\n");
        for (self.recent_files.items) |f| try w.print("file = \"{s}\"\n", .{f});
        for (self.recent_filters.items) |f| try w.print("filter = \"{s}\"\n", .{f});

        if (self.macros.items.len != 0) {
            try w.writeAll("\n[macros]\n");
            for (self.macros.items) |m| try w.print("\"{s}\" = \"{s}\"\n", .{ m.name, m.value });
        }

        if (self.global_marks.items.len != 0) {
            try w.writeAll("\n[marks]\n");
            for (self.global_marks.items) |mark| {
                try w.print("\"{c}\" = \"{d}|{s}\"\n", .{
                    mark.label,
                    mark.frame,
                    mark.path,
                });
            }
        }

        const data = try aw.toOwnedSlice();
        defer self.allocator.free(data);

        var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
        const tmp = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path});
        const cwd = std.Io.Dir.cwd();
        try cwd.writeFile(io, .{ .sub_path = tmp, .data = data });
        try cwd.rename(tmp, cwd, path, io);
    }

    pub fn parseToml(self: *Config, content: []const u8) !void {
        var section: []const u8 = "main";
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            if (line[0] == '[') {
                if (std.mem.lastIndexOfScalar(u8, line, ']')) |end| {
                    section = std.mem.trim(u8, line[1..end], " \t");
                }
                continue;
            }
            const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const key = std.mem.trim(u8, line[0..eq], " \t\"");
            var value = std.mem.trim(u8, line[eq + 1 ..], " \t");
            if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                value = value[1 .. value.len - 1];
            }

            if (std.mem.eql(u8, section, "main")) {
                self.applySetting(key, value) catch |err| switch (err) {
                    error.UnknownSetting, error.InvalidValue => {},
                    else => return err,
                };
            } else if (std.mem.eql(u8, section, "recents")) {
                if (std.mem.eql(u8, key, "file")) {
                    try self.recent_files.append(self.allocator, try self.allocator.dupe(u8, value));
                } else if (std.mem.eql(u8, key, "filter")) {
                    try self.recent_filters.append(self.allocator, try self.allocator.dupe(u8, value));
                }
            } else if (std.mem.eql(u8, section, "macros")) {
                try self.macros.append(self.allocator, .{
                    .name = try self.allocator.dupe(u8, key),
                    .value = try self.allocator.dupe(u8, value),
                });
            } else if (std.mem.eql(u8, section, "marks") and key.len == 1 and
                key[0] >= 'A' and key[0] <= 'Z')
            {
                const separator = std.mem.indexOfScalar(u8, value, '|') orelse continue;
                const frame = std.fmt.parseInt(u32, value[0..separator], 10) catch continue;
                try self.global_marks.append(self.allocator, .{
                    .label = key[0],
                    .frame = frame,
                    .path = try self.allocator.dupe(u8, value[separator + 1 ..]),
                });
            }
        }
    }

    /// Apply one `key = value` pair from TOML or `:set`. Unknown keys fail.
    pub fn applySetting(self: *Config, key: []const u8, value: []const u8) !void {
        if (std.mem.indexOfScalar(u8, value, '"') != null or std.mem.indexOfScalar(u8, value, '\n') != null) {
            return error.InvalidValue;
        }
        if (!try self.applyMain(key, value)) return error.UnknownSetting;
    }

    pub fn formatSettings(self: *const Config, allocator: std.mem.Allocator) ![]u8 {
        var writer: std.Io.Writer.Allocating = .init(allocator);
        errdefer writer.deinit();
        try writer.writer.print(
            \\Settings (:set <key> <value>)
            \\tshark = {s}
            \\dumpcap = {s}
            \\capinfos = {s}
            \\tshark-args = {s}
            \\capture-command = {s}
            \\tail-command = {s}
            \\always-keep-pcap = {}
            \\auto-scroll = {}
            \\pcap-bundle-size = {d}
            \\pcap-cache-size = {d}
            \\disk-cache-size-mb = {d}
            \\ui-cache-size = {d}
            \\stream-cache-size = {d}
            \\dark-mode = {}
            \\packet-colors = {}
            \\layout = {s}
            \\theme = {s}
            \\stream-view = {s}
            \\column-format = {s}
            \\packet-list-ratio = {d:.2}
            \\detail-ratio = {d:.2}
            \\conv-types = {s}
            \\conv-absolute-time = {}
            \\conv-resolve-names = {}
            \\conv-use-filter = {}
            \\search-type = {s}
            \\search-target = {s}
            \\search-case-sensitive = {}
            \\copy-command = {s}
            \\copy-command-timeout = {d}
            \\browse-command = {s}
            \\pager = {s}
            \\wormhole-length = {d}
            \\wormhole-rendezvous-url = {s}
            \\wormhole-transit-relay = {s}
            \\wireshark-profile = {s}
            \\
        , .{
            self.tshark,
            self.dumpcap,
            self.capinfos,
            self.tshark_args,
            self.capture_command,
            self.tail_command,
            self.always_keep_pcap,
            self.auto_scroll,
            self.pcap_bundle_size,
            self.pcap_cache_size,
            self.disk_cache_size_mb,
            self.ui_cache_size,
            self.stream_cache_size,
            self.dark_mode,
            self.packet_colors,
            @tagName(self.layout),
            self.theme,
            self.stream_view,
            self.column_format,
            self.packet_list_ratio,
            self.detail_ratio,
            self.conv_types,
            self.conv_absolute_time,
            self.conv_resolve_names,
            self.conv_use_filter,
            self.search_type,
            self.search_target,
            self.search_case_sensitive,
            self.copy_command,
            self.copy_command_timeout,
            self.browse_command,
            self.pager,
            self.wormhole_length,
            self.wormhole_rendezvous_url,
            self.wormhole_transit_relay,
            self.wireshark_profile,
        });
        return writer.toOwnedSlice();
    }

    fn applyMain(self: *Config, key: []const u8, value: []const u8) !bool {
        if (std.mem.eql(u8, key, "tshark")) {
            try replaceOwned(self.allocator, &self.tshark, value);
        } else if (std.mem.eql(u8, key, "dumpcap")) {
            try replaceOwned(self.allocator, &self.dumpcap, value);
        } else if (std.mem.eql(u8, key, "capinfos")) {
            try replaceOwned(self.allocator, &self.capinfos, value);
        } else if (std.mem.eql(u8, key, "tshark-args")) {
            try replaceOwned(self.allocator, &self.tshark_args, value);
        } else if (std.mem.eql(u8, key, "capture-command")) {
            try replaceOwned(self.allocator, &self.capture_command, value);
        } else if (std.mem.eql(u8, key, "tail-command")) {
            try replaceOwned(self.allocator, &self.tail_command, value);
        } else if (std.mem.eql(u8, key, "always-keep-pcap")) {
            self.always_keep_pcap = parseBool(value);
        } else if (std.mem.eql(u8, key, "auto-scroll")) {
            self.auto_scroll = parseBool(value);
        } else if (std.mem.eql(u8, key, "pcap-bundle-size")) {
            self.pcap_bundle_size = std.fmt.parseInt(u32, value, 10) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "pcap-cache-size")) {
            self.pcap_cache_size = std.fmt.parseInt(u32, value, 10) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "disk-cache-size-mb")) {
            self.disk_cache_size_mb = std.fmt.parseInt(u32, value, 10) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "ui-cache-size")) {
            self.ui_cache_size = std.fmt.parseInt(u32, value, 10) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "stream-cache-size")) {
            self.stream_cache_size = std.fmt.parseInt(u32, value, 10) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "disable-shark-fin")) {
            self.disable_shark_fin = parseBool(value);
        } else if (std.mem.eql(u8, key, "dark-mode")) {
            self.dark_mode = parseBool(value);
        } else if (std.mem.eql(u8, key, "packet-colors")) {
            self.packet_colors = parseBool(value);
        } else if (std.mem.eql(u8, key, "layout")) {
            self.layout = std.meta.stringToEnum(Layout, value) orelse return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "theme")) {
            try replaceOwned(self.allocator, &self.theme, value);
        } else if (std.mem.eql(u8, key, "stream-view")) {
            try replaceOwned(self.allocator, &self.stream_view, value);
        } else if (std.mem.eql(u8, key, "packet-list-ratio")) {
            self.packet_list_ratio = std.fmt.parseFloat(f32, value) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "detail-ratio")) {
            self.detail_ratio = std.fmt.parseFloat(f32, value) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "search-type")) {
            try replaceOwned(self.allocator, &self.search_type, value);
        } else if (std.mem.eql(u8, key, "search-target")) {
            try replaceOwned(self.allocator, &self.search_target, value);
        } else if (std.mem.eql(u8, key, "search-case-sensitive")) {
            self.search_case_sensitive = parseBool(value);
        } else if (std.mem.eql(u8, key, "conv-types")) {
            try replaceOwned(self.allocator, &self.conv_types, value);
        } else if (std.mem.eql(u8, key, "conv-absolute-time")) {
            self.conv_absolute_time = parseBool(value);
        } else if (std.mem.eql(u8, key, "conv-resolve-names")) {
            self.conv_resolve_names = parseBool(value);
        } else if (std.mem.eql(u8, key, "conv-use-filter")) {
            self.conv_use_filter = parseBool(value);
        } else if (std.mem.eql(u8, key, "copy-command-timeout")) {
            self.copy_command_timeout = std.fmt.parseInt(u32, value, 10) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "wormhole-length")) {
            self.wormhole_length = std.fmt.parseInt(u32, value, 10) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, key, "wormhole-rendezvous-url")) {
            try replaceOwned(self.allocator, &self.wormhole_rendezvous_url, value);
        } else if (std.mem.eql(u8, key, "wormhole-transit-relay")) {
            try replaceOwned(self.allocator, &self.wormhole_transit_relay, value);
        } else if (std.mem.eql(u8, key, "profile")) {
            try replaceOwned(self.allocator, &self.profile, value);
        } else if (std.mem.eql(u8, key, "column-format")) {
            try replaceOwned(self.allocator, &self.column_format, value);
        } else if (std.mem.eql(u8, key, "copy-command")) {
            try replaceOwned(self.allocator, &self.copy_command, value);
        } else if (std.mem.eql(u8, key, "browse-command")) {
            try replaceOwned(self.allocator, &self.browse_command, value);
        } else if (std.mem.eql(u8, key, "pager")) {
            try replaceOwned(self.allocator, &self.pager, value);
        } else if (std.mem.eql(u8, key, "wireshark-profile")) {
            try replaceOwned(self.allocator, &self.wireshark_profile, value);
        } else return false;
        return true;
    }

    pub fn addRecentFile(self: *Config, path: []const u8) !void {
        var i: usize = 0;
        while (i < self.recent_files.items.len) {
            if (std.mem.eql(u8, self.recent_files.items[i], path)) {
                const old = self.recent_files.orderedRemove(i);
                self.allocator.free(old);
            } else i += 1;
        }
        try self.recent_files.insert(self.allocator, 0, try self.allocator.dupe(u8, path));
        while (self.recent_files.items.len > 20) {
            const old = self.recent_files.pop().?;
            self.allocator.free(old);
        }
    }

    pub fn addRecentFilter(self: *Config, filter: []const u8) !void {
        if (filter.len == 0) return;
        var i: usize = 0;
        while (i < self.recent_filters.items.len) {
            if (std.mem.eql(u8, self.recent_filters.items[i], filter)) {
                const old = self.recent_filters.orderedRemove(i);
                self.allocator.free(old);
            } else i += 1;
        }
        try self.recent_filters.insert(self.allocator, 0, try self.allocator.dupe(u8, filter));
        while (self.recent_filters.items.len > 20) {
            const old = self.recent_filters.pop().?;
            self.allocator.free(old);
        }
    }

    pub fn setProfileName(self: *Config, name: []const u8) !void {
        try replaceOwned(self.allocator, &self.profile, name);
    }

    pub fn setWiresharkProfile(self: *Config, name: []const u8) !void {
        try replaceOwned(self.allocator, &self.wireshark_profile, name);
    }

    pub fn setThemeName(self: *Config, name: []const u8) !void {
        try replaceOwned(self.allocator, &self.theme, name);
    }

    pub fn setColumnFormat(self: *Config, format: []const u8) !void {
        try replaceOwned(self.allocator, &self.column_format, format);
    }

    pub fn setGlobalMark(self: *Config, label: u8, path: []const u8, frame: u32) !void {
        if (label < 'A' or label > 'Z') return;
        for (self.global_marks.items) |*mark| {
            if (mark.label == label) {
                const copy = try self.allocator.dupe(u8, path);
                self.allocator.free(mark.path);
                mark.path = copy;
                mark.frame = frame;
                return;
            }
        }
        try self.global_marks.append(self.allocator, .{
            .label = label,
            .path = try self.allocator.dupe(u8, path),
            .frame = frame,
        });
    }

    pub fn getGlobalMark(self: *const Config, label: u8) ?GlobalMark {
        for (self.global_marks.items) |mark| {
            if (mark.label == label) return mark;
        }
        return null;
    }
};

fn replaceOwned(allocator: std.mem.Allocator, dest: *[]u8, value: []const u8) !void {
    const copy = try allocator.dupe(u8, value);
    if (dest.len != 0) allocator.free(dest.*);
    dest.* = copy;
}

fn parseBool(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "true") or
        std.ascii.eqlIgnoreCase(value, "yes") or
        std.ascii.eqlIgnoreCase(value, "on") or
        std.mem.eql(u8, value, "1");
}

test "parse toml config" {
    const allocator = std.testing.allocator;
    var cfg = try Config.defaults(allocator);
    defer cfg.deinit();
    try cfg.parseToml(
        \\[main]
        \\dark-mode = false
        \\pcap-bundle-size = 500
        \\layout = "side_by_side"
        \\
        \\[recents]
        \\file = "/tmp/a.pcap"
        \\filter = "tcp"
        \\
        \\[marks]
        \\"A" = "42|/tmp/a.pcap"
    );
    try std.testing.expect(!cfg.dark_mode);
    try std.testing.expectEqual(@as(u32, 500), cfg.pcap_bundle_size);
    try std.testing.expect(cfg.layout == .side_by_side);
    try std.testing.expectEqual(@as(usize, 1), cfg.recent_files.items.len);
    try std.testing.expectEqual(@as(u32, 42), cfg.getGlobalMark('A').?.frame);
    try std.testing.expectEqualStrings("/tmp/a.pcap", cfg.getGlobalMark('A').?.path);
    try cfg.applySetting("tshark-args", "-o tcp.check_checksum:true");
    try cfg.applySetting("disk-cache-size-mb", "32");
    try cfg.applySetting("copy-command", "wl-copy");
    try std.testing.expectError(error.UnknownSetting, cfg.applySetting("nope", "1"));
    try std.testing.expectEqualStrings("-o tcp.check_checksum:true", cfg.tshark_args);
    try std.testing.expectEqual(@as(u32, 32), cfg.disk_cache_size_mb);

    const io = std.testing.io;
    const path = "/tmp/zigshark-settings-test.toml";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};
    try cfg.save(io, path);
    var loaded = try Config.loadOrDefault(allocator, io, path);
    defer loaded.deinit();
    try std.testing.expectEqualStrings("wl-copy", loaded.copy_command);
    try std.testing.expectEqual(@as(u32, 32), loaded.disk_cache_size_mb);
    try std.testing.expect(!loaded.dark_mode);
}
