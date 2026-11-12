const std = @import("std");
const app = @import("../app.zig");
const process_mod = @import("../../shark/process.zig");
const stats_mod = @import("../../shark/stats.zig");
const expert_mod = @import("../expert.zig");
const streams_shark = @import("../../shark/streams.zig");
const convs_shark = @import("../../shark/convs.zig");

const AppModel = app.AppModel;
const OverlayKind = app.OverlayKind;

fn streamDisplayFilter(allocator: std.mem.Allocator, proto: []const u8, index: u32) ![]u8 {
    var lower: [16]u8 = undefined;
    const name = if (proto.len <= lower.len) std.ascii.lowerString(lower[0..proto.len], proto) else proto;
    return std.fmt.allocPrint(allocator, "{s}.stream == {d}", .{ name, index });
}

pub fn showExpert(self: *AppModel, args: []const u8) !void {
    const which = std.mem.trim(u8, args, " \t");
    if (which.len == 0) {
        try showOpenPacketExpert(self);
        return;
    }
    if (std.mem.eql(u8, which, "all")) {
        try showFileExpert(self);
        return;
    }
    try self.showMessage("Usage: :expert [all]");
}

fn showOpenPacketExpert(self: *AppModel) !void {
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

fn showFileExpert(self: *AppModel) !void {
    const path = self.capturePath() orelse {
        try self.showMessage("No capture file loaded");
        return;
    };
    self.clearExpert();
    var argv = try process_mod.argvExpert(self.allocator, self.tools.tshark, path);
    defer argv.deinit(self.allocator);
    var out = try self.runProcessLimited(argv.slice(), process_mod.view_stdout_cap);
    defer out.deinit(self.allocator);
    if (!out.term.success() and out.stdout.len == 0) {
        try self.showMessage(if (out.stderr.len != 0) out.stderr else "Expert info failed");
        return;
    }
    const rows = try expert_mod.parseFile(self.allocator, out.stdout);
    defer {
        for (rows) |*row| {
            var copy = row.*;
            copy.deinit(self.allocator);
        }
        self.allocator.free(rows);
    }
    const shown = @min(rows.len, process_mod.view_row_cap);
    self.freeStringList(&self.stat_filters);
    const filters = try self.allocator.alloc([]u8, shown);
    var filled: usize = 0;
    var stored = false;
    errdefer if (!stored) {
        for (filters[0..filled]) |filter| self.allocator.free(filter);
        self.allocator.free(filters);
    };
    var text: std.Io.Writer.Allocating = .init(self.allocator);
    defer text.deinit();
    if (shown == 0) try text.writer.writeAll("No expert info in this capture");
    for (rows[0..shown], 0..) |row, index| {
        filters[index] = try self.allocator.dupe(u8, row.summary);
        filled += 1;
        if (index != 0) try text.writer.writeByte('\n');
        try text.writer.print("{s}  {s}", .{ expert_mod.label(row.severity), row.summary });
    }
    try writeCapNote(&text.writer, out.truncated, shown < rows.len);
    self.stat_filters = filters;
    stored = true;
    const owned = try text.toOwnedSlice();
    defer self.allocator.free(owned);
    try self.showPick("Expert  Enter selects the frame", owned, .expert_file);
}

pub fn firstExpertFrame(self: *AppModel, summary: []const u8) !?u32 {
    const path = self.capturePath() orelse return null;
    const filter = try expertMessageFilter(self.allocator, summary);
    defer self.allocator.free(filter);
    var argv = try process_mod.argvFieldDump(self.allocator, self.tools.tshark, path, filter, &.{"frame.number"});
    defer argv.deinit(self.allocator);
    var out = try self.runProcessLimited(argv.slice(), process_mod.view_stdout_cap);
    defer out.deinit(self.allocator);
    var lines = std.mem.splitAny(u8, out.stdout, "\n\r");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0) continue;
        return std.fmt.parseInt(u32, line, 10) catch continue;
    }
    return null;
}

fn expertMessageFilter(allocator: std.mem.Allocator, summary: []const u8) ![]u8 {
    var escaped: std.Io.Writer.Allocating = .init(allocator);
    errdefer escaped.deinit();
    for (summary) |char| {
        if (char == '\\' or char == '"') try escaped.writer.writeByte('\\');
        try escaped.writer.writeByte(char);
    }
    const body = try escaped.toOwnedSlice();
    defer allocator.free(body);
    return std.fmt.allocPrint(allocator, "_ws.expert.message == \"{s}\"", .{body});
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
    try showFieldTable(
        self,
        &.{ "frame.number", "dns.qry.name", "dns.flags.rcode" },
        "",
        stats_mod.parseDnsTable,
        "DNS  Enter filters that name",
        .dns,
    );
}

pub fn showHttp(self: *AppModel) !void {
    try showFieldTable(
        self,
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
    try installStatRows(self, rows, out.truncated, title, kind);
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
    for (rows) |*row| {
        if (row.filter.len != 0) continue;
        const frame = frameFromOnlyThere(row.label) orelse continue;
        const encoded = try std.fmt.allocPrint(self.allocator, "other\t{d}\t{s}", .{ frame, other });
        self.allocator.free(row.filter);
        row.filter = encoded;
    }
    const shown = @min(rows.len, process_mod.view_row_cap);
    try installStatRows(self, rows[0..shown], here.truncated or there.truncated or shown < rows.len, "Compare  Enter selects the frame", .compare);
}

fn frameFromOnlyThere(label: []const u8) ?u32 {
    const prefix = "only there  ";
    if (!std.mem.startsWith(u8, label, prefix)) return null;
    const rest = label[prefix.len..];
    const end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    if (end == 0) return null;
    return std.fmt.parseInt(u32, rest[0..end], 10) catch null;
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
    const note = std.mem.trim(u8, args, " \t");
    if (std.mem.eql(u8, note, "list")) {
        try listPacketComments(self);
        return;
    }
    const path = self.capturePath() orelse {
        try self.showMessage("No capture file loaded");
        return;
    };
    const frame = self.session.selectedFrame() orelse {
        try self.showMessage("Select a packet first");
        return;
    };
    if (note.len == 0) {
        const filter = try std.fmt.allocPrint(self.allocator, "frame.number == {d}", .{frame});
        defer self.allocator.free(filter);
        var argv = try process_mod.argvFieldDump(self.allocator, self.tools.tshark, path, filter, &.{"frame.comment"});
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

fn listPacketComments(self: *AppModel) !void {
    const path = self.capturePath() orelse {
        try self.showMessage("No capture file loaded");
        return;
    };
    var argv = try process_mod.argvFieldDump(
        self.allocator,
        self.tools.tshark,
        path,
        "frame.comment",
        &.{ "frame.number", "frame.comment" },
    );
    defer argv.deinit(self.allocator);
    var out = try self.runProcessLimited(argv.slice(), process_mod.view_stdout_cap);
    defer out.deinit(self.allocator);
    if (!out.term.success() and out.stdout.len == 0) {
        try self.showMessage(if (out.stderr.len != 0) out.stderr else "Could not list packet comments");
        return;
    }

    self.freeStringList(&self.stat_filters);
    var frames: std.ArrayList([]u8) = .empty;
    var stored = false;
    errdefer if (!stored) {
        for (frames.items) |item| self.allocator.free(item);
        frames.deinit(self.allocator);
    };
    var text: std.Io.Writer.Allocating = .init(self.allocator);
    defer text.deinit();
    var rows: usize = 0;
    var skipped_extra = false;
    var lines = std.mem.splitScalar(u8, out.stdout, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        const tab = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
        const frame_text = std.mem.trim(u8, line[0..tab], " \t");
        const comment = std.mem.trim(u8, line[tab + 1 ..], " \t");
        if (frame_text.len == 0 or comment.len == 0) continue;
        _ = std.fmt.parseInt(u32, frame_text, 10) catch continue;
        if (rows >= process_mod.view_row_cap) {
            skipped_extra = true;
            break;
        }
        const copy = try self.allocator.dupe(u8, frame_text);
        frames.append(self.allocator, copy) catch |err| {
            self.allocator.free(copy);
            return err;
        };
        if (rows != 0) try text.writer.writeByte('\n');
        try text.writer.print("{s}  {s}", .{ frame_text, comment });
        rows += 1;
    }
    if (rows == 0) {
        try self.showMessage("No packet comments");
        return;
    }
    try writeCapNote(&text.writer, out.truncated, skipped_extra);
    self.stat_filters = try frames.toOwnedSlice(self.allocator);
    stored = true;
    const owned = try text.toOwnedSlice();
    defer self.allocator.free(owned);
    try self.showPick("Comments  Enter selects the frame", owned, .comment_list);
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

pub fn acceptExport(self: *AppModel) !void {
    const args = self.export_request;
    self.export_request = &.{};
    self.export_confirm = false;
    self.dismissOverlays();
    defer self.allocator.free(args);
    try runExport(self, args, true);
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
        try exportObjects(self, protocol, directory);
        return;
    }
    const out_path = parts.next() orelse {
        try self.showMessage("Usage: :export packets|packet|json|csv <path>");
        return;
    };
    if (!force and try pathExists(self, out_path)) {
        try askOverwrite(self, trimmed);
        return;
    }
    if (std.mem.eql(u8, command, "json")) {
        try writeDisplayed(self, out_path, true);
    } else if (std.mem.eql(u8, command, "csv")) {
        try writeDisplayed(self, out_path, false);
    } else if (std.mem.eql(u8, command, "packets")) {
        try exportPcap(self, out_path, null);
    } else if (std.mem.eql(u8, command, "packet")) {
        const frame = self.session.selectedFrame() orelse {
            try self.showMessage("Select a packet first");
            return;
        };
        try exportPcap(self, out_path, frame);
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

pub fn applyOpenStreamFilter(self: *AppModel) !void {
    if (self.stream_list_filter.len == 0) {
        try self.showMessage("Follow a stream first");
        return;
    }
    const filter = try self.allocator.dupe(u8, self.stream_list_filter);
    defer self.allocator.free(filter);
    self.dismissOverlays();
    try self.commitFilter(filter, true);
}

pub fn showStream(self: *AppModel, proto: []const u8, index: u32, body: []const u8, capped: bool) !void {
    const listed = try streamDisplayFilter(self.allocator, proto, index);
    if (self.stream_list_filter.len != 0) self.allocator.free(self.stream_list_filter);
    self.stream_list_filter = listed;
    if (self.stream_filter.len != 0) self.allocator.free(self.stream_filter);
    self.stream_filter = try std.fmt.allocPrint(self.allocator, "{s}.stream == {d}", .{ proto, index });
    var parsed = streams_shark.parseYaml(self.allocator, body) catch streams_shark.parse(self.allocator, body) catch {
        const shown = try capText(self.allocator, body, capped, false);
        defer self.allocator.free(shown);
        try self.showPick("Stream  f filters", shown, .streams);
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
    const row_capped = try trimStreamChunks(self);
    var text: std.Io.Writer.Allocating = .init(self.allocator);
    defer text.deinit();
    if (self.stream_chunks.len == 0) {
        try text.writer.writeAll(body);
    } else {
        const diagram = try streams_shark.sequenceDiagram(self.allocator, self.stream_chunks);
        defer self.allocator.free(diagram);
        try text.writer.writeAll(diagram);
    }
    try writeCapNote(&text.writer, capped, row_capped);
    const owned = try text.toOwnedSlice();
    defer self.allocator.free(owned);
    var known_frame = false;
    for (self.stream_chunks) |chunk| {
        if (chunk.frame != null) known_frame = true;
    }
    try self.showPick(if (known_frame)
        "Stream  f filters  Enter selects"
    else
        "Stream  f filters  Enter guesses", owned, .streams);
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
    const row_capped = try trimConversations(self);
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
