const std = @import("std");
const tools_mod = @import("../shark/tools.zig");
const process = @import("../shark/process.zig");
const packet = @import("packet.zig");
const session_mod = @import("session.zig");
const lru_mod = @import("../cache/lru.zig");

pub const LoaderConfig = struct {
    bundle_size: u32 = 1000,
    cache_size: u32 = 64,
    tshark_args: []const u8 = "",
    column_format: []const u8 = "",
};

pub const Event = union(enum) {
    packets_loaded: packet.PsmlTable,
    detail_loaded: packet.DetailBundle,
    error_msg: []const u8,
    capture_progress: []const u8,
    done,

    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .packets_loaded => |*table| table.deinit(allocator),
            .detail_loaded => |*b| b.deinit(allocator),
            .error_msg => |s| allocator.free(@constCast(s)),
            .capture_progress => |s| allocator.free(@constCast(s)),
            .done => {},
        }
    }
};

const PsmlTask = struct {
    loader: *CaptureLoader,
    argv: process.Argv,
    generation: u64,
};

const DetailTask = struct {
    loader: *CaptureLoader,
    pdml_argv: process.Argv,
    hex_argv: process.Argv,
    frame: u32,
    generation: u64,
};

pub const CaptureLoader = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    tools: *const tools_mod.Tools,
    config: LoaderConfig,
    detail_cache: lru_mod.Lru(u32, packet.DetailBundle),
    events: std.ArrayList(Event),
    event_mutex: std.Io.Mutex = .init,
    workers: std.ArrayList(std.Thread) = .empty,
    list_generation: std.atomic.Value(u64) = .init(0),
    detail_generation: std.atomic.Value(u64) = .init(0),
    cancel_token: process.CancellationToken = .{},
    live_child: ?std.process.Child = null,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        tools: *const tools_mod.Tools,
        config: LoaderConfig,
    ) CaptureLoader {
        var cache = lru_mod.Lru(u32, packet.DetailBundle).init(allocator, config.cache_size);
        cache.on_evict = struct {
            fn cb(a: std.mem.Allocator, _: u32, value: packet.DetailBundle) void {
                var v = value;
                v.deinit(a);
            }
        }.cb;
        return .{
            .allocator = allocator,
            .io = io,
            .tools = tools,
            .config = config,
            .detail_cache = cache,
            .events = .empty,
        };
    }

    pub fn deinit(self: *CaptureLoader, io: std.Io) void {
        self.cancel_token.cancel(io);
        if (self.live_child) |*child| child.kill(io);
        for (self.workers.items) |worker| worker.join();
        self.workers.deinit(self.allocator);
        self.detail_cache.deinit();
        for (self.events.items) |*ev| ev.deinit(self.allocator);
        self.events.deinit(self.allocator);
    }

    pub fn drainEvents(self: *CaptureLoader) ![]Event {
        self.event_mutex.lockUncancelable(self.io);
        defer self.event_mutex.unlock(self.io);
        return try self.events.toOwnedSlice(self.allocator);
    }

    pub fn pushEvent(self: *CaptureLoader, ev: Event) !void {
        self.event_mutex.lockUncancelable(self.io);
        defer self.event_mutex.unlock(self.io);
        try self.events.append(self.allocator, ev);
    }

    pub fn clearDetailCache(self: *CaptureLoader, io: std.Io) void {
        self.detail_cache.clear(io);
    }

    pub fn requestPsml(self: *CaptureLoader, session: *session_mod.Session) !void {
        session.loading = .loading_list;
        self.cancel_token.cancel(self.io);
        const generation = self.list_generation.fetchAdd(1, .acq_rel) + 1;
        self.cancel_token.reset();
        var argv = try process.argvPsmlLoad(
            self.allocator,
            self.tools.tshark,
            session.source,
            session.display_filter,
            if (self.config.column_format.len != 0) self.config.column_format else null,
        );
        errdefer argv.deinit(self.allocator);
        try appendDissectionOptions(self.allocator, &argv, session, self.config.tshark_args);
        if (self.tools.supports_color) try argv.append(self.allocator, "--color");

        const task = try self.allocator.create(PsmlTask);
        errdefer self.allocator.destroy(task);
        task.* = .{
            .loader = self,
            .argv = argv,
            .generation = generation,
        };
        try self.workers.ensureUnusedCapacity(self.allocator, 1);
        const worker = try std.Thread.spawn(.{}, runPsmlWorker, .{task});
        self.workers.appendAssumeCapacity(worker);
    }

    pub fn requestDetail(
        self: *CaptureLoader,
        session: *session_mod.Session,
        frame: u32,
    ) !void {
        const path = self.filePath(session) orelse return error.NoCaptureFile;
        session.loading = .loading_detail;
        self.cancel_token.cancel(self.io);
        const generation = self.detail_generation.fetchAdd(1, .acq_rel) + 1;
        self.cancel_token.reset();

        if (self.detail_cache.get(self.io, frame)) |cached| {
            const copy = try cached.clone(self.allocator);
            try self.pushEvent(.{ .detail_loaded = copy });
            return;
        }

        const end = frame + self.config.bundle_size - 1;
        var pdml_argv = try process.argvPdmlBundle(
            self.allocator,
            self.tools.tshark,
            path,
            session.display_filter,
            frame,
            end,
        );
        errdefer pdml_argv.deinit(self.allocator);
        try appendDissectionOptions(self.allocator, &pdml_argv, session, self.config.tshark_args);

        var hex_argv = try process.argvHexBundle(
            self.allocator,
            self.tools.tshark,
            path,
            session.display_filter,
            frame,
            end,
        );
        errdefer hex_argv.deinit(self.allocator);
        try appendDissectionOptions(self.allocator, &hex_argv, session, self.config.tshark_args);

        const task = try self.allocator.create(DetailTask);
        errdefer self.allocator.destroy(task);
        task.* = .{
            .loader = self,
            .pdml_argv = pdml_argv,
            .hex_argv = hex_argv,
            .frame = frame,
            .generation = generation,
        };
        try self.workers.ensureUnusedCapacity(self.allocator, 1);
        const worker = try std.Thread.spawn(.{}, runDetailWorker, .{task});
        self.workers.appendAssumeCapacity(worker);
    }

    fn filePath(_: *const CaptureLoader, session: *const session_mod.Session) ?[]const u8 {
        return switch (session.source) {
            .file => |p| p,
            .fifo => |p| p,
            .stdin => null,
            .interfaces => if (session.capture_path.len != 0) session.capture_path else null,
        };
    }

    pub const LoadError = error{NoCaptureFile};

    pub fn loadPsml(self: *CaptureLoader, io: std.Io, session: *session_mod.Session) !void {
        session.loading = .loading_list;
        var argv = try process.argvPsmlLoad(
            self.allocator,
            self.tools.tshark,
            session.source,
            session.display_filter,
            if (self.config.column_format.len != 0) self.config.column_format else null,
        );
        defer argv.deinit(self.allocator);
        try appendDissectionOptions(self.allocator, &argv, session, self.config.tshark_args);
        if (self.tools.supports_color) try argv.append(self.allocator, "--color");

        var out = try process.runCapture(self.allocator, io, argv.slice());
        defer out.deinit(self.allocator);
        if (self.cancel_token.isCancelled()) return;
        if (!out.term.success()) {
            try session.setError(out.stderr);
            try self.pushEvent(.{ .error_msg = try self.allocator.dupe(u8, out.stderr) });
            return;
        }

        var table = try packet.parsePsml(self.allocator, out.stdout);
        session.setListHeaders(table.headers);
        table.headers = &.{};
        session.setPackets(table.packets);
        session.loading = .idle;
        try self.pushEvent(.{ .packets_loaded = table });
    }

    pub fn loadDetailBundle(self: *CaptureLoader, io: std.Io, session: *const session_mod.Session, frame: u32) !void {
        const path = self.filePath(session) orelse return error.NoCaptureFile;
        @constCast(session).loading = .loading_detail;
        if (self.detail_cache.get(io, frame)) |cached| {
            const copy = try cached.clone(self.allocator);
            try self.pushEvent(.{ .detail_loaded = copy });
            @constCast(session).loading = .idle;
            return;
        }

        const start = frame;
        const end = frame + self.config.bundle_size - 1;
        var pdml_argv = try process.argvPdmlBundle(self.allocator, self.tools.tshark, path, session.display_filter, start, end);
        defer pdml_argv.deinit(self.allocator);
        try appendDissectionOptions(self.allocator, &pdml_argv, session, self.config.tshark_args);
        var hex_argv = try process.argvHexBundle(self.allocator, self.tools.tshark, path, session.display_filter, start, end);
        defer hex_argv.deinit(self.allocator);
        try appendDissectionOptions(self.allocator, &hex_argv, session, self.config.tshark_args);

        var pdml_out = try process.runCapture(self.allocator, io, pdml_argv.slice());
        defer pdml_out.deinit(self.allocator);
        var hex_out = try process.runCapture(self.allocator, io, hex_argv.slice());
        defer hex_out.deinit(self.allocator);
        if (self.cancel_token.isCancelled()) return;
        if (!pdml_out.term.success()) {
            try self.pushEvent(.{ .error_msg = try self.allocator.dupe(u8, pdml_out.stderr) });
            return;
        }

        const detail = try packet.parsePdmlPacket(self.allocator, pdml_out.stdout, frame);
        const bytes = try packet.parseHexdump(self.allocator, hex_out.stdout, frame);
        const bundle = packet.DetailBundle{ .pdml = detail, .bytes = bytes };
        const for_ui = try bundle.clone(self.allocator);
        try self.detail_cache.put(io, frame, bundle);
        try self.pushEvent(.{ .detail_loaded = for_ui });
        @constCast(session).loading = .idle;
    }

    pub fn prefetchAroundSelection(self: *CaptureLoader, io: std.Io, session: *const session_mod.Session) !void {
        const idx = session.selected_index orelse return;
        const radius: i32 = 3;
        var d: i32 = -radius;
        while (d <= radius) : (d += 1) {
            const i = @as(isize, @intCast(idx)) + @as(isize, d);
            if (i < 0 or i >= session.packets.len) continue;
            const frame = session.packets[@intCast(i)].frame;
            if (self.detail_cache.get(io, frame) == null) {
                try self.loadDetailBundle(io, session, frame);
            }
        }
    }

    pub fn startLiveCapture(
        self: *CaptureLoader,
        io: std.Io,
        session: *session_mod.Session,
        interfaces: []const []const u8,
        temp_path: []const u8,
    ) !void {
        if (interfaces.len == 0) return error.NoCaptureInterface;
        session.loading = .capturing;
        if (session.capture_path.len != 0) self.allocator.free(session.capture_path);
        session.capture_path = try self.allocator.dupe(u8, temp_path);
        session.source = .{ .fifo = session.capture_path };

        var argv: process.Argv = undefined;
        if (self.tools.dumpcap_can_capture) {
            argv = try process.argvDumpcapLive(self.allocator, self.tools.dumpcap, interfaces, temp_path, session.capture_filter);
        } else {
            try session.setError(tools_mod.dumpcapPermissionMessage());
            try self.pushEvent(.{ .error_msg = try self.allocator.dupe(u8, tools_mod.dumpcapPermissionMessage()) });
            argv = try process.argvTsharkLiveFallback(self.allocator, self.tools.tshark, interfaces, temp_path, session.capture_filter);
        }
        defer argv.deinit(self.allocator);

        self.live_child = try std.process.spawn(io, .{
            .argv = argv.slice(),
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
        });
        try self.pushEvent(.{ .capture_progress = try self.allocator.dupe(u8, "capture started") });
    }

    pub fn pollLiveCapture(self: *CaptureLoader, io: std.Io) !void {
        var child = self.live_child orelse return;
        const term = child.wait(io) catch return;
        self.live_child = null;
        if (!term.success()) {
            try self.pushEvent(.{ .error_msg = try self.allocator.dupe(u8, "capture process exited with failure") });
            return;
        }
        try self.pushEvent(.done);
    }

    pub fn cancel(self: *CaptureLoader, io: std.Io) void {
        self.cancel_token.cancel(io);
        self.stopLiveCapture(io);
    }

    pub fn stopLiveCapture(self: *CaptureLoader, io: std.Io) void {
        if (self.live_child) |*child| child.kill(io);
        self.live_child = null;
    }
};

fn runPsmlWorker(task: *PsmlTask) void {
    const loader = task.loader;
    defer {
        task.argv.deinit(loader.allocator);
        loader.allocator.destroy(task);
    }

    var output = process.runCaptureCancellable(
        loader.allocator,
        loader.io,
        task.argv.slice(),
        &loader.cancel_token,
    ) catch |err| {
        if (err == error.Cancelled or task.generation != loader.list_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    defer output.deinit(loader.allocator);
    if (task.generation != loader.list_generation.load(.acquire)) return;
    if (!output.term.success()) {
        emitWorkerError(loader, output.stderr);
        return;
    }

    var table = packet.parsePsml(loader.allocator, output.stdout) catch |err| {
        emitWorkerError(loader, @errorName(err));
        return;
    };
    if (loader.cancel_token.isCancelled() or
        task.generation != loader.list_generation.load(.acquire))
    {
        table.deinit(loader.allocator);
        return;
    }
    var event: Event = .{ .packets_loaded = table };
    loader.pushEvent(event) catch {
        event.deinit(loader.allocator);
    };
}

fn runDetailWorker(task: *DetailTask) void {
    const loader = task.loader;
    defer {
        task.pdml_argv.deinit(loader.allocator);
        task.hex_argv.deinit(loader.allocator);
        loader.allocator.destroy(task);
    }

    var pdml_output = process.runCaptureCancellable(
        loader.allocator,
        loader.io,
        task.pdml_argv.slice(),
        &loader.cancel_token,
    ) catch |err| {
        if (err == error.Cancelled or task.generation != loader.detail_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    defer pdml_output.deinit(loader.allocator);
    if (!pdml_output.term.success()) {
        emitWorkerError(loader, pdml_output.stderr);
        return;
    }

    var hex_output = process.runCaptureCancellable(
        loader.allocator,
        loader.io,
        task.hex_argv.slice(),
        &loader.cancel_token,
    ) catch |err| {
        if (err == error.Cancelled or task.generation != loader.detail_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    defer hex_output.deinit(loader.allocator);
    if (!hex_output.term.success()) {
        emitWorkerError(loader, hex_output.stderr);
        return;
    }

    const detail = packet.parsePdmlPacket(
        loader.allocator,
        pdml_output.stdout,
        task.frame,
    ) catch |err| {
        emitWorkerError(loader, @errorName(err));
        return;
    };
    const bytes = packet.parseHexdump(
        loader.allocator,
        hex_output.stdout,
        task.frame,
    ) catch |err| {
        var mutable_detail = detail;
        mutable_detail.deinit(loader.allocator);
        emitWorkerError(loader, @errorName(err));
        return;
    };
    var bundle = packet.DetailBundle{ .pdml = detail, .bytes = bytes };

    if (loader.cancel_token.isCancelled() or
        task.generation != loader.detail_generation.load(.acquire))
    {
        bundle.deinit(loader.allocator);
        return;
    }

    const ui_copy = bundle.clone(loader.allocator) catch |err| {
        bundle.deinit(loader.allocator);
        emitWorkerError(loader, @errorName(err));
        return;
    };
    loader.detail_cache.put(loader.io, task.frame, bundle) catch |err| {
        var mutable_copy = ui_copy;
        mutable_copy.deinit(loader.allocator);
        bundle.deinit(loader.allocator);
        emitWorkerError(loader, @errorName(err));
        return;
    };
    var event: Event = .{ .detail_loaded = ui_copy };
    loader.pushEvent(event) catch {
        event.deinit(loader.allocator);
    };
}

fn emitWorkerError(loader: *CaptureLoader, message: []const u8) void {
    const copy = loader.allocator.dupe(u8, message) catch return;
    var event: Event = .{ .error_msg = copy };
    loader.pushEvent(event) catch {
        event.deinit(loader.allocator);
    };
}

fn appendDissectionOptions(
    allocator: std.mem.Allocator,
    argv: *process.Argv,
    session: *const session_mod.Session,
    configured_args: []const u8,
) !void {
    if (session.timestamp_format.len != 0) {
        try argv.append(allocator, "-t");
        try argv.append(allocator, session.timestamp_format);
    }
    if (session.wireshark_profile.len != 0) {
        try argv.append(allocator, "-C");
        try argv.append(allocator, session.wireshark_profile);
    }
    for (session.decode_as_args.items) |decode_as| {
        try argv.append(allocator, "-d");
        try argv.append(allocator, decode_as);
    }
    var extra = std.mem.tokenizeAny(u8, configured_args, " \t\r\n");
    while (extra.next()) |arg| try argv.append(allocator, arg);
}

test "load psml from fixture file" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var cfg_tools = tools_mod.Tools{
        .allocator = allocator,
        .tshark = try allocator.dupe(u8, "tshark"),
        .dumpcap = try allocator.dupe(u8, "dumpcap"),
        .capinfos = try allocator.dupe(u8, "capinfos"),
        .tshark_version = try allocator.dupe(u8, "4.0.0"),
        .dumpcap_version = try allocator.dupe(u8, ""),
        .capinfos_version = try allocator.dupe(u8, ""),
        .supports_color = false,
        .dumpcap_can_capture = false,
    };
    defer cfg_tools.deinit();

    if (!tools_mod.tsharkAvailable(io)) {
        var session = session_mod.Session.init(allocator, .{ .file = "tests/fixtures/1.pcap" });
        defer session.deinit();
        const cwd = std.Io.Dir.cwd();
        const xml = try cwd.readFileAlloc(io, "tests/fixtures/1.psml", allocator, .unlimited);
        defer allocator.free(xml);
        var table = try packet.parsePsml(allocator, xml);
        session.setListHeaders(table.headers);
        table.headers = &.{};
        session.setPackets(table.packets);
        table.packets = &.{};
        try std.testing.expect(session.packets.len > 0);
        return;
    }

    var loader = CaptureLoader.init(allocator, io, &cfg_tools, .{});
    defer loader.deinit(io);

    var session = session_mod.Session.init(allocator, .{ .file = "tests/fixtures/1.pcap" });
    defer session.deinit();

    try loader.loadPsml(io, &session);
    try std.testing.expect(session.packets.len > 0);
    const events = try loader.drainEvents();
    defer {
        for (events) |*ev| {
            // Session owns packet summaries after loadPsml; do not free them via the event.
            if (ev.* == .packets_loaded) ev.* = .done;
            ev.deinit(allocator);
        }
        allocator.free(events);
    }
    try std.testing.expect(events.len >= 1);
}

test "detail cache releases owned bundles" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    if (!tools_mod.tsharkAvailable(io)) return error.SkipZigTest;

    var cfg_tools = try tools_mod.discover(allocator, io, .{
        .tshark = "tshark",
        .dumpcap = "dumpcap",
        .capinfos = "capinfos",
    });
    defer cfg_tools.deinit();

    var loader = CaptureLoader.init(allocator, io, &cfg_tools, .{ .bundle_size = 1, .cache_size = 2 });
    defer loader.deinit(io);

    var session = session_mod.Session.init(allocator, .{ .file = "tests/fixtures/1.pcap" });
    defer session.deinit();
    try loader.loadDetailBundle(io, &session, 1);
    try std.testing.expectEqual(@as(usize, 1), loader.detail_cache.len(io));

    const events = try loader.drainEvents();
    defer allocator.free(events);
    for (events) |*event| event.deinit(allocator);
}

test "asynchronous summary request returns owned event" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    if (!tools_mod.tsharkAvailable(io)) return error.SkipZigTest;

    var cfg_tools = try tools_mod.discover(allocator, io, .{
        .tshark = "tshark",
        .dumpcap = "dumpcap",
        .capinfos = "capinfos",
    });
    defer cfg_tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &cfg_tools, .{});
    defer loader.deinit(io);
    var session = session_mod.Session.init(allocator, .{ .file = "tests/fixtures/1.pcap" });
    defer session.deinit();

    try loader.requestPsml(&session);
    const worker = loader.workers.pop().?;
    worker.join();
    const events = try loader.drainEvents();
    defer allocator.free(events);
    try std.testing.expectEqual(@as(usize, 1), events.len);
    switch (events[0]) {
        .packets_loaded => |table| try std.testing.expectEqual(@as(usize, 18), table.packets.len),
        else => return error.UnexpectedEvent,
    }
    for (events) |*event| event.deinit(allocator);
}
