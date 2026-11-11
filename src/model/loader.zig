const std = @import("std");
const tools_mod = @import("../shark/tools.zig");
const process = @import("../shark/process.zig");
const packet = @import("packet.zig");
const session_mod = @import("session.zig");
const lru_mod = @import("../cache/lru.zig");
const psml = @import("../shark/psml.zig");
const log_mod = @import("../log.zig");

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
    /// Headless tests record the PSML argv and skip worker threads.
    defer_spawn: bool = false,
    psml_argv: process.Argv = .{},
    has_psml_argv: bool = false,

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
        if (self.has_psml_argv) self.psml_argv.deinit(self.allocator);
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

    pub fn setCacheSize(self: *CaptureLoader, size: u32) void {
        self.config.cache_size = @max(size, 1);
        self.detail_cache.setCapacity(self.io, self.config.cache_size);
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

        if (self.defer_spawn) {
            if (self.has_psml_argv) self.psml_argv.deinit(self.allocator);
            self.psml_argv = argv;
            self.has_psml_argv = true;
            return;
        }

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
        if (self.defer_spawn) return;
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

        const window = detailWindow(frame, self.config.bundle_size, self.config.cache_size);
        var pdml_argv = try process.argvPdmlBundle(
            self.allocator,
            self.tools.tshark,
            path,
            session.display_filter,
            window.start,
            window.end,
        );
        errdefer pdml_argv.deinit(self.allocator);
        try appendDissectionOptions(self.allocator, &pdml_argv, session, self.config.tshark_args);

        var hex_argv = try process.argvHexBundle(
            self.allocator,
            self.tools.tshark,
            path,
            session.display_filter,
            window.start,
            window.end,
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

        const window = detailWindow(frame, self.config.bundle_size, self.config.cache_size);
        var pdml_argv = try process.argvPdmlBundle(self.allocator, self.tools.tshark, path, session.display_filter, window.start, window.end);
        defer pdml_argv.deinit(self.allocator);
        try appendDissectionOptions(self.allocator, &pdml_argv, session, self.config.tshark_args);
        var hex_argv = try process.argvHexBundle(self.allocator, self.tools.tshark, path, session.display_filter, window.start, window.end);
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

        const started = std.Io.Timestamp.now(io, .awake).nanoseconds;
        try ingestDetail(self, pdml_out.stdout, hex_out.stdout, frame, null);
        const elapsed_ms = @divTrunc(std.Io.Timestamp.now(io, .awake).nanoseconds -| started, std.time.ns_per_ms);
        log_mod.info("detail", "frame {d} loaded in {d} ms", .{ frame, elapsed_ms });
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
        if (self.live_child) |*child| {
            if (child.id != null) child.kill(io);
        }
        self.live_child = null;
    }
};

fn runPsmlWorker(task: *PsmlTask) void {
    const loader = task.loader;
    defer {
        task.argv.deinit(loader.allocator);
        loader.allocator.destroy(task);
    }

    var feed = PsmlFeed.init(loader, task.generation);
    defer feed.deinit();
    var saw_stdout = false;
    var output = process.runStdoutChunks(
        loader.allocator,
        loader.io,
        task.argv.slice(),
        &loader.cancel_token,
        &feed,
        PsmlFeed.onChunk,
        &saw_stdout,
    ) catch |err| {
        if (err == error.Cancelled or task.generation != loader.list_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    defer output.deinit(loader.allocator);
    if (task.generation != loader.list_generation.load(.acquire) or loader.cancel_token.isCancelled()) return;

    feed.finish() catch |err| {
        if (err == error.Cancelled or task.generation != loader.list_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    if (!output.term.success()) {
        emitWorkerError(loader, output.stderr);
        return;
    }
    loader.pushEvent(.done) catch {};
}

const PsmlFeed = struct {
    loader: *CaptureLoader,
    generation: u64,
    started_ns: i96,
    pending: std.ArrayList(u8) = .empty,
    batch: std.ArrayList(packet.PacketSummary) = .empty,
    headers: [][]u8 = &.{},
    headers_sent: bool = false,
    replace_next: bool = true,
    emitted_rows: usize = 0,

    fn init(loader: *CaptureLoader, generation: u64) PsmlFeed {
        return .{
            .loader = loader,
            .generation = generation,
            .started_ns = std.Io.Timestamp.now(loader.io, .awake).nanoseconds,
        };
    }

    fn deinit(self: *PsmlFeed) void {
        const allocator = self.loader.allocator;
        self.pending.deinit(allocator);
        for (self.batch.items) |*summary| summary.deinit(allocator);
        self.batch.deinit(allocator);
        for (self.headers) |header| allocator.free(header);
        if (self.headers.len != 0) allocator.free(self.headers);
    }

    fn onChunk(ctx: *anyopaque, chunk: []const u8) anyerror!void {
        const self: *PsmlFeed = @ptrCast(@alignCast(ctx));
        if (self.generation != self.loader.list_generation.load(.acquire)) return error.Cancelled;
        try self.pending.appendSlice(self.loader.allocator, chunk);
        try self.drain(false);
    }

    fn finish(self: *PsmlFeed) !void {
        try self.drain(true);
        if (!self.headers_sent and self.headers.len != 0) try self.emit(0, true);
    }

    fn drain(self: *PsmlFeed, flush: bool) !void {
        const allocator = self.loader.allocator;
        var available = try psml.parseAvailable(allocator, self.pending.items);
        defer available.deinit(allocator);
        if (available.headers.len != 0 and self.headers.len == 0 and !self.headers_sent) {
            self.headers = available.headers;
            available.headers = &.{};
        }
        for (available.packets) |*source| {
            const summary = try packet.summaryFromPsml(allocator, source);
            try self.batch.append(allocator, summary);
        }
        self.dropPending(available.consumed);

        const bundle = @max(self.loader.config.bundle_size, 1);
        while (self.batch.items.len >= bundle) {
            try self.emit(bundle, false);
        }
        if (flush and self.batch.items.len != 0) try self.emit(self.batch.items.len, false);
    }

    fn emit(self: *PsmlFeed, count: usize, headers_only: bool) !void {
        if (self.generation != self.loader.list_generation.load(.acquire)) return error.Cancelled;
        const allocator = self.loader.allocator;
        const packets = if (headers_only)
            try allocator.alloc(packet.PacketSummary, 0)
        else blk: {
            const n = @min(count, self.batch.items.len);
            const slice = try allocator.alloc(packet.PacketSummary, n);
            @memcpy(slice, self.batch.items[0..n]);
            std.mem.copyForwards(packet.PacketSummary, self.batch.items[0 .. self.batch.items.len - n], self.batch.items[n..]);
            self.batch.shrinkRetainingCapacity(self.batch.items.len - n);
            break :blk slice;
        };
        var headers: [][]u8 = &.{};
        if (!self.headers_sent) {
            headers = self.headers;
            self.headers = &.{};
            self.headers_sent = true;
        }
        var table = packet.PsmlTable{
            .headers = headers,
            .packets = packets,
            .append = !self.replace_next,
        };
        self.replace_next = false;
        self.emitted_rows += table.packets.len;
        const elapsed_ms = @divTrunc(std.Io.Timestamp.now(self.loader.io, .awake).nanoseconds -| self.started_ns, std.time.ns_per_ms);
        log_mod.info("psml", "{d} rows after {d} ms", .{ self.emitted_rows, elapsed_ms });
        self.loader.pushEvent(.{ .packets_loaded = table }) catch |err| {
            table.deinit(allocator);
            return err;
        };
    }

    fn dropPending(self: *PsmlFeed, consumed: usize) void {
        if (consumed == 0) return;
        if (consumed >= self.pending.items.len) {
            self.pending.clearRetainingCapacity();
            return;
        }
        std.mem.copyForwards(u8, self.pending.items[0 .. self.pending.items.len - consumed], self.pending.items[consumed..]);
        self.pending.shrinkRetainingCapacity(self.pending.items.len - consumed);
    }
};

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
    if (loader.cancel_token.isCancelled() or task.generation != loader.detail_generation.load(.acquire)) return;

    const started = std.Io.Timestamp.now(loader.io, .awake).nanoseconds;
    ingestDetail(loader, pdml_output.stdout, hex_output.stdout, task.frame, task.generation) catch |err| {
        if (err == error.Cancelled or task.generation != loader.detail_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    const elapsed_ms = @divTrunc(std.Io.Timestamp.now(loader.io, .awake).nanoseconds -| started, std.time.ns_per_ms);
    log_mod.info("detail", "frame {d} loaded in {d} ms", .{ task.frame, elapsed_ms });
}

fn ingestDetail(
    self: *CaptureLoader,
    pdml_xml: []const u8,
    hex_text: []const u8,
    requested: u32,
    generation: ?u64,
) !void {
    if (generation) |expected| {
        if (expected != self.detail_generation.load(.acquire) or self.cancel_token.isCancelled()) return error.Cancelled;
    }
    const details = try packet.parsePdmlPackets(self.allocator, pdml_xml);
    var detail_kept = try self.allocator.alloc(bool, details.len);
    defer self.allocator.free(detail_kept);
    @memset(detail_kept, false);
    defer {
        for (details, detail_kept) |*detail, kept| if (!kept) detail.deinit(self.allocator);
        self.allocator.free(details);
    }

    const dumps = try packet.parseHexdumpPackets(self.allocator, hex_text);
    var dump_kept = try self.allocator.alloc(bool, dumps.len);
    defer self.allocator.free(dump_kept);
    @memset(dump_kept, false);
    defer {
        for (dumps, dump_kept) |*dump, kept| if (!kept) dump.deinit(self.allocator);
        self.allocator.free(dumps);
    }

    var ui_copy: ?packet.DetailBundle = null;
    errdefer if (ui_copy) |*copy| copy.deinit(self.allocator);

    for (details, 0..) |*detail, index| {
        if (generation) |expected| {
            if (expected != self.detail_generation.load(.acquire) or self.cancel_token.isCancelled()) return error.Cancelled;
        }
        const bytes = if (index < dumps.len) dumps[index] else packet.PacketBytes{
            .frame = detail.frame,
            .raw = try self.allocator.alloc(u8, 0),
            .hexdump_lines = try self.allocator.alloc([]const u8, 0),
        };
        if (index < dumps.len) dump_kept[index] = true;
        detail_kept[index] = true;
        var bundle = packet.DetailBundle{ .pdml = detail.*, .bytes = bytes };
        bundle.bytes.frame = bundle.pdml.frame;

        if (bundle.pdml.frame == requested and ui_copy == null) {
            ui_copy = bundle.clone(self.allocator) catch |err| {
                bundle.deinit(self.allocator);
                return err;
            };
        }
        if (self.detail_cache.get(self.io, bundle.pdml.frame) == null) {
            self.detail_cache.put(self.io, bundle.pdml.frame, bundle) catch |err| {
                bundle.deinit(self.allocator);
                return err;
            };
        } else {
            bundle.deinit(self.allocator);
        }
    }

    const copy = ui_copy orelse return error.UnexpectedEnd;
    ui_copy = null;
    var event: Event = .{ .detail_loaded = copy };
    self.pushEvent(event) catch |err| {
        event.deinit(self.allocator);
        return err;
    };
}

const DetailWindow = struct { start: u32, end: u32 };

fn detailWindow(frame: u32, bundle_size: u32, cache_size: u32) DetailWindow {
    const cache = @max(cache_size, 1);
    if (cache <= 1) return .{ .start = frame, .end = frame };
    const bundle = @max(bundle_size, 1);
    const back: u32 = if (frame > 1) 1 else 0;
    var forward: u32 = if (bundle <= 1) 1 else bundle - 1;
    const room = cache - 1;
    if (back + forward > room) forward = if (room > back) room - back else 0;
    return .{ .start = frame - back, .end = frame + forward };
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
    try std.testing.expectEqual(@as(usize, 2), loader.detail_cache.len(io));
    try std.testing.expect(loader.detail_cache.get(io, 1) != null);
    try std.testing.expect(loader.detail_cache.get(io, 2) != null);

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
    var packets: usize = 0;
    for (events) |event| switch (event) {
        .packets_loaded => |table| {
            packets += 1;
            try std.testing.expectEqual(@as(usize, 18), table.packets.len);
            try std.testing.expect(!table.append);
        },
        .done => {},
        else => return error.UnexpectedEvent,
    };
    try std.testing.expectEqual(@as(usize, 1), packets);
    for (events) |*event| event.deinit(allocator);
}

const fake_tshark =
    \\#!/bin/bash
    \\path=
    \\prev=
    \\for arg in "$@"; do
    \\  if [ "$prev" = "-r" ]; then
    \\    path=$arg
    \\  fi
    \\  prev=$arg
    \\done
    \\case "$path" in
    \\  *hold*)
    \\    echo started > "$path.started"
    \\    while [ ! -f "$path.release" ]; do
    \\      :
    \\    done
    \\    printf '%s\n' '<psml><packet><section>1</section></packet></psml>'
    \\    ;;
    \\  *slow*)
    \\    echo started > "$path.started"
    \\    start=$SECONDS
    \\    while (( SECONDS - start < 5 )); do
    \\      :
    \\    done
    \\    echo finished > "$path.finished"
    \\    printf '%s\n' '<psml><packet><section>4</section></packet></psml>'
    \\    ;;
    \\  *)
    \\    printf '%s\n' '<psml><packet><section>9</section></packet></psml>'
    \\    ;;
    \\esac
    \\exit 0
;

fn writeExecutable(io: std.Io, path: []const u8, body: []const u8) !void {
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = body,
        .flags = .{ .permissions = @fromBackingInt(@intCast(0o755)) },
    });
}

fn waitForPath(io: std.Io, path: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    var spins: usize = 0;
    while (spins < 100) : (spins += 1) {
        if (cwd.access(io, path, .{})) |_| return else |_| {
            try std.Io.sleep(io, .fromMilliseconds(20), .awake);
        }
    }
    return error.TimedOut;
}

fn joinWorkers(loader: *CaptureLoader) void {
    while (loader.workers.pop()) |worker| worker.join();
}

fn testingTools(allocator: std.mem.Allocator, tshark: []const u8) !tools_mod.Tools {
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

fn ownedBundle(allocator: std.mem.Allocator, frame: u32) !packet.DetailBundle {
    return .{
        .pdml = .{
            .frame = frame,
            .root = .{
                .name = try allocator.dupe(u8, "frame"),
                .showname = try allocator.dupe(u8, ""),
                .show = try std.fmt.allocPrint(allocator, "{d}", .{frame}),
                .pos = 0,
                .size = 1,
                .children = try allocator.alloc(packet.DetailNode, 0),
            },
        },
        .bytes = .{
            .frame = frame,
            .raw = try allocator.dupe(u8, "ab"),
            .hexdump_lines = try allocator.alloc([]const u8, 0),
        },
    };
}

test "stale psml generation is dropped and a second request cancels the first child" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const script_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/tshark", .{tmp.sub_path[0..]});
    defer allocator.free(script_path);
    const hold_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/hold.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(hold_path);
    const slow_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/slow.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(slow_path);
    const fast_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/fast.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(fast_path);
    try writeExecutable(io, script_path, fake_tshark);

    var tools = try testingTools(allocator, script_path);
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &tools, .{});
    defer {
        joinWorkers(&loader);
        loader.deinit(io);
    }

    var session = session_mod.Session.init(allocator, .{ .file = hold_path });
    defer session.deinit();
    try loader.requestPsml(&session);
    const started = try std.fmt.allocPrint(allocator, "{s}.started", .{hold_path});
    defer allocator.free(started);
    try waitForPath(io, started);
    _ = loader.list_generation.fetchAdd(1, .acq_rel);
    const release = try std.fmt.allocPrint(allocator, "{s}.release", .{hold_path});
    defer allocator.free(release);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = release, .data = "go\n" });
    joinWorkers(&loader);
    const dropped = try loader.drainEvents();
    defer {
        for (dropped) |*event| event.deinit(allocator);
        allocator.free(dropped);
    }
    try std.testing.expectEqual(@as(usize, 0), dropped.len);

    try session.setFileSource(slow_path);
    try loader.requestPsml(&session);
    const slow_started = try std.fmt.allocPrint(allocator, "{s}.started", .{slow_path});
    defer allocator.free(slow_started);
    try waitForPath(io, slow_started);
    const before = std.Io.Timestamp.now(io, .awake).nanoseconds;
    try session.setFileSource(fast_path);
    try loader.requestPsml(&session);
    joinWorkers(&loader);
    const after = std.Io.Timestamp.now(io, .awake).nanoseconds;
    try std.testing.expect(after - before < 3 * std.time.ns_per_s);
    const finished = try std.fmt.allocPrint(allocator, "{s}.finished", .{slow_path});
    defer allocator.free(finished);
    if (std.Io.Dir.cwd().access(io, finished, .{})) |_| return error.ChildWasNotCancelled else |_| {}

    const events = try loader.drainEvents();
    defer {
        for (events) |*event| event.deinit(allocator);
        allocator.free(events);
    }
    try std.testing.expectEqual(@as(usize, 2), events.len);
    switch (events[0]) {
        .packets_loaded => |table| {
            try std.testing.expectEqual(@as(usize, 1), table.packets.len);
            try std.testing.expectEqual(@as(u32, 9), table.packets[0].frame);
            try std.testing.expect(!table.append);
        },
        else => return error.UnexpectedEvent,
    }
    try std.testing.expect(events[1] == .done);
}

test "detail cache eviction frees the bundle" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tools = try testingTools(allocator, "tshark");
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &tools, .{ .cache_size = 1 });
    defer loader.deinit(io);

    try loader.detail_cache.put(io, 1, try ownedBundle(allocator, 1));
    try loader.detail_cache.put(io, 2, try ownedBundle(allocator, 2));
    try std.testing.expectEqual(@as(usize, 1), loader.detail_cache.len(io));
    try std.testing.expect(loader.detail_cache.get(io, 1) == null);
    const kept = loader.detail_cache.get(io, 2) orelse return error.MissingBundle;
    try std.testing.expectEqual(@as(u32, 2), kept.pdml.frame);
}

test "detail window keeps the previous and next frame inside the cache" {
    try std.testing.expectEqual(@as(u32, 9), detailWindow(10, 1000, 64).start);
    try std.testing.expectEqual(@as(u32, 72), detailWindow(10, 1000, 64).end);
    try std.testing.expectEqual(@as(u32, 9), detailWindow(10, 1, 64).start);
    try std.testing.expectEqual(@as(u32, 11), detailWindow(10, 1, 64).end);
    try std.testing.expectEqual(@as(u32, 4), detailWindow(4, 1, 1).start);
    try std.testing.expectEqual(@as(u32, 4), detailWindow(4, 1, 1).end);
}

test "cached detail is returned without spawning tshark" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tools = try testingTools(allocator, "tshark");
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &tools, .{});
    defer loader.deinit(io);
    var session = session_mod.Session.init(allocator, .{ .file = "missing.pcap" });
    defer session.deinit();

    try loader.detail_cache.put(io, 4, try ownedBundle(allocator, 4));
    try loader.requestDetail(&session, 4);
    try std.testing.expectEqual(@as(usize, 0), loader.workers.items.len);
    const events = try loader.drainEvents();
    defer allocator.free(events);
    switch (events[0]) {
        .detail_loaded => |bundle| try std.testing.expectEqual(@as(u32, 4), bundle.pdml.frame),
        else => return error.UnexpectedEvent,
    }
    for (events) |*event| event.deinit(allocator);
}

test "a stale detail generation does not enter the cache" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tools = try testingTools(allocator, "tshark");
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &tools, .{ .cache_size = 4 });
    defer loader.deinit(io);
    _ = loader.detail_generation.fetchAdd(1, .acq_rel);
    const pdml_xml =
        \\<pdml><packet><proto name="frame" showname="Frame 1" size="1" pos="0">
        \\<field name="frame.number" show="1" showname="Frame Number: 1" size="0" pos="0"/>
        \\</proto></packet><packet><proto name="frame" showname="Frame 2" size="1" pos="0">
        \\<field name="frame.number" show="2" showname="Frame Number: 2" size="0" pos="0"/>
        \\</proto></packet></pdml>
    ;
    const hex = "0000  aa\n\n0000  bb\n";
    try std.testing.expectError(error.Cancelled, ingestDetail(&loader, pdml_xml, hex, 2, 0));
    try std.testing.expectEqual(@as(usize, 0), loader.detail_cache.len(io));

    try ingestDetail(&loader, pdml_xml, hex, 2, null);
    try std.testing.expect(loader.detail_cache.get(io, 1) != null);
    try std.testing.expect(loader.detail_cache.get(io, 2) != null);
    const events = try loader.drainEvents();
    defer allocator.free(events);
    switch (events[0]) {
        .detail_loaded => |bundle| try std.testing.expectEqual(@as(u32, 2), bundle.pdml.frame),
        else => return error.UnexpectedEvent,
    }
    for (events) |*event| event.deinit(allocator);
}

test "shrinking the detail cache drops the oldest bundle" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tools = try testingTools(allocator, "tshark");
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &tools, .{ .cache_size = 2 });
    defer loader.deinit(io);
    try loader.detail_cache.put(io, 1, try ownedBundle(allocator, 1));
    try loader.detail_cache.put(io, 2, try ownedBundle(allocator, 2));
    loader.setCacheSize(1);
    try std.testing.expectEqual(@as(usize, 1), loader.detail_cache.len(io));
    try std.testing.expect(loader.detail_cache.get(io, 1) == null);
    try std.testing.expect(loader.detail_cache.get(io, 2) != null);
}

const stream_tshark =
    \\#!/bin/bash
    \\path=
    \\prev=
    \\for arg in "$@"; do
    \\  if [ "$prev" = "-r" ]; then
    \\    path=$arg
    \\  fi
    \\  prev=$arg
    \\done
    \\echo started > "$path.started"
    \\printf '%s\n' '<psml><structure><section>No.</section></structure><packet><section>1</section></packet>'
    \\while [ ! -f "$path.release" ]; do
    \\  :
    \\done
    \\printf '%s\n' '<packet><section>2</section></packet></psml>'
    \\exit 0
;

test "psml rows arrive before tshark exits and a later chunk appends" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const script_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/tshark", .{tmp.sub_path[0..]});
    defer allocator.free(script_path);
    const capture_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/stream.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(capture_path);
    try writeExecutable(io, script_path, stream_tshark);

    var tools = try testingTools(allocator, script_path);
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &tools, .{ .bundle_size = 1 });
    defer {
        joinWorkers(&loader);
        loader.deinit(io);
    }
    var session = session_mod.Session.init(allocator, .{ .file = capture_path });
    defer session.deinit();
    try loader.requestPsml(&session);
    const started = try std.fmt.allocPrint(allocator, "{s}.started", .{capture_path});
    defer allocator.free(started);
    try waitForPath(io, started);

    var first: ?Event = null;
    var spins: usize = 0;
    while (spins < 100) : (spins += 1) {
        const pending = try loader.drainEvents();
        if (pending.len != 0) {
            first = pending[0];
            if (pending.len != 1) return error.UnexpectedEvent;
            allocator.free(pending);
            break;
        }
        allocator.free(pending);
        try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    }
    const early = first orelse return error.TimedOut;
    switch (early) {
        .packets_loaded => |table| {
            try std.testing.expect(!table.append);
            try std.testing.expectEqual(@as(usize, 1), table.packets.len);
            try std.testing.expectEqual(@as(u32, 1), table.packets[0].frame);
            var mutable = early;
            mutable.deinit(allocator);
        },
        else => return error.UnexpectedEvent,
    }

    const release = try std.fmt.allocPrint(allocator, "{s}.release", .{capture_path});
    defer allocator.free(release);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = release, .data = "go\n" });
    joinWorkers(&loader);
    const rest = try loader.drainEvents();
    defer allocator.free(rest);
    var appended = false;
    for (rest) |event| switch (event) {
        .packets_loaded => |table| {
            appended = true;
            try std.testing.expect(table.append);
            try std.testing.expectEqual(@as(u32, 2), table.packets[0].frame);
        },
        .done => {},
        else => return error.UnexpectedEvent,
    };
    try std.testing.expect(appended);
    for (rest) |*event| event.deinit(allocator);
}
