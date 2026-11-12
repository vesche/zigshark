const std = @import("std");
const builtin = @import("builtin");
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
    append_rows: bool,
};

const LiveWatch = struct {
    loader: *CaptureLoader,
    child: std.process.Child,
    out_path: []u8,
};

const LiveListTask = struct {
    loader: *CaptureLoader,
    argv: process.Argv,
    path: []u8,
    generation: u64,
    stop: std.atomic.Value(bool) = .init(false),
    follow: ?std.Thread = null,
    stdin: ?std.Io.File = null,
};

const DetailTask = struct {
    loader: *CaptureLoader,
    pdml_argv: process.Argv,
    hex_argv: process.Argv,
    frame: u32,
    generation: u64,
};

/// One list or detail thread. `done` is set when the worker function returns.
/// The handle stays until a later request, `drainEvents`, or `deinit` joins it.
const LoaderThread = struct {
    thread: std.Thread = undefined,
    done: std.atomic.Value(bool) = .init(false),
};

pub const CaptureLoader = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    tools: *const tools_mod.Tools,
    config: LoaderConfig,
    detail_cache: lru_mod.Lru(u32, packet.DetailBundle),
    events: std.ArrayList(Event),
    event_mutex: std.Io.Mutex = .init,
    workers: std.ArrayList(*LoaderThread) = .empty,
    list_generation: std.atomic.Value(u64) = .init(0),
    detail_generation: std.atomic.Value(u64) = .init(0),
    /// Packet-list reloads and detail loads must not cancel each other.
    list_cancel: process.CancellationToken = .{},
    cancel_token: process.CancellationToken = .{},
    list_inflight: std.atomic.Value(u32) = .init(0),
    /// Set while dumpcap or the tshark fallback is writing the capture file.
    capture_active: std.atomic.Value(bool) = .init(false),
    live_stop: std.atomic.Value(bool) = .init(false),
    live_reaped: std.atomic.Value(bool) = .init(true),
    live_id: ?std.process.Child.Id = null,
    live_watcher: ?std.Thread = null,
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
        self.list_cancel.cancel(io);
        self.cancel_token.cancel(io);
        if (self.has_psml_argv) self.psml_argv.deinit(self.allocator);
        self.stopLiveCapture(io);
        self.joinWorkers();
        self.workers.deinit(self.allocator);
        self.detail_cache.deinit();
        for (self.events.items) |*ev| ev.deinit(self.allocator);
        self.events.deinit(self.allocator);
    }

    pub fn drainEvents(self: *CaptureLoader) ![]Event {
        self.reapFinished();
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

    pub fn listInFlight(self: *const CaptureLoader) bool {
        return self.list_inflight.load(.acquire) != 0;
    }

    pub fn requestPsml(self: *CaptureLoader, session: *session_mod.Session) !void {
        self.reapFinished();
        if (self.capture_active.load(.acquire) and !self.defer_spawn) {
            try self.startLiveList(session);
            return;
        }
        try self.requestPsmlNewerThan(session, null);
    }

    /// `after_frame` appends only packets newer than that frame. Live refresh
    /// uses it so a growing file is not dissected from the start again.
    pub fn requestPsmlNewerThan(self: *CaptureLoader, session: *session_mod.Session, after_frame: ?u32) !void {
        self.reapFinished();
        const owned_filter = if (after_frame) |frame|
            try frameFloorFilter(self.allocator, session.display_filter, frame)
        else
            null;
        defer if (owned_filter) |filter| self.allocator.free(filter);
        const filter: ?[]const u8 = owned_filter orelse session.display_filter;

        session.loading = .loading_list;
        self.list_cancel.cancel(self.io);
        const generation = self.list_generation.fetchAdd(1, .acq_rel) + 1;
        self.list_cancel.reset();
        var argv = try process.argvPsmlLoad(
            self.allocator,
            self.tools.tshark,
            session.source,
            filter,
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
            .append_rows = after_frame != null,
        };
        argv = .{};
        errdefer task.argv.deinit(self.allocator);
        _ = self.list_inflight.fetchAdd(1, .acq_rel);
        errdefer _ = self.list_inflight.fetchSub(1, .acq_rel);
        try self.spawnWorker(runTrackedPsml, task);
    }

    pub fn requestDetail(
        self: *CaptureLoader,
        session: *session_mod.Session,
        frame: u32,
    ) !void {
        self.reapFinished();
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
        try self.spawnWorker(runTrackedDetail, task);
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

        var captured = captureDetailWindow(self, io, pdml_argv.slice(), hex_argv.slice()) catch |err| {
            if (err == error.Cancelled or self.cancel_token.isCancelled()) return;
            return err;
        };
        defer captured.deinit(self.allocator);
        if (self.cancel_token.isCancelled()) return;
        if (!captured.pdml.term.success()) {
            try self.pushEvent(.{ .error_msg = try self.allocator.dupe(u8, captured.pdml.stderr) });
            return;
        }
        if (!captured.hex.term.success()) {
            try self.pushEvent(.{ .error_msg = try self.allocator.dupe(u8, captured.hex.stderr) });
            return;
        }

        try ingestDetail(self, captured.pdml.stdout, captured.hex.stdout, frame, null);
        logDetailLoad(io, frame, captured.started_ns, captured.pdml_done_ns, captured.hex_done_ns);
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
        // dumpcap drops privileges before creating -w, so under sudo it cannot
        // create test.pcap in this directory. The capture bytes come back on
        // stdout and this process writes the absolute path.
        const absolute = try absoluteCapturePath(self.allocator, io, temp_path);
        createCaptureFile(io, absolute) catch |err| {
            self.allocator.free(absolute);
            return err;
        };
        if (session.capture_path.len != 0) self.allocator.free(session.capture_path);
        session.capture_path = absolute;
        session.source = .{ .fifo = session.capture_path };

        var argv: process.Argv = undefined;
        if (self.tools.dumpcap_can_capture) {
            argv = try process.argvDumpcapLive(self.allocator, self.tools.dumpcap, interfaces, session.capture_filter);
        } else {
            try session.setError(tools_mod.dumpcapPermissionMessage());
            try self.pushEvent(.{ .error_msg = try self.allocator.dupe(u8, tools_mod.dumpcapPermissionMessage()) });
            argv = try process.argvTsharkLiveFallback(self.allocator, self.tools.tshark, interfaces, session.capture_filter);
        }
        defer argv.deinit(self.allocator);

        self.stopLiveCapture(io);
        const out_path = try self.allocator.dupe(u8, session.capture_path);
        const watch = try self.allocator.create(LiveWatch);
        watch.loader = self;
        watch.out_path = out_path;
        watch.child = std.process.spawn(io, .{
            .argv = argv.slice(),
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
        }) catch |err| {
            self.allocator.free(watch.out_path);
            self.allocator.destroy(watch);
            return err;
        };
        // The watcher owns the child. It writes stdout into the capture file
        // and drains stderr so the capture cannot block on a full pipe.
        self.live_reaped.store(false, .release);
        self.live_stop.store(false, .release);
        self.live_id = watch.child.id;
        self.live_watcher = std.Thread.spawn(.{}, runLiveWatch, .{watch}) catch |err| {
            if (watch.child.id != null) watch.child.kill(io);
            self.allocator.free(watch.out_path);
            self.allocator.destroy(watch);
            self.live_id = null;
            return err;
        };
        self.capture_active.store(true, .release);
        self.pushEvent(.{ .capture_progress = try self.allocator.dupe(u8, "capture started") }) catch |err| {
            self.stopLiveCapture(io);
            return err;
        };
    }

    pub fn cancel(self: *CaptureLoader, io: std.Io) void {
        self.list_cancel.cancel(io);
        self.cancel_token.cancel(io);
        self.stopLiveCapture(io);
    }

    pub fn stopLiveCapture(self: *CaptureLoader, io: std.Io) void {
        _ = io;
        if (!self.live_reaped.load(.acquire)) {
            if (self.live_id) |id| signalStop(id);
        }
        self.live_id = null;
        if (self.live_watcher) |thread| {
            thread.join();
            self.live_watcher = null;
        }
        // The file is flushed. The list reader closes tshark's stdin after this
        // and finishes the packets already on disk.
        self.live_stop.store(true, .release);
        self.capture_active.store(false, .release);
    }

    /// One tshark reads the growing capture from the start of the call until
    /// the capture stops. Restarting it on every new packet re-dissects the
    /// whole file and saturates the machine.
    pub fn startLiveList(self: *CaptureLoader, session: *session_mod.Session) !void {
        const path = self.filePath(session) orelse return error.NoCaptureFile;
        const path_copy = try self.allocator.dupe(u8, path);
        var argv = process.argvPsmlLoad(
            self.allocator,
            self.tools.tshark,
            .stdin,
            session.display_filter,
            if (self.config.column_format.len != 0) self.config.column_format else null,
        ) catch |err| {
            self.allocator.free(path_copy);
            return err;
        };
        errdefer argv.deinit(self.allocator);
        errdefer self.allocator.free(path_copy);

        session.loading = .loading_list;
        self.list_cancel.cancel(self.io);
        const generation = self.list_generation.fetchAdd(1, .acq_rel) + 1;
        self.list_cancel.reset();
        try appendDissectionOptions(self.allocator, &argv, session, self.config.tshark_args);
        if (self.tools.supports_color) try argv.append(self.allocator, "--color");

        if (self.defer_spawn) {
            if (self.has_psml_argv) self.psml_argv.deinit(self.allocator);
            self.psml_argv = argv;
            self.has_psml_argv = true;
            argv = .{};
            self.allocator.free(path_copy);
            return;
        }

        const task = try self.allocator.create(LiveListTask);
        task.* = .{
            .loader = self,
            .argv = argv,
            .path = path_copy,
            .generation = generation,
        };
        argv = .{};
        _ = self.list_inflight.fetchAdd(1, .acq_rel);
        self.spawnWorker(runTrackedLiveList, task) catch |err| {
            _ = self.list_inflight.fetchSub(1, .acq_rel);
            task.argv.deinit(self.allocator);
            self.allocator.destroy(task);
            return err;
        };
    }

    /// Join threads whose worker functions have returned. In-flight work stays
    /// in `workers` so quit can still cancel it.
    fn reapFinished(self: *CaptureLoader) void {
        var index: usize = 0;
        while (index < self.workers.items.len) {
            const tracked = self.workers.items[index];
            if (!tracked.done.load(.acquire)) {
                index += 1;
                continue;
            }
            tracked.thread.join();
            self.allocator.destroy(tracked);
            _ = self.workers.swapRemove(index);
        }
    }

    pub fn joinWorkers(self: *CaptureLoader) void {
        while (self.workers.pop()) |tracked| {
            tracked.thread.join();
            self.allocator.destroy(tracked);
        }
    }

    fn spawnWorker(self: *CaptureLoader, comptime func: anytype, task: anytype) !void {
        self.reapFinished();
        try self.workers.ensureUnusedCapacity(self.allocator, 1);
        const tracked = try self.allocator.create(LoaderThread);
        errdefer self.allocator.destroy(tracked);
        tracked.* = .{};
        tracked.thread = try std.Thread.spawn(.{}, func, .{ task, tracked });
        self.workers.appendAssumeCapacity(tracked);
    }
};

fn signalStop(id: std.process.Child.Id) void {
    if (builtin.os.tag == .windows) {
        const status: std.os.windows.NTSTATUS = @fromBackingInt(@intCast(1));
        _ = std.os.windows.ntdll.NtTerminateProcess(id, status);
    } else if (builtin.os.tag != .wasi) {
        std.posix.kill(id, std.posix.SIG.TERM) catch {};
    }
}

fn runLiveWatch(watch: *LiveWatch) void {
    const loader = watch.loader;
    defer {
        loader.allocator.free(watch.out_path);
        loader.allocator.destroy(watch);
    }
    const io = loader.io;

    var stderr_text: std.ArrayList(u8) = .empty;
    defer stderr_text.deinit(loader.allocator);

    const cwd = std.Io.Dir.cwd();
    const file = cwd.createFile(io, watch.out_path, .{ .truncate = true }) catch {
        if (watch.child.id) |id| signalStop(id);
        const term = watch.child.wait(io) catch {
            loader.live_reaped.store(true, .release);
            return;
        };
        loader.live_reaped.store(true, .release);
        _ = term;
        reportLiveFailure(loader, "could not write the capture file");
        return;
    };
    defer file.close(io);

    var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: std.Io.File.MultiReader = undefined;
    multi_reader.init(loader.allocator, io, multi_reader_buffer.toStreams(), &.{ watch.child.stdout.?, watch.child.stderr.? });
    defer multi_reader.deinit();

    var write_failed = false;
    while (multi_reader.fill(65536, .none)) |_| {
        const stdout = multi_reader.reader(0);
        const chunk = stdout.buffered();
        if (chunk.len != 0) {
            file.writeStreamingAll(io, chunk) catch {
                write_failed = true;
                if (watch.child.id) |id| signalStop(id);
                stdout.seek = stdout.end;
                break;
            };
            stdout.seek = stdout.end;
        }
        const stderr = multi_reader.reader(1);
        const err_chunk = stderr.buffered();
        if (err_chunk.len != 0 and stderr_text.items.len < 4096) {
            const room = 4096 - stderr_text.items.len;
            const take = @min(room, err_chunk.len);
            stderr_text.appendSlice(loader.allocator, err_chunk[0..take]) catch {};
        }
        if (err_chunk.len != 0) stderr.seek = stderr.end;
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => {},
    }

    const term = watch.child.wait(io) catch {
        loader.live_reaped.store(true, .release);
        return;
    };
    loader.live_reaped.store(true, .release);
    if (loader.live_stop.load(.acquire)) return;
    if (write_failed) {
        reportLiveFailure(loader, "could not write the capture file");
        return;
    }
    if (term.success()) return;

    const trimmed = std.mem.trim(u8, stderr_text.items, " \t\r\n");
    const shown = if (trimmed.len != 0) trimmed else "capture process exited with failure";
    reportLiveFailure(loader, shown);
}

fn reportLiveFailure(loader: *CaptureLoader, message: []const u8) void {
    const limit = @min(message.len, 4096);
    const copy = loader.allocator.dupe(u8, message[0..limit]) catch return;
    var event: Event = .{ .error_msg = copy };
    loader.pushEvent(event) catch {
        event.deinit(loader.allocator);
    };
}

fn drainChildStderr(allocator: std.mem.Allocator, io: std.Io, stderr: std.Io.File, out: *std.ArrayList(u8)) void {
    var buf: [4096]u8 = undefined;
    var iov: [1][]u8 = .{&buf};
    const cap = 16 * 1024;
    while (out.items.len < cap) {
        const n = stderr.readStreaming(io, &iov) catch break;
        if (n == 0) return;
        const room = cap - out.items.len;
        const take = @min(n, room);
        out.appendSlice(allocator, buf[0..take]) catch break;
    }
    while (true) {
        const n = stderr.readStreaming(io, &iov) catch return;
        if (n == 0) return;
    }
}

fn giveCaptureToSudoUser(io: std.Io, file: std.Io.File) void {
    var raw: [32 * 1024]u8 = undefined;
    const cwd = std.Io.Dir.cwd();
    const env_file = cwd.openFile(io, "/proc/self/environ", .{}) catch return;
    defer env_file.close(io);
    var iov: [1][]u8 = .{&raw};
    const n = env_file.readStreaming(io, &iov) catch return;
    if (n == 0) return;
    const uid = envValue(raw[0..n], "SUDO_UID") orelse return;
    const gid = envValue(raw[0..n], "SUDO_GID") orelse return;
    const uid_i = std.fmt.parseInt(std.Io.File.Uid, uid, 10) catch return;
    const gid_i = std.fmt.parseInt(std.Io.File.Gid, gid, 10) catch return;
    file.setOwner(io, uid_i, gid_i) catch {};
}

fn envValue(block: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, block, 0);
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry, key) and entry.len > key.len and entry[key.len] == '=') {
            return entry[key.len + 1 ..];
        }
    }
    return null;
}

fn absoluteCapturePath(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(path)) return allocator.dupe(u8, path);
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    return std.fs.path.join(allocator, &.{ cwd, path });
}

fn createCaptureFile(io: std.Io, path: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| {
        if (dir.len != 0) try cwd.createDirPath(io, dir);
    }
    const file = try cwd.createFile(io, path, .{
        .truncate = true,
        .permissions = @fromBackingInt(@intCast(0o644)),
    });
    defer file.close(io);
    // sudo leaves this process as root, which can create the file, then
    // dumpcap drops to the invoking user. Hand the file to that user.
    giveCaptureToSudoUser(io, file);
}

fn runLiveList(task: *LiveListTask) void {
    const loader = task.loader;
    const io = loader.io;
    defer {
        task.stop.store(true, .release);
        if (task.follow) |thread| thread.join();
        if (task.stdin) |stdin| stdin.close(io);
        _ = loader.list_inflight.fetchSub(1, .acq_rel);
        task.argv.deinit(loader.allocator);
        loader.allocator.free(task.path);
        loader.allocator.destroy(task);
    }
    if (loader.list_cancel.isCancelled()) return;

    var child = std.process.spawn(io, .{
        .argv = task.argv.slice(),
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch |err| {
        emitWorkerError(loader, @errorName(err));
        return;
    };
    loader.list_cancel.bind(io, &child);
    defer loader.list_cancel.release(io, &child);

    const stdin = child.stdin orelse return;
    child.stdin = null;
    task.stdin = stdin;
    task.follow = std.Thread.spawn(.{}, pumpCapture, .{task}) catch |err| {
        emitWorkerError(loader, @errorName(err));
        return;
    };

    var feed = PsmlFeed.init(loader, task.generation, false);
    defer feed.deinit();
    var stderr_text: std.ArrayList(u8) = .empty;
    defer stderr_text.deinit(loader.allocator);
    const term = streamChildOutput(loader, &child, &feed, &stderr_text) catch |err| {
        if (err == error.Cancelled or task.generation != loader.list_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    if (task.generation != loader.list_generation.load(.acquire) or loader.list_cancel.isCancelled()) return;
    feed.finish() catch |err| {
        if (err == error.Cancelled or task.generation != loader.list_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    const failed = !term.success() and !process.isTruncatedCapture(stderr_text.items);
    if (failed and !loader.live_stop.load(.acquire)) {
        const trimmed = std.mem.trim(u8, stderr_text.items, " \t\r\n");
        emitWorkerError(loader, if (trimmed.len != 0) trimmed else "live packet list failed");
        return;
    }
    loader.pushEvent(.done) catch {};
}

fn pumpCapture(task: *LiveListTask) void {
    const loader = task.loader;
    const io = loader.io;
    const stdin = task.stdin orelse return;
    defer {
        stdin.close(io);
        task.stdin = null;
    }
    const cwd = std.Io.Dir.cwd();
    var file: ?std.Io.File = null;
    defer if (file) |opened| opened.close(io);
    var offset: u64 = 0;
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        if (file == null) {
            file = cwd.openFile(io, task.path, .{}) catch {
                if (task.stop.load(.acquire) or loader.live_stop.load(.acquire)) break;
                std.Io.sleep(io, .fromMilliseconds(40), .awake) catch break;
                continue;
            };
        }
        const opened = file.?;
        const stat = cwd.statFile(io, task.path, .{}) catch {
            if (task.stop.load(.acquire) or loader.live_stop.load(.acquire)) break;
            std.Io.sleep(io, .fromMilliseconds(40), .awake) catch break;
            continue;
        };
        if (stat.size < offset) offset = 0;
        if (stat.size == offset) {
            if (task.stop.load(.acquire) or loader.live_stop.load(.acquire)) break;
            std.Io.sleep(io, .fromMilliseconds(40), .awake) catch break;
            continue;
        }
        const want = @min(buf.len, stat.size - offset);
        var iov: [1][]u8 = .{buf[0..want]};
        const n = opened.readPositional(io, &iov, offset) catch break;
        if (n == 0) {
            if (task.stop.load(.acquire) or loader.live_stop.load(.acquire)) break;
            std.Io.sleep(io, .fromMilliseconds(40), .awake) catch break;
            continue;
        }
        stdin.writeStreamingAll(io, buf[0..n]) catch break;
        offset += n;
    }
}

fn streamChildOutput(
    loader: *CaptureLoader,
    child: *std.process.Child,
    feed: *PsmlFeed,
    stderr_text: *std.ArrayList(u8),
) !std.process.Child.Term {
    const io = loader.io;
    var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: std.Io.File.MultiReader = undefined;
    multi_reader.init(loader.allocator, io, multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer multi_reader.deinit();

    while (multi_reader.fill(4096, .none)) |_| {
        if (loader.list_cancel.isCancelled()) return error.Cancelled;
        const stdout = multi_reader.reader(0);
        const chunk = stdout.buffered();
        if (chunk.len != 0) {
            try PsmlFeed.onChunk(@ptrCast(feed), chunk);
            stdout.seek = stdout.end;
        }
        const stderr = multi_reader.reader(1);
        const err_chunk = stderr.buffered();
        if (err_chunk.len != 0 and stderr_text.items.len < 4096) {
            const room = 4096 - stderr_text.items.len;
            const take = @min(room, err_chunk.len);
            stderr_text.appendSlice(loader.allocator, err_chunk[0..take]) catch {};
        }
        stderr.seek = stderr.end;
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => {
            if (loader.list_cancel.isCancelled()) return error.Cancelled;
            return err;
        },
    }
    return if (loader.list_cancel.isCancelled())
        error.Cancelled
    else
        try loader.list_cancel.waitUnlessCancelled(io, child);
}

fn frameFloorFilter(allocator: std.mem.Allocator, display: []const u8, after_frame: u32) ![]u8 {
    if (display.len == 0) return std.fmt.allocPrint(allocator, "frame.number > {d}", .{after_frame});
    return std.fmt.allocPrint(allocator, "({s}) and frame.number > {d}", .{ display, after_frame });
}

/// A live file should be read again only after the previous read has finished
/// and dumpcap has appended bytes.
pub fn liveReloadDue(in_flight: bool, size: u64, synced: u64) bool {
    return !in_flight and size != 0 and size != synced;
}

fn runTrackedPsml(task: *PsmlTask, tracked: *LoaderThread) void {
    defer tracked.done.store(true, .release);
    runPsmlWorker(task);
}

fn runTrackedDetail(task: *DetailTask, tracked: *LoaderThread) void {
    defer tracked.done.store(true, .release);
    runDetailWorker(task);
}

fn runTrackedLiveList(task: *LiveListTask, tracked: *LoaderThread) void {
    defer tracked.done.store(true, .release);
    runLiveList(task);
}

fn runPsmlWorker(task: *PsmlTask) void {
    const loader = task.loader;
    defer {
        _ = loader.list_inflight.fetchSub(1, .acq_rel);
        task.argv.deinit(loader.allocator);
        loader.allocator.destroy(task);
    }

    var feed = PsmlFeed.init(loader, task.generation, task.append_rows);
    defer feed.deinit();
    var saw_stdout = false;
    var output = process.runStdoutChunks(
        loader.allocator,
        loader.io,
        task.argv.slice(),
        &loader.list_cancel,
        &feed,
        PsmlFeed.onChunk,
        &saw_stdout,
    ) catch |err| {
        if (err == error.Cancelled or task.generation != loader.list_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    defer output.deinit(loader.allocator);
    if (task.generation != loader.list_generation.load(.acquire) or loader.list_cancel.isCancelled()) return;

    feed.finish() catch |err| {
        if (err == error.Cancelled or task.generation != loader.list_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    if (!output.term.success()) {
        // A capture that is still open ends mid-packet. Keep the rows tshark
        // already wrote instead of covering the list with an error dialog.
        const usable = process.isTruncatedCapture(output.stderr) and
            (feed.emitted_rows > 0 or loader.capture_active.load(.acquire));
        if (!usable) {
            emitWorkerError(loader, output.stderr);
            return;
        }
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

    fn init(loader: *CaptureLoader, generation: u64, append_rows: bool) PsmlFeed {
        return .{
            .loader = loader,
            .generation = generation,
            .started_ns = std.Io.Timestamp.now(loader.io, .awake).nanoseconds,
            .replace_next = !append_rows,
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

        // Paint a live capture before a thousand-row bundle fills. The read
        // often ends at a short packet, and that tail has to be flushed by
        // the time tshark exits.
        const configured: usize = @max(@as(usize, self.loader.config.bundle_size), 1);
        const bundle: usize = if (self.loader.capture_active.load(.acquire))
            @min(configured, 16)
        else
            configured;
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
            .generation = self.generation,
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

    var captured = captureDetailWindow(loader, loader.io, task.pdml_argv.slice(), task.hex_argv.slice()) catch |err| {
        if (err == error.Cancelled or task.generation != loader.detail_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    defer captured.deinit(loader.allocator);
    if (loader.cancel_token.isCancelled() or task.generation != loader.detail_generation.load(.acquire)) return;
    if (!captured.pdml.term.success()) {
        emitWorkerError(loader, captured.pdml.stderr);
        return;
    }
    if (!captured.hex.term.success()) {
        emitWorkerError(loader, captured.hex.stderr);
        return;
    }

    ingestDetail(loader, captured.pdml.stdout, captured.hex.stdout, task.frame, task.generation) catch |err| {
        if (err == error.Cancelled or task.generation != loader.detail_generation.load(.acquire)) return;
        emitWorkerError(loader, @errorName(err));
        return;
    };
    logDetailLoad(loader.io, task.frame, captured.started_ns, captured.pdml_done_ns, captured.hex_done_ns);
}

const DetailCapture = struct {
    pdml: process.RunOutput,
    hex: process.RunOutput,
    started_ns: i96,
    pdml_done_ns: i96,
    hex_done_ns: i96,

    fn deinit(self: *DetailCapture, allocator: std.mem.Allocator) void {
        self.pdml.deinit(allocator);
        self.hex.deinit(allocator);
    }
};

const DetailSide = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    token: *process.CancellationToken,
    output: ?process.RunOutput = null,
    done_ns: i96 = 0,
    err: ?anyerror = null,

    fn run(self: *DetailSide) void {
        const output = process.runCaptureCancellable(self.allocator, self.io, self.argv, self.token) catch |err| {
            self.done_ns = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
            self.err = err;
            return;
        };
        self.done_ns = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        self.output = output;
    }
};

/// PDML and hex for one frame window. Both children share `cancel_token`, so a
/// newer selection kills the pair instead of waiting out the first process.
fn captureDetailWindow(
    self: *CaptureLoader,
    io: std.Io,
    pdml_argv: []const []const u8,
    hex_argv: []const []const u8,
) !DetailCapture {
    const started_ns = std.Io.Timestamp.now(io, .awake).nanoseconds;
    var pdml_side = DetailSide{
        .allocator = self.allocator,
        .io = io,
        .argv = pdml_argv,
        .token = &self.cancel_token,
    };
    var hex_side = DetailSide{
        .allocator = self.allocator,
        .io = io,
        .argv = hex_argv,
        .token = &self.cancel_token,
    };
    const pdml_thread = try std.Thread.spawn(.{}, DetailSide.run, .{&pdml_side});
    const hex_thread = std.Thread.spawn(.{}, DetailSide.run, .{&hex_side}) catch |err| {
        pdml_thread.join();
        if (pdml_side.output) |*output| output.deinit(self.allocator);
        return err;
    };
    pdml_thread.join();
    hex_thread.join();
    errdefer if (pdml_side.output) |*output| output.deinit(self.allocator);
    errdefer if (hex_side.output) |*output| output.deinit(self.allocator);

    if (pdml_side.err) |err| return err;
    if (hex_side.err) |err| return err;
    return .{
        .pdml = pdml_side.output orelse return error.Cancelled,
        .hex = hex_side.output orelse return error.Cancelled,
        .started_ns = started_ns,
        .pdml_done_ns = pdml_side.done_ns,
        .hex_done_ns = hex_side.done_ns,
    };
}

fn elapsedMs(start_ns: i96, end_ns: i96) i96 {
    return @divTrunc(end_ns -| start_ns, std.time.ns_per_ms);
}

const DetailTiming = struct {
    total_ms: i96,
    pdml_ms: i96,
    hex_ms: i96,
    parse_ms: i96,
};

/// Each tshark duration is that process's own runtime. Parse starts once both
/// have finished, which is not the same instant when the runs overlap.
fn detailTiming(started_ns: i96, pdml_done_ns: i96, hex_done_ns: i96, parsed_ns: i96) DetailTiming {
    const ready_ns = @max(pdml_done_ns, hex_done_ns);
    return .{
        .total_ms = elapsedMs(started_ns, parsed_ns),
        .pdml_ms = elapsedMs(started_ns, pdml_done_ns),
        .hex_ms = elapsedMs(started_ns, hex_done_ns),
        .parse_ms = elapsedMs(ready_ns, parsed_ns),
    };
}

fn detailLoadLine(buf: []u8, frame: u32, total_ms: i96, pdml_ms: i96, hex_ms: i96, parse_ms: i96) []const u8 {
    return std.fmt.bufPrint(buf, "frame {d} loaded in {d} ms (pdml {d} ms, hex {d} ms, parse {d} ms)", .{
        frame,
        total_ms,
        pdml_ms,
        hex_ms,
        parse_ms,
    }) catch buf[0..0];
}

fn logDetailLoad(io: std.Io, frame: u32, started_ns: i96, pdml_done_ns: i96, hex_done_ns: i96) void {
    const done_ns = std.Io.Timestamp.now(io, .awake).nanoseconds;
    const timing = detailTiming(started_ns, pdml_done_ns, hex_done_ns, done_ns);
    var buf: [160]u8 = undefined;
    const line = detailLoadLine(&buf, frame, timing.total_ms, timing.pdml_ms, timing.hex_ms, timing.parse_ms);
    log_mod.info("detail", "{s}", .{line});
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
    if (session.tls_keylog_file.len != 0) {
        const option = try std.fmt.allocPrint(allocator, "tls.keylog_file:{s}", .{session.tls_keylog_file});
        defer allocator.free(option);
        try argv.append(allocator, "-o");
        try argv.append(allocator, option);
    }
    if (session.name_resolution.len != 0) {
        try argv.append(allocator, "-N");
        try argv.append(allocator, session.name_resolution);
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
    worker.thread.join();
    loader.allocator.destroy(worker);
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

fn fakeTsharkPath(allocator: std.mem.Allocator) ![]u8 {
    const name = if (builtin.os.tag == .windows) "fake-tshark.exe" else "fake-tshark";
    return std.fmt.allocPrint(allocator, "zig-out/bin/{s}", .{name});
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
    const tool = try fakeTsharkPath(allocator);
    defer allocator.free(tool);
    const hold_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/hold.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(hold_path);
    const slow_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/slow.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(slow_path);
    const fast_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/fast.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(fast_path);

    var tools = try testingTools(allocator, tool);
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &tools, .{});
    defer {
        loader.joinWorkers();
        loader.deinit(io);
    }

    var session = session_mod.Session.init(allocator, .{ .file = hold_path });
    defer session.deinit();
    try loader.requestPsml(&session);
    const started = try std.fmt.allocPrint(allocator, "{s}.started", .{hold_path});
    defer allocator.free(started);
    try waitForPath(io, started);
    try std.testing.expect(loader.listInFlight());
    _ = loader.list_generation.fetchAdd(1, .acq_rel);
    const release = try std.fmt.allocPrint(allocator, "{s}.release", .{hold_path});
    defer allocator.free(release);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = release, .data = "go\n" });
    loader.joinWorkers();
    try std.testing.expect(!loader.listInFlight());
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
    loader.joinWorkers();
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

test "a detail load does not cancel the packet list" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tool = try fakeTsharkPath(allocator);
    defer allocator.free(tool);
    const hold_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/hold.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(hold_path);

    var tools = try testingTools(allocator, tool);
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &tools, .{});
    defer {
        loader.joinWorkers();
        loader.deinit(io);
    }

    var session = session_mod.Session.init(allocator, .{ .file = hold_path });
    defer session.deinit();
    try loader.requestPsml(&session);
    const started = try std.fmt.allocPrint(allocator, "{s}.started", .{hold_path});
    defer allocator.free(started);
    try waitForPath(io, started);
    try loader.requestDetail(&session, 1);
    const release = try std.fmt.allocPrint(allocator, "{s}.release", .{hold_path});
    defer allocator.free(release);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = release, .data = "go\n" });
    loader.joinWorkers();

    const events = try loader.drainEvents();
    defer {
        for (events) |*event| event.deinit(allocator);
        allocator.free(events);
    }
    var saw_packets = false;
    for (events) |event| {
        if (event == .packets_loaded) saw_packets = true;
    }
    try std.testing.expect(saw_packets);
}

test "deinit returns while a packet-list child is still held" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tool = try fakeTsharkPath(allocator);
    defer allocator.free(tool);
    const hold_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/hold.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(hold_path);

    var tools = try testingTools(allocator, tool);
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &tools, .{});
    var session = session_mod.Session.init(allocator, .{ .file = hold_path });
    defer session.deinit();
    try loader.requestPsml(&session);
    const started = try std.fmt.allocPrint(allocator, "{s}.started", .{hold_path});
    defer allocator.free(started);
    try waitForPath(io, started);

    const before = std.Io.Timestamp.now(io, .awake).nanoseconds;
    loader.deinit(io);
    const after = std.Io.Timestamp.now(io, .awake).nanoseconds;
    try std.testing.expect(after - before < 3 * std.time.ns_per_s);
}

test "a finished loader thread is joined before the next request returns" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tool = try fakeTsharkPath(allocator);
    defer allocator.free(tool);
    const list_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/quicklist.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(list_path);
    const detail_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/bothfast.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(detail_path);

    var tools = try testingTools(allocator, tool);
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &tools, .{});
    defer loader.deinit(io);
    var session = session_mod.Session.init(allocator, .{ .file = list_path });
    defer session.deinit();

    try loader.requestPsml(&session);
    try waitUntilWorkerDone(io, &loader);
    try loader.detail_cache.put(io, 3, try ownedBundle(allocator, 3));
    try loader.requestDetail(&session, 3);
    try std.testing.expectEqual(@as(usize, 0), loader.workers.items.len);

    try session.setFileSource(detail_path);
    try loader.requestDetail(&session, 7);
    try waitUntilWorkerDone(io, &loader);
    try loader.requestDetail(&session, 7);
    try std.testing.expectEqual(@as(usize, 0), loader.workers.items.len);
}

test "deinit returns while a detail child is still held" {
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
    var loader = CaptureLoader.init(allocator, io, &tools, .{});
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
    const after = std.Io.Timestamp.now(io, .awake).nanoseconds;
    try std.testing.expect(after - before < 3 * std.time.ns_per_s);
    try expectNoMarker(io, allocator, path, ".pdml.finished");
    try expectNoMarker(io, allocator, path, ".hex.finished");
}

fn waitUntilWorkerDone(io: std.Io, loader: *CaptureLoader) !void {
    var spins: usize = 0;
    while (spins < 100) : (spins += 1) {
        if (loader.workers.items.len == 1 and loader.workers.items[0].done.load(.acquire)) return;
        try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    }
    return error.TimedOut;
}

fn expectNoMarker(io: std.Io, allocator: std.mem.Allocator, path: []const u8, suffix: []const u8) !void {
    const marker = try std.fmt.allocPrint(allocator, "{s}{s}", .{ path, suffix });
    defer allocator.free(marker);
    if (std.Io.Dir.cwd().access(io, marker, .{})) |_| return error.ChildWasNotCancelled else |_| {}
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

test "detail timing line counts both tshark runs and the parse" {
    var buf: [160]u8 = undefined;
    const line = detailLoadLine(&buf, 12, 41, 22, 13, 5);
    try std.testing.expectEqualStrings(
        "frame 12 loaded in 41 ms (pdml 22 ms, hex 13 ms, parse 5 ms)",
        line,
    );
}

test "overlapped detail timing keeps each tshark run when hex finishes first" {
    const ns = std.time.ns_per_ms;
    const timing = detailTiming(1_000 * ns, 1_030 * ns, 1_010 * ns, 1_035 * ns);
    try std.testing.expectEqual(@as(i96, 35), timing.total_ms);
    try std.testing.expectEqual(@as(i96, 30), timing.pdml_ms);
    try std.testing.expectEqual(@as(i96, 10), timing.hex_ms);
    try std.testing.expectEqual(@as(i96, 5), timing.parse_ms);
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

test "psml rows arrive before tshark exits and a later chunk appends" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tool = try fakeTsharkPath(allocator);
    defer allocator.free(tool);
    const capture_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/stream.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(capture_path);

    var tools = try testingTools(allocator, tool);
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, io, &tools, .{ .bundle_size = 1 });
    defer {
        loader.joinWorkers();
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
    loader.joinWorkers();
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

test "live reload waits for the in-flight read and then asks for new frames" {
    try std.testing.expect(!liveReloadDue(true, 100, 0));
    try std.testing.expect(!liveReloadDue(false, 0, 0));
    try std.testing.expect(!liveReloadDue(false, 40, 40));
    try std.testing.expect(liveReloadDue(false, 40, 0));

    const allocator = std.testing.allocator;
    const floor = try frameFloorFilter(allocator, "tcp or udp", 7);
    defer allocator.free(floor);
    try std.testing.expectEqualStrings("(tcp or udp) and frame.number > 7", floor);
    const bare = try frameFloorFilter(allocator, "", 7);
    defer allocator.free(bare);
    try std.testing.expectEqualStrings("frame.number > 7", bare);

    var tools = try testingTools(allocator, "tshark");
    defer tools.deinit();
    var loader = CaptureLoader.init(allocator, std.testing.io, &tools, .{});
    loader.defer_spawn = true;
    defer loader.deinit(std.testing.io);
    var session = session_mod.Session.init(allocator, .{ .fifo = "live.pcap" });
    defer session.deinit();
    try session.setFilter("tcp", null);
    try loader.requestPsmlNewerThan(&session, 4);
    const argv = loader.psml_argv.slice();
    var saw_floor = false;
    var saw_flush = false;
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "(tcp) and frame.number > 4")) saw_floor = true;
        if (std.mem.eql(u8, arg, "-l")) saw_flush = true;
    }
    try std.testing.expect(saw_floor);
    try std.testing.expect(saw_flush);
    try std.testing.expect(!loader.listInFlight());
}

test "dumpcap stderr is drained so the capture file is written" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const script_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/dumpcap", .{tmp.sub_path[0..]});
    defer allocator.free(script_path);
    const out_path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/live.pcap", .{tmp.sub_path[0..]});
    defer allocator.free(out_path);

    const script =
        \\#!/usr/bin/env python3
        \\import sys
        \\args = sys.argv[1:]
        \\if "-D" in args:
        \\    sys.stdout.write("1. fake0\\n")
        \\    raise SystemExit(0)
        \\out = None
        \\i = 0
        \\while i < len(args):
        \\    if args[i] == "-w" and i + 1 < len(args):
        \\        out = args[i + 1]
        \\        i += 2
        \\        continue
        \\    i += 1
        \\if out != "-":
        \\    sys.exit(2)
        \\sys.stderr.write(("x" * 80 + "\\n") * 4000)
        \\sys.stderr.flush()
        \\with open("tests/fixtures/1.pcap", "rb") as src:
        \\    sys.stdout.buffer.write(src.read())
        \\    sys.stdout.buffer.flush()
        \\
    ;
    const cwd = std.Io.Dir.cwd();
    {
        const script_file = try cwd.createFile(io, script_path, .{
            .truncate = true,
            .permissions = @fromBackingInt(@intCast(0o755)),
        });
        errdefer script_file.close(io);
        try script_file.writeStreamingAll(io, script);
        script_file.close(io);
    }

    var tools = try testingTools(allocator, "tshark");
    defer tools.deinit();
    tools.dumpcap_can_capture = true;
    const dumpcap = try allocator.dupe(u8, script_path);
    allocator.free(tools.dumpcap);
    tools.dumpcap = dumpcap;

    var loader = CaptureLoader.init(allocator, io, &tools, .{});
    defer loader.deinit(io);
    const ifaces = try allocator.alloc([]const u8, 1);
    defer allocator.free(ifaces);
    ifaces[0] = "eth0";
    var session = session_mod.Session.init(allocator, .{ .interfaces = ifaces });
    defer session.deinit();

    try loader.startLiveCapture(io, &session, ifaces, out_path);
    try std.testing.expect(std.fs.path.isAbsolute(session.capture_path));
    var spins: usize = 0;
    var wrote = false;
    while (spins < 200) : (spins += 1) {
        const stat = cwd.statFile(io, out_path, .{}) catch {
            try std.Io.sleep(io, .fromMilliseconds(20), .awake);
            continue;
        };
        if (stat.size >= 2000) {
            wrote = true;
            break;
        }
        try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    }
    try std.testing.expect(wrote);
}
