const std = @import("std");
const builtin = @import("builtin");

pub const RunOutput = struct {
    stdout: []u8,
    stderr: []u8,
    term: std.process.Child.Term,
    /// Stdout hit `view_stdout_cap` or the limit passed to `runCaptureLimited`.
    truncated: bool = false,

    pub fn deinit(self: *RunOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

/// Optional stand-in for `runCapture`. Headless tests use this so command
/// dispatch can run without spawning tshark.
pub const Runner = *const fn (std.mem.Allocator, std.Io, []const []const u8) anyerror!RunOutput;

pub const CancellationToken = struct {
    cancelled: std.atomic.Value(bool) = .init(false),
    mutex: std.Io.Mutex = .init,
    child: ?*std.process.Child = null,

    pub fn cancel(self: *CancellationToken, io: std.Io) void {
        self.cancelled.store(true, .release);
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.child) |child| reap(child, io);
    }

    pub fn isCancelled(self: *const CancellationToken) bool {
        return self.cancelled.load(.acquire);
    }

    pub fn reset(self: *CancellationToken) void {
        self.cancelled.store(false, .release);
    }

    pub fn bind(self: *CancellationToken, io: std.Io, child: *std.process.Child) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.child = child;
        if (self.cancelled.load(.acquire)) reap(child, io);
    }

    /// The worker is done with this child. Reap it if another thread has not
    /// already done so, then drop the binding.
    pub fn release(self: *CancellationToken, io: std.Io, child: *std.process.Child) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.child == child) self.child = null;
        reap(child, io);
    }

    pub fn waitUnlessCancelled(self: *CancellationToken, io: std.Io, child: *std.process.Child) !std.process.Child.Term {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.cancelled.load(.acquire) or child.id == null) {
            reap(child, io);
            return error.Cancelled;
        }
        return try child.wait(io);
    }
};

/// `Child.kill` panics in debug builds when the pid was already reaped
/// (`ESRCH`). Every kill of a shared child goes through here, under the token
/// mutex, and only while `id` is still set.
fn reap(child: *std.process.Child, io: std.Io) void {
    if (child.id == null) return;
    child.kill(io);
}

pub const Source = union(enum) {
    file: []const u8,
    interfaces: [][]const u8,
    stdin,
    fifo: []const u8,
};

/// A stable seven-column layout keeps packet rendering consistent across
/// Wireshark versions and user Wireshark preferences.
pub const default_column_format =
    "gui.column.format:\"No.\",\"%m\",\"Time\",\"%t\",\"Source\",\"%s\",\"Destination\",\"%d\",\"Protocol\",\"%p\",\"Length\",\"%L\",\"Info\",\"%i\"";

pub const delta_column_format =
    "gui.column.format:\"No.\",\"%m\",\"Time\",\"%t\",\"Delta\",\"%Gt\",\"Source\",\"%s\",\"Destination\",\"%d\",\"Protocol\",\"%p\",\"Length\",\"%L\",\"Info\",\"%i\"";

pub const absolute_column_format =
    "gui.column.format:\"No.\",\"%m\",\"Time\",\"%Yt\",\"Source\",\"%s\",\"Destination\",\"%d\",\"Protocol\",\"%p\",\"Length\",\"%L\",\"Info\",\"%i\"";

pub fn columnFormatOrDefault(format: ?[]const u8) []const u8 {
    if (format) |value| if (value.len != 0) return value;
    return default_column_format;
}

pub const view_stdout_cap: usize = 1024 * 1024;
pub const view_row_cap: usize = 200;

pub fn runCapture(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) !RunOutput {
    return runCaptureCancellable(allocator, io, argv, null);
}

/// Read stdout as tshark writes it. `on_chunk` sees each new slice before the
/// process exits. `saw_stdout` is set when any chunk is delivered, which keeps
/// the permission retry from parsing the same bytes twice.
pub fn runStdoutChunks(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    token: ?*CancellationToken,
    context: *anyopaque,
    on_chunk: *const fn (*anyopaque, []const u8) anyerror!void,
    saw_stdout: *bool,
) !RunOutput {
    var first = try runStdoutOnce(allocator, io, argv, token, context, on_chunk, saw_stdout);
    if (builtin.os.tag != .linux or first.term.success() or saw_stdout.*) return first;
    const path_index = deniedCaptureArg(argv, first.stderr) orelse return first;

    const copied = copyCaptureToTmp(allocator, io, argv[path_index]) catch return first;
    defer allocator.free(copied);
    defer std.Io.Dir.cwd().deleteFile(io, copied) catch {};

    const replaced = allocator.alloc([]const u8, argv.len) catch |err| {
        first.deinit(allocator);
        return err;
    };
    defer allocator.free(replaced);
    @memcpy(replaced, argv);
    replaced[path_index] = copied;

    const second = runStdoutOnce(allocator, io, replaced, token, context, on_chunk, saw_stdout) catch |err| {
        first.deinit(allocator);
        return err;
    };
    first.deinit(allocator);
    return second;
}

pub fn runCaptureCancellable(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    token: ?*CancellationToken,
) !RunOutput {
    var first = try runOnce(allocator, io, argv, token, null);
    if (builtin.os.tag != .linux or first.term.success()) return first;
    const path_index = deniedCaptureArg(argv, first.stderr) orelse return first;

    const copied = copyCaptureToTmp(allocator, io, argv[path_index]) catch return first;
    defer allocator.free(copied);
    defer std.Io.Dir.cwd().deleteFile(io, copied) catch {};

    const replaced = allocator.alloc([]const u8, argv.len) catch |err| {
        first.deinit(allocator);
        return err;
    };
    defer allocator.free(replaced);
    @memcpy(replaced, argv);
    replaced[path_index] = copied;

    const second = runOnce(allocator, io, replaced, token, null) catch |err| {
        first.deinit(allocator);
        return err;
    };
    first.deinit(allocator);
    return second;
}

pub fn runCaptureLimited(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    limit: usize,
) !RunOutput {
    var first = try runOnce(allocator, io, argv, null, limit);
    if (first.truncated or builtin.os.tag != .linux or first.term.success()) return first;
    const path_index = deniedCaptureArg(argv, first.stderr) orelse return first;

    const copied = copyCaptureToTmp(allocator, io, argv[path_index]) catch return first;
    defer allocator.free(copied);
    defer std.Io.Dir.cwd().deleteFile(io, copied) catch {};

    const replaced = allocator.alloc([]const u8, argv.len) catch |err| {
        first.deinit(allocator);
        return err;
    };
    defer allocator.free(replaced);
    @memcpy(replaced, argv);
    replaced[path_index] = copied;

    const second = runOnce(allocator, io, replaced, null, limit) catch |err| {
        first.deinit(allocator);
        return err;
    };
    first.deinit(allocator);
    return second;
}

/// Keep at most `limit` bytes, ending on a newline when one fits.
pub fn clipStdout(allocator: std.mem.Allocator, text: *[]u8, limit: usize) !bool {
    if (text.len <= limit) return false;
    const end = if (std.mem.lastIndexOfScalar(u8, text.*[0..limit], '\n')) |index| index + 1 else limit;
    const clipped = try allocator.dupe(u8, text.*[0..end]);
    allocator.free(text.*);
    text.* = clipped;
    return true;
}

fn runOnce(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    token: ?*CancellationToken,
    limit: ?usize,
) !RunOutput {
    if (token) |cancel| {
        if (cancel.isCancelled()) return error.Cancelled;
    }
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    if (token) |cancel| cancel.bind(io, &child);
    defer if (token) |cancel| {
        cancel.release(io, &child);
    } else if (child.id != null) {
        child.kill(io);
    };

    var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: std.Io.File.MultiReader = undefined;
    multi_reader.init(allocator, io, multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer multi_reader.deinit();

    var truncated = false;
    while (multi_reader.fill(4096, .none)) |_| {
        if (token) |cancel| {
            if (cancel.isCancelled()) return error.Cancelled;
        }
        if (limit) |max| {
            const stdout = multi_reader.reader(0);
            if (stdout.end - stdout.seek >= max) {
                truncated = true;
                break;
            }
        }
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => {
            if (token) |cancel| {
                if (cancel.isCancelled()) return error.Cancelled;
            }
            return err;
        },
    }
    const term = if (truncated) blk: {
        if (child.id != null) child.kill(io);
        break :blk std.process.Child.Term{ .unknown = 1 };
    } else if (token) |cancel|
        try cancel.waitUnlessCancelled(io, &child)
    else
        try child.wait(io);
    var stdout_slice = try multi_reader.toOwnedSlice(0);
    errdefer allocator.free(stdout_slice);
    if (limit) |max| {
        if (try clipStdout(allocator, &stdout_slice, max)) truncated = true;
    }
    const stderr_slice = try multi_reader.toOwnedSlice(1);
    return .{
        .stdout = stdout_slice,
        .stderr = stderr_slice,
        .term = term,
        .truncated = truncated,
    };
}

fn runStdoutOnce(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    token: ?*CancellationToken,
    context: *anyopaque,
    on_chunk: *const fn (*anyopaque, []const u8) anyerror!void,
    saw_stdout: *bool,
) !RunOutput {
    if (token) |cancel| {
        if (cancel.isCancelled()) return error.Cancelled;
    }
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    if (token) |cancel| cancel.bind(io, &child);
    defer if (token) |cancel| {
        cancel.release(io, &child);
    } else if (child.id != null) {
        child.kill(io);
    };

    var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: std.Io.File.MultiReader = undefined;
    multi_reader.init(allocator, io, multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer multi_reader.deinit();

    while (multi_reader.fill(4096, .none)) |_| {
        if (token) |cancel| {
            if (cancel.isCancelled()) return error.Cancelled;
        }
        const stdout = multi_reader.reader(0);
        const chunk = stdout.buffered();
        if (chunk.len != 0) {
            saw_stdout.* = true;
            try on_chunk(context, chunk);
            stdout.seek = stdout.end;
        }
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => {
            if (token) |cancel| {
                if (cancel.isCancelled()) return error.Cancelled;
            }
            return err;
        },
    }
    const term = if (token) |cancel|
        try cancel.waitUnlessCancelled(io, &child)
    else
        try child.wait(io);
    const stderr_slice = try multi_reader.toOwnedSlice(1);
    return .{
        .stdout = try allocator.alloc(u8, 0),
        .stderr = stderr_slice,
        .term = term,
    };
}

/// Ubuntu 26 confines tshark with AppArmor so it can read captures under `/tmp`
/// and almost nowhere else. The kernel reports that as EACCES.
fn deniedCaptureArg(argv: []const []const u8, stderr: []const u8) ?usize {
    if (std.mem.indexOf(u8, stderr, "don't have permission to read the file") == null) return null;
    var i: usize = 0;
    while (i + 1 < argv.len) : (i += 1) {
        if (!std.mem.eql(u8, argv[i], "-r")) continue;
        if (stderrQuotes(stderr, argv[i + 1])) return i + 1;
    }
    var j = argv.len;
    while (j > 1) {
        j -= 1;
        if (stderrQuotes(stderr, argv[j])) return j;
    }
    return null;
}

fn stderrQuotes(stderr: []const u8, path: []const u8) bool {
    if (path.len == 0 or std.mem.eql(u8, path, "-")) return false;
    if (path.len + 2 > 4096) return false;
    var buf: [4096]u8 = undefined;
    const quoted = std.fmt.bufPrint(buf[0 .. path.len + 2], "\"{s}\"", .{path}) catch return false;
    return std.mem.indexOf(u8, stderr, quoted) != null;
}

var temp_capture_seq: std.atomic.Value(u64) = .init(0);

fn copyCaptureToTmp(allocator: std.mem.Allocator, io: std.Io, src: []const u8) ![]u8 {
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const seq = temp_capture_seq.fetchAdd(1, .monotonic);
    const hex = std.fmt.bytesToHex(&nonce, .lower);
    const dest = try std.fmt.allocPrint(allocator, "/tmp/zigshark-{d}-{s}.pcap", .{ seq, hex[0..] });
    errdefer allocator.free(dest);
    const cwd = std.Io.Dir.cwd();
    errdefer cwd.deleteFile(io, dest) catch {};

    const in_file = try cwd.openFile(io, src, .{});
    defer in_file.close(io);
    const out_file = try cwd.createFile(io, dest, .{
        .truncate = true,
        .permissions = @fromBackingInt(@intCast(0o600)),
    });
    errdefer out_file.close(io);

    var buf: [64 * 1024]u8 = undefined;
    var iov: [1][]u8 = .{&buf};
    while (true) {
        const n = in_file.readStreaming(io, &iov) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        if (n == 0) break;
        try out_file.writeStreamingAll(io, buf[0..n]);
    }
    out_file.close(io);
    return dest;
}

pub const Argv = struct {
    list: std.ArrayList([]const u8) = .empty,

    pub fn deinit(self: *Argv, allocator: std.mem.Allocator) void {
        for (self.list.items) |s| allocator.free(s);
        self.list.deinit(allocator);
    }

    pub fn append(self: *Argv, allocator: std.mem.Allocator, s: []const u8) !void {
        try self.list.append(allocator, try allocator.dupe(u8, s));
    }

    pub fn slice(self: *const Argv) []const []const u8 {
        return self.list.items;
    }
};

pub fn argvPsmlLoad(
    allocator: std.mem.Allocator,
    tshark: []const u8,
    source: Source,
    display_filter: ?[]const u8,
    column_format: ?[]const u8,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-T");
    try a.append(allocator, "psml");
    try a.append(allocator, "-o");
    try a.append(allocator, columnFormatOrDefault(column_format));
    switch (source) {
        .file => |path| {
            try a.append(allocator, "-r");
            try a.append(allocator, path);
        },
        .stdin => {
            try a.append(allocator, "-l");
            try a.append(allocator, "-r");
            try a.append(allocator, "-");
        },
        .fifo => |path| {
            // A live file is still growing. Flush each packet so the UI can
            // paint rows before tshark reaches the current end.
            try a.append(allocator, "-l");
            try a.append(allocator, "-r");
            try a.append(allocator, path);
        },
        .interfaces => |ifaces| {
            for (ifaces) |iface| {
                try a.append(allocator, "-i");
                try a.append(allocator, iface);
            }
        },
    }
    if (display_filter) |f| {
        if (f.len != 0) {
            try a.append(allocator, "-Y");
            try a.append(allocator, f);
        }
    }
    return a;
}

pub fn argvPdmlBundle(
    allocator: std.mem.Allocator,
    tshark: []const u8,
    path: []const u8,
    display_filter: ?[]const u8,
    frame_start: u32,
    frame_end: u32,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    try a.append(allocator, "-T");
    try a.append(allocator, "pdml");
    try appendFrameRangeFilter(allocator, &a, display_filter, frame_start, frame_end);
    return a;
}

pub fn argvHexBundle(
    allocator: std.mem.Allocator,
    tshark: []const u8,
    path: []const u8,
    display_filter: ?[]const u8,
    frame_start: u32,
    frame_end: u32,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    try a.append(allocator, "-x");
    try appendFrameRangeFilter(allocator, &a, display_filter, frame_start, frame_end);
    return a;
}

fn appendFrameRangeFilter(
    allocator: std.mem.Allocator,
    a: *Argv,
    display_filter: ?[]const u8,
    frame_start: u32,
    frame_end: u32,
) !void {
    var buf: [512]u8 = undefined;
    const range = try std.fmt.bufPrint(&buf, "frame.number>={d} and frame.number<={d}", .{ frame_start, frame_end });
    const merged = blk: {
        if (display_filter) |f| {
            if (f.len == 0) break :blk try allocator.dupe(u8, range);
            const m = try std.fmt.allocPrint(allocator, "({s}) and ({s})", .{ f, range });
            break :blk m;
        }
        break :blk try allocator.dupe(u8, range);
    };
    defer allocator.free(merged);
    try a.append(allocator, "-Y");
    try a.append(allocator, merged);
}

pub fn argvFilterValidate(allocator: std.mem.Allocator, tshark: []const u8, empty_pcap: []const u8, filter: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, empty_pcap);
    try a.append(allocator, "-Y");
    try a.append(allocator, filter);
    return a;
}

pub fn argvFieldsDump(allocator: std.mem.Allocator, tshark: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-G");
    try a.append(allocator, "fields");
    return a;
}

pub fn argvColumnsDump(allocator: std.mem.Allocator, tshark: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-G");
    try a.append(allocator, "column-formats");
    return a;
}

pub fn argvFollowStream(allocator: std.mem.Allocator, tshark: []const u8, path: []const u8, proto: []const u8, stream_idx: u32) !Argv {
    return argvFollowStreamMode(allocator, tshark, path, proto, "ascii", stream_idx);
}

pub fn argvFollowStreamMode(
    allocator: std.mem.Allocator,
    tshark: []const u8,
    path: []const u8,
    proto: []const u8,
    mode: []const u8,
    stream_idx: u32,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    try a.append(allocator, "-q");
    var z: [128]u8 = undefined;
    const spec = try std.fmt.bufPrint(&z, "follow,{s},{s},{d}", .{ proto, mode, stream_idx });
    try a.append(allocator, "-z");
    try a.append(allocator, spec);
    return a;
}

pub fn argvConversations(allocator: std.mem.Allocator, tshark: []const u8, path: []const u8, conv_types: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    try a.append(allocator, "-q");
    try a.append(allocator, "-z");
    var z: [256]u8 = undefined;
    const spec = try std.fmt.bufPrint(&z, "conv,{s}", .{conv_types});
    try a.append(allocator, spec);
    return a;
}

pub fn argvHierarchy(allocator: std.mem.Allocator, tshark: []const u8, path: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    try a.append(allocator, "-q");
    try a.append(allocator, "-z");
    try a.append(allocator, "io,phs");
    return a;
}

pub fn argvEndpoints(allocator: std.mem.Allocator, tshark: []const u8, path: []const u8, kind: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    try a.append(allocator, "-q");
    try a.append(allocator, "-z");
    const spec = try std.fmt.allocPrint(allocator, "endpoints,{s}", .{kind});
    defer allocator.free(spec);
    try a.append(allocator, spec);
    return a;
}

pub fn argvExpert(allocator: std.mem.Allocator, tshark: []const u8, path: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    try a.append(allocator, "-q");
    try a.append(allocator, "-z");
    try a.append(allocator, "expert");
    return a;
}

pub fn argvIoStat(allocator: std.mem.Allocator, tshark: []const u8, path: []const u8, interval: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    try a.append(allocator, "-q");
    try a.append(allocator, "-z");
    const spec = try std.fmt.allocPrint(allocator, "io,stat,{s}", .{interval});
    defer allocator.free(spec);
    try a.append(allocator, spec);
    return a;
}

pub fn argvFieldDump(
    allocator: std.mem.Allocator,
    tshark: []const u8,
    path: []const u8,
    display_filter: []const u8,
    fields: []const []const u8,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    if (display_filter.len != 0) {
        try a.append(allocator, "-Y");
        try a.append(allocator, display_filter);
    }
    try a.append(allocator, "-T");
    try a.append(allocator, "fields");
    for (fields) |field| {
        try a.append(allocator, "-e");
        try a.append(allocator, field);
    }
    return a;
}

pub fn argvLua(allocator: std.mem.Allocator, tshark: []const u8, path: []const u8, script: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    try a.append(allocator, "-q");
    try a.append(allocator, "-X");
    const option = try std.fmt.allocPrint(allocator, "lua_script:{s}", .{script});
    defer allocator.free(option);
    try a.append(allocator, option);
    return a;
}

pub fn argvEditcapComment(
    allocator: std.mem.Allocator,
    editcap: []const u8,
    src: []const u8,
    dst: []const u8,
    frame: u32,
    comment: []const u8,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, editcap);
    const spec = try std.fmt.allocPrint(allocator, "{d}:{s}", .{ frame, comment });
    defer allocator.free(spec);
    try a.append(allocator, "-a");
    try a.append(allocator, spec);
    try a.append(allocator, src);
    try a.append(allocator, dst);
    return a;
}

pub fn argvProtocolList(allocator: std.mem.Allocator, tshark: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-G");
    try a.append(allocator, "protocols");
    return a;
}

pub fn argvExportPcap(
    allocator: std.mem.Allocator,
    tshark: []const u8,
    path: []const u8,
    display_filter: []const u8,
    out_path: []const u8,
    frame: ?u32,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    const filter = try exportFilter(allocator, display_filter, frame);
    defer allocator.free(filter);
    if (filter.len != 0) {
        try a.append(allocator, "-Y");
        try a.append(allocator, filter);
    }
    try a.append(allocator, "-F");
    try a.append(allocator, "pcapng");
    try a.append(allocator, "-w");
    try a.append(allocator, out_path);
    return a;
}

pub fn argvExportObjects(
    allocator: std.mem.Allocator,
    tshark: []const u8,
    path: []const u8,
    display_filter: []const u8,
    protocol: []const u8,
    directory: []const u8,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-r");
    try a.append(allocator, path);
    try a.append(allocator, "-q");
    if (display_filter.len != 0) {
        try a.append(allocator, "-Y");
        try a.append(allocator, display_filter);
    }
    const spec = try std.fmt.allocPrint(allocator, "{s},{s}", .{ protocol, directory });
    defer allocator.free(spec);
    try a.append(allocator, "--export-objects");
    try a.append(allocator, spec);
    return a;
}

fn exportFilter(allocator: std.mem.Allocator, display_filter: []const u8, frame: ?u32) ![]u8 {
    if (frame) |number| {
        if (display_filter.len == 0) return std.fmt.allocPrint(allocator, "frame.number == {d}", .{number});
        return std.fmt.allocPrint(allocator, "({s}) and frame.number == {d}", .{ display_filter, number });
    }
    return allocator.dupe(u8, display_filter);
}

pub fn argvCapinfos(allocator: std.mem.Allocator, capinfos: []const u8, path: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, capinfos);
    try a.append(allocator, path);
    return a;
}

pub fn argvInterfaceList(allocator: std.mem.Allocator, tshark: []const u8) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    try a.append(allocator, "-D");
    return a;
}

pub fn argvDumpcapLive(
    allocator: std.mem.Allocator,
    dumpcap: []const u8,
    interfaces: []const []const u8,
    capture_filter: ?[]const u8,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, dumpcap);
    // Packet counts go to stderr. An unread pipe fills and dumpcap blocks
    // before it flushes packets.
    try a.append(allocator, "-q");
    for (interfaces) |iface| {
        try a.append(allocator, "-i");
        try a.append(allocator, iface);
    }
    // stdout is the capture. dumpcap drops privileges before it would create
    // -w, so a path in the user's directory fails even under sudo.
    try a.append(allocator, "-w");
    try a.append(allocator, "-");
    if (capture_filter) |f| {
        if (f.len != 0) {
            try a.append(allocator, "-f");
            try a.append(allocator, f);
        }
    }
    return a;
}

pub fn argvTsharkLiveFallback(
    allocator: std.mem.Allocator,
    tshark: []const u8,
    interfaces: []const []const u8,
    capture_filter: ?[]const u8,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    // `-Q` stops the running packet count. Same deadlock as dumpcap without `-q`.
    try a.append(allocator, "-Q");
    for (interfaces) |iface| {
        try a.append(allocator, "-i");
        try a.append(allocator, iface);
    }
    try a.append(allocator, "-w");
    try a.append(allocator, "-");
    if (capture_filter) |f| {
        if (f.len != 0) {
            try a.append(allocator, "-f");
            try a.append(allocator, f);
        }
    }
    return a;
}

/// tshark exits non-zero with this text when it reads a capture that is still
/// being written. The packets before the short read are valid.
pub fn isTruncatedCapture(stderr: []const u8) bool {
    return std.mem.indexOf(u8, stderr, "cut short in the middle of a packet") != null;
}

test "argv builders produce expected heads" {
    const allocator = std.testing.allocator;
    var psml = try argvPsmlLoad(allocator, "/usr/bin/tshark", .{ .file = "/tmp/x.pcap" }, "tcp", null);
    defer psml.deinit(allocator);
    try std.testing.expectEqualStrings("/usr/bin/tshark", psml.list.items[0]);
    try std.testing.expectEqual(@as(usize, 9), psml.list.items.len);
    try std.testing.expectEqualStrings(default_column_format, psml.list.items[4]);

    var validate = try argvFilterValidate(allocator, "tshark", "tests/fixtures/empty.pcap", "tcp");
    defer validate.deinit(allocator);
    try std.testing.expect(std.mem.eql(u8, validate.list.items[validate.list.items.len - 1], "tcp"));
}

test "read denial selects the capture path" {
    const stderr = "tshark: You don't have permission to read the file \"tests/fixtures/1.pcap\".\n";
    const tshark_argv = [_][]const u8{ "tshark", "-r", "tests/fixtures/1.pcap", "-T", "psml" };
    try std.testing.expectEqual(@as(?usize, 2), deniedCaptureArg(&tshark_argv, stderr));
    try std.testing.expect(deniedCaptureArg(&tshark_argv, "tshark: syntax error\n") == null);

    const capinfos_argv = [_][]const u8{ "capinfos", "tests/fixtures/1.pcap" };
    try std.testing.expectEqual(@as(?usize, 1), deniedCaptureArg(&capinfos_argv, stderr));
    const stdin_argv = [_][]const u8{ "tshark", "-r", "-", "-T", "psml" };
    const stdin_err = "tshark: You don't have permission to read the file \"-\".\n";
    try std.testing.expect(deniedCaptureArg(&stdin_argv, stdin_err) == null);

    const short = "tshark: The file \"live.pcapng\" appears to have been cut short in the middle of a packet.\n";
    try std.testing.expect(isTruncatedCapture(short));
    try std.testing.expect(!isTruncatedCapture("tshark: syntax error\n"));
}

test "live capture argv stays quiet and flushes packet rows" {
    const allocator = std.testing.allocator;
    var dump = try argvDumpcapLive(allocator, "dumpcap", &.{ "eth0", "wlan0" }, "tcp");
    defer dump.deinit(allocator);
    try std.testing.expectEqualStrings("dumpcap", dump.list.items[0]);
    try std.testing.expectEqualStrings("-q", dump.list.items[1]);
    try std.testing.expectEqualStrings("eth0", dump.list.items[3]);
    try std.testing.expectEqualStrings("wlan0", dump.list.items[5]);
    try std.testing.expectEqualStrings("-", dump.list.items[7]);
    try std.testing.expectEqualStrings("tcp", dump.list.items[dump.list.items.len - 1]);

    var fallback = try argvTsharkLiveFallback(allocator, "tshark", &.{"eth0"}, null);
    defer fallback.deinit(allocator);
    try std.testing.expectEqualStrings("-Q", fallback.list.items[1]);

    var live = try argvPsmlLoad(allocator, "tshark", .{ .fifo = "out.pcap" }, null, null);
    defer live.deinit(allocator);
    try std.testing.expectEqualStrings("-l", live.list.items[5]);
    try std.testing.expectEqualStrings("-r", live.list.items[6]);
    try std.testing.expectEqualStrings("out.pcap", live.list.items[7]);
}

fn fakeTsharkPath(allocator: std.mem.Allocator) ![]u8 {
    const name = if (builtin.os.tag == .windows) "fake-tshark.exe" else "fake-tshark";
    return std.fmt.allocPrint(allocator, "zig-out/bin/{s}", .{name});
}

test "a capped capture stops reading and keeps a prefix" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const tool = try fakeTsharkPath(allocator);
    defer allocator.free(tool);
    const argv = [_][]const u8{tool};
    const before = std.Io.Timestamp.now(io, .awake).nanoseconds;
    var out = try runCaptureLimited(allocator, io, &argv, 48);
    defer out.deinit(allocator);
    const after = std.Io.Timestamp.now(io, .awake).nanoseconds;
    try std.testing.expect(out.truncated);
    try std.testing.expect(out.stdout.len <= 48);
    try std.testing.expect(std.mem.startsWith(u8, out.stdout, "row "));
    try std.testing.expect(after - before < 3 * std.time.ns_per_s);
}
