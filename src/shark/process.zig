const std = @import("std");
const builtin = @import("builtin");

pub const RunOutput = struct {
    stdout: []u8,
    stderr: []u8,
    term: std.process.Child.Term,

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

    fn bind(self: *CancellationToken, io: std.Io, child: *std.process.Child) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.child = child;
        if (self.cancelled.load(.acquire)) reap(child, io);
    }

    /// The worker is done with this child. Reap it if another thread has not
    /// already done so, then drop the binding.
    fn release(self: *CancellationToken, io: std.Io, child: *std.process.Child) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.child == child) self.child = null;
        reap(child, io);
    }

    fn waitUnlessCancelled(self: *CancellationToken, io: std.Io, child: *std.process.Child) !std.process.Child.Term {
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

pub fn runCapture(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) !RunOutput {
    return runCaptureCancellable(allocator, io, argv, null);
}

pub fn runCaptureCancellable(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    token: ?*CancellationToken,
) !RunOutput {
    var first = try runOnce(allocator, io, argv, token);
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

    const second = runOnce(allocator, io, replaced, token) catch |err| {
        first.deinit(allocator);
        return err;
    };
    first.deinit(allocator);
    return second;
}

fn runOnce(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    token: ?*CancellationToken,
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
    const stdout_slice = try multi_reader.toOwnedSlice(0);
    errdefer allocator.free(stdout_slice);
    const stderr_slice = try multi_reader.toOwnedSlice(1);
    return .{
        .stdout = stdout_slice,
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
            try a.append(allocator, "-r");
            try a.append(allocator, "-");
        },
        .fifo => |path| {
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
    out_path: []const u8,
    capture_filter: ?[]const u8,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, dumpcap);
    for (interfaces) |iface| {
        try a.append(allocator, "-i");
        try a.append(allocator, iface);
    }
    try a.append(allocator, "-w");
    try a.append(allocator, out_path);
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
    out_path: []const u8,
    capture_filter: ?[]const u8,
) !Argv {
    var a: Argv = .{};
    errdefer a.deinit(allocator);
    try a.append(allocator, tshark);
    for (interfaces) |iface| {
        try a.append(allocator, "-i");
        try a.append(allocator, iface);
    }
    try a.append(allocator, "-w");
    try a.append(allocator, out_path);
    if (capture_filter) |f| {
        if (f.len != 0) {
            try a.append(allocator, "-f");
            try a.append(allocator, f);
        }
    }
    return a;
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
}
