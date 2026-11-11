const std = @import("std");

pub const TransferError = error{
    WormholeNotFound,
    WormholeFailed,
} || std.process.SpawnError || std.process.Child.WaitError;

fn commandAvailable(io: std.Io, command: []const u8) bool {
    const result = std.process.run(std.heap.page_allocator, io, .{
        .argv = &.{ command, "--version" },
        .stdout_limit = .limited(512),
        .stderr_limit = .limited(512),
    }) catch return false;
    defer std.heap.page_allocator.free(result.stdout);
    defer std.heap.page_allocator.free(result.stderr);
    return result.term.success();
}

pub fn wormholeAvailable(io: std.Io) bool {
    return commandAvailable(io, "wormhole");
}

pub fn sendFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8) TransferError!void {
    if (!wormholeAvailable(io)) return error.WormholeNotFound;
    var child = try std.process.spawn(io, .{
        .argv = &.{ "wormhole", "send", path },
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    if (!term.success()) return error.WormholeFailed;
    _ = allocator;
}

pub const Job = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    log: std.ArrayList(u8) = .empty,
    finished: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    pub fn start(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !*Job {
        return startNamed(allocator, io, "wormhole", path);
    }

    fn startNamed(allocator: std.mem.Allocator, io: std.Io, tool: []const u8, path: []const u8) !*Job {
        if (!commandAvailable(io, tool)) return error.WormholeNotFound;
        return startArgv(allocator, io, &.{ tool, "send", path });
    }

    fn startArgv(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) !*Job {
        const job = try allocator.create(Job);
        errdefer allocator.destroy(job);
        job.* = .{ .allocator = allocator, .io = io };
        const owned = try allocator.alloc([]u8, argv.len);
        errdefer allocator.free(owned);
        var filled: usize = 0;
        errdefer {
            for (owned[0..filled]) |arg| allocator.free(arg);
        }
        for (argv) |arg| {
            owned[filled] = try allocator.dupe(u8, arg);
            filled += 1;
        }
        job.thread = try std.Thread.spawn(.{}, runJob, .{ job, owned });
        return job;
    }

    pub fn isFinished(self: *const Job) bool {
        return self.finished.load(.acquire);
    }

    pub fn snapshot(self: *Job, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.log.items.len == 0) return allocator.dupe(u8, "Sending via wormhole…");
        return allocator.dupe(u8, self.log.items);
    }

    pub fn destroy(self: *Job) void {
        if (self.thread) |thread| thread.join();
        self.log.deinit(self.allocator);
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    fn append(self: *Job, bytes: []const u8) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.log.appendSlice(self.allocator, bytes) catch {};
    }
};

fn runJob(job: *Job, argv: [][]u8) void {
    defer {
        for (argv) |arg| job.allocator.free(arg);
        job.allocator.free(argv);
        job.finished.store(true, .release);
    }

    var child = std.process.spawn(job.io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch {
        job.append("failed to start wormhole\n");
        return;
    };

    var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: std.Io.File.MultiReader = undefined;
    multi_reader.init(job.allocator, job.io, multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer multi_reader.deinit();
    const stdout_reader = multi_reader.reader(0);
    const stderr_reader = multi_reader.reader(1);
    var stdout_seen: usize = 0;
    var stderr_seen: usize = 0;
    while (multi_reader.fill(256, .none)) |_| {
        const out = stdout_reader.buffered();
        if (out.len > stdout_seen) {
            job.append(out[stdout_seen..]);
            stdout_seen = out.len;
        }
        const err = stderr_reader.buffered();
        if (err.len > stderr_seen) {
            job.append(err[stderr_seen..]);
            stderr_seen = err.len;
        }
    } else |_| {}
    const term = child.wait(job.io) catch {
        if (child.id != null) child.kill(job.io);
        job.append("\nwormhole failed\n");
        return;
    };
    if (!term.success()) job.append("\nwormhole failed\n");
}

fn waitJob(job: *Job, io: std.Io) !void {
    var spins: usize = 0;
    while (!job.isFinished()) : (spins += 1) {
        if (spins > 200) return error.TimedOut;
        try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    }
}

test "wormhole reports a missing binary without using the network" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    try std.testing.expectError(
        error.WormholeNotFound,
        Job.startNamed(allocator, io, "zigshark-missing-wormhole", "x.pcap"),
    );

    const job = try Job.startArgv(allocator, io, &.{"/no/such/zigshark-wormhole"});
    defer job.destroy();
    try waitJob(job, io);
    const text = try job.snapshot(allocator);
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "failed to start wormhole") != null);
}

test "wormhole job keeps a progress line and failure text" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/fake-wormhole", .{tmp.sub_path[0..]});
    defer allocator.free(path);
    const script =
        \\#!/bin/sh
        \\printf 'sending 1/2\n'
        \\exit 1
    ;
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = script,
        .flags = .{ .permissions = @fromBackingInt(@intCast(0o755)) },
    });

    const job = try Job.startArgv(allocator, io, &.{path});
    defer job.destroy();
    try waitJob(job, io);
    const text = try job.snapshot(allocator);
    defer allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "sending 1/2") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "wormhole failed") != null);
}
