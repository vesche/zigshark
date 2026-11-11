const std = @import("std");

pub const TransferError = error{
    WormholeNotFound,
    WormholeFailed,
} || std.process.SpawnError || std.process.Child.WaitError;

pub fn wormholeAvailable(io: std.Io) bool {
    const result = std.process.run(std.heap.page_allocator, io, .{
        .argv = &.{ "wormhole", "--version" },
        .stdout_limit = .limited(512),
        .stderr_limit = .limited(512),
    }) catch return false;
    defer std.heap.page_allocator.free(result.stdout);
    defer std.heap.page_allocator.free(result.stderr);
    return result.term.success();
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
        if (!wormholeAvailable(io)) return error.WormholeNotFound;
        const job = try allocator.create(Job);
        job.* = .{ .allocator = allocator, .io = io };
        const owned_path = try allocator.dupe(u8, path);
        job.thread = try std.Thread.spawn(.{}, runJob, .{ job, owned_path });
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

fn runJob(job: *Job, path: []u8) void {
    defer job.allocator.free(path);
    defer job.finished.store(true, .release);
    job.append("Sending ");
    job.append(path);
    job.append("\n");

    var child = std.process.spawn(job.io, .{
        .argv = &.{ "wormhole", "send", path },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch {
        job.append("failed to start wormhole\n");
        return;
    };
    defer child.kill(job.io);

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
        job.append("\nwormhole failed\n");
        return;
    };
    if (!term.success()) job.append("\nwormhole failed\n");
}
