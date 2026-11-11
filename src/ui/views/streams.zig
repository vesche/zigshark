const std = @import("std");
const process = @import("../../shark/process.zig");
const streams = @import("../../shark/streams.zig");

pub const FollowLoad = struct {
    body: []u8,
    capped: bool,
};

pub fn loadFollow(
    allocator: std.mem.Allocator,
    io: std.Io,
    tshark: []const u8,
    path: []const u8,
    stream_index: u32,
    proto: []const u8,
    mode: []const u8,
    runner: ?process.Runner,
) !FollowLoad {
    var argv = try process.argvFollowStreamMode(
        allocator,
        tshark,
        path,
        proto,
        mode,
        stream_index,
    );
    defer argv.deinit(allocator);

    var out = if (runner) |run|
        try run(allocator, io, argv.slice())
    else
        try process.runCaptureLimited(allocator, io, argv.slice(), process.view_stdout_cap);
    defer out.deinit(allocator);
    var capped = out.truncated;
    if (try process.clipStdout(allocator, &out.stdout, process.view_stdout_cap)) capped = true;

    if (out.stdout.len == 0) {
        return .{
            .body = try std.fmt.allocPrint(
                allocator,
                "No {s} stream {d} found in {s}\n{s}",
                .{ proto, stream_index, path, out.stderr },
            ),
            .capped = false,
        };
    }
    if (std.ascii.eqlIgnoreCase(mode, "raw")) {
        var parsed = streams.parse(allocator, out.stdout) catch {
            return .{ .body = try allocator.dupe(u8, out.stdout), .capped = capped };
        };
        defer parsed.deinit(allocator);
        const shown = @min(parsed.chunks.len, process.view_row_cap);
        if (shown < parsed.chunks.len) capped = true;
        var result: std.Io.Writer.Allocating = .init(allocator);
        errdefer result.deinit();
        try result.writer.print(
            "{s} stream {d}\n{s}\n\nClient: {s}\nServer: {s}\n\n",
            .{ proto, stream_index, parsed.filter, parsed.node0, parsed.node1 },
        );
        for (parsed.chunks[0..shown]) |chunk| {
            try result.writer.print(
                "[{s}]\n",
                .{if (chunk.direction == .client) "client -> server" else "server -> client"},
            );
            for (chunk.data, 0..) |byte, index| {
                if (index != 0) try result.writer.writeByte(' ');
                try result.writer.print("{x:0>2}", .{byte});
                if ((index + 1) % 16 == 0) try result.writer.writeByte('\n');
            }
            try result.writer.writeAll("\n\n");
        }
        if (capped) try result.writer.writeAll("Stopped at the output cap. The rest was not loaded.\n");
        return .{ .body = try result.toOwnedSlice(), .capped = capped };
    }
    return .{ .body = try allocator.dupe(u8, out.stdout), .capped = capped };
}

pub fn loadPlaceholder(allocator: std.mem.Allocator) ![]u8 {
    return try allocator.dupe(u8, "Run :streams [index] after loading a capture.");
}
