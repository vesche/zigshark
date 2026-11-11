const std = @import("std");
const process = @import("../../shark/process.zig");
const streams = @import("../../shark/streams.zig");

pub fn loadFollow(
    allocator: std.mem.Allocator,
    io: std.Io,
    tshark: []const u8,
    path: []const u8,
    stream_index: u32,
    proto: []const u8,
    mode: []const u8,
    runner: ?process.Runner,
) ![]u8 {
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
        try process.runCapture(allocator, io, argv.slice());
    defer out.deinit(allocator);

    if (out.stdout.len == 0) {
        return try std.fmt.allocPrint(
            allocator,
            "No {s} stream {d} found in {s}\n{s}",
            .{ proto, stream_index, path, out.stderr },
        );
    }
    if (std.ascii.eqlIgnoreCase(mode, "raw")) {
        var parsed = streams.parse(allocator, out.stdout) catch {
            return try allocator.dupe(u8, out.stdout);
        };
        defer parsed.deinit(allocator);
        var result: std.Io.Writer.Allocating = .init(allocator);
        errdefer result.deinit();
        try result.writer.print(
            "{s} stream {d}\n{s}\n\nClient: {s}\nServer: {s}\n\n",
            .{ proto, stream_index, parsed.filter, parsed.node0, parsed.node1 },
        );
        for (parsed.chunks) |chunk| {
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
        return result.toOwnedSlice();
    }
    return try allocator.dupe(u8, out.stdout);
}

pub fn loadPlaceholder(allocator: std.mem.Allocator) ![]u8 {
    return try allocator.dupe(u8, "Run :streams [index] after loading a capture.");
}
