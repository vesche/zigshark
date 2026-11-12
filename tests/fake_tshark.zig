const std = @import("std");

/// Stand-in for tshark in tests. A shell script is not a valid Windows executable.
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    const capture = argAfter(args, "-r");
    if (capture == null) {
        if (argAfter(args, "-G") != null) {
            try std.Io.sleep(io, .fromSeconds(8), .awake);
            try writeStdout(io, "F\tField name\ttcp.port\n");
            return;
        }
        try flood(io);
        return;
    }
    const path = capture.?;
    if (std.mem.indexOf(u8, path, "hold") != null) {
        try writeMarker(allocator, io, path, ".started", "started\n");
        try waitFor(allocator, io, path, ".release");
        try writeStdout(io, "<psml><packet><section>1</section></packet></psml>\n");
        return;
    }
    if (std.mem.indexOf(u8, path, "slow") != null) {
        try writeMarker(allocator, io, path, ".started", "started\n");
        try std.Io.sleep(io, .fromSeconds(5), .awake);
        try writeMarker(allocator, io, path, ".finished", "finished\n");
        try writeStdout(io, "<psml><packet><section>4</section></packet></psml>\n");
        return;
    }
    if (std.mem.indexOf(u8, path, "stream") != null) {
        try writeMarker(allocator, io, path, ".started", "started\n");
        try writeStdout(io, "<psml><structure><section>No.</section></structure><packet><section>1</section></packet>\n");
        try waitFor(allocator, io, path, ".release");
        try writeStdout(io, "<packet><section>2</section></packet></psml>\n");
        return;
    }
    try writeStdout(io, "<psml><packet><section>9</section></packet></psml>\n");
}

fn argAfter(args: []const []const u8, flag: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 1 < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], flag)) return args[i + 1];
    }
    return null;
}

fn flood(io: std.Io) !void {
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        var buf: [32]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "row {d}\n", .{i});
        try writeStdout(io, line);
    }
    while (true) try std.Io.sleep(io, .fromSeconds(60), .awake);
}

fn writeStdout(io: std.Io, text: []const u8) !void {
    var buffer: [512]u8 = undefined;
    var writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
    try writer.interface.writeAll(text);
    try writer.interface.flush();
}

fn writeMarker(
    allocator: std.mem.Allocator,
    io: std.Io,
    capture: []const u8,
    suffix: []const u8,
    body: []const u8,
) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ capture, suffix });
    defer allocator.free(path);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = body });
}

fn waitFor(allocator: std.mem.Allocator, io: std.Io, capture: []const u8, suffix: []const u8) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ capture, suffix });
    defer allocator.free(path);
    const cwd = std.Io.Dir.cwd();
    while (true) {
        if (cwd.access(io, path, .{})) |_| return else |_| {
            try std.Io.sleep(io, .fromMilliseconds(20), .awake);
        }
    }
}
