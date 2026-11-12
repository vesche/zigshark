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
    if (try detailStandIn(allocator, io, args, path)) return;
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

const DetailMode = enum { wait, sleep, fast };

fn detailMode(path: []const u8) ?DetailMode {
    if (std.mem.indexOf(u8, path, "bothwait") != null) return .wait;
    if (std.mem.indexOf(u8, path, "bothsleep") != null) return .sleep;
    if (std.mem.indexOf(u8, path, "bothfast") != null) return .fast;
    return null;
}

fn outputKind(args: []const []const u8) []const u8 {
    if (argAfter(args, "-T")) |format| {
        if (std.mem.eql(u8, format, "pdml")) return "pdml";
    }
    if (hasArg(args, "-x")) return "hex";
    return "psml";
}

fn hasArg(args: []const []const u8, flag: []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, flag)) return true;
    }
    return false;
}

/// Detail-load stand-in. `bothwait` blocks until `<path>.release`. `bothsleep`
/// sleeps long enough that a test fails if the child is not killed. `bothfast`
/// prints one frame and exits. PDML and hex each write their own marker.
fn detailStandIn(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    path: []const u8,
) !bool {
    const mode = detailMode(path) orelse return false;
    const kind = outputKind(args);
    var suffix_buf: [32]u8 = undefined;
    const started = std.fmt.bufPrint(&suffix_buf, ".{s}.started", .{kind}) catch return error.Unexpected;
    try writeMarker(allocator, io, path, started, "started\n");
    switch (mode) {
        .wait => try waitFor(allocator, io, path, ".release"),
        .sleep => try std.Io.sleep(io, .fromSeconds(8), .awake),
        .fast => {},
    }
    try writeDetail(io, path, kind);
    const finished = std.fmt.bufPrint(&suffix_buf, ".{s}.finished", .{kind}) catch return error.Unexpected;
    try writeMarker(allocator, io, path, finished, "finished\n");
    return true;
}

fn writeDetail(io: std.Io, path: []const u8, kind: []const u8) !void {
    const frame: u32 = if (std.mem.indexOf(u8, path, "bothfast") != null) 7 else 2;
    var buf: [320]u8 = undefined;
    if (std.mem.eql(u8, kind, "pdml")) {
        const xml = std.fmt.bufPrint(&buf, "<pdml><packet><proto name=\"frame\" showname=\"Frame {d}\" size=\"1\" pos=\"0\"><field name=\"frame.number\" show=\"{d}\" showname=\"Frame Number: {d}\" size=\"0\" pos=\"0\"/></proto></packet></pdml>\n", .{ frame, frame, frame }) catch return error.Unexpected;
        try writeStdout(io, xml);
        return;
    }
    if (std.mem.eql(u8, kind, "hex")) {
        try writeStdout(io, "0000  aa\n");
        return;
    }
    const xml = std.fmt.bufPrint(&buf, "<psml><packet><section>{d}</section></packet></psml>\n", .{frame}) catch return error.Unexpected;
    try writeStdout(io, xml);
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
