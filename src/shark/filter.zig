const std = @import("std");
const process = @import("process.zig");

pub fn validateDisplayFilter(
    allocator: std.mem.Allocator,
    io: std.Io,
    tshark: []const u8,
    empty_pcap: []const u8,
    filter: []const u8,
) !bool {
    return validateDisplayFilterRun(allocator, io, tshark, empty_pcap, filter, null);
}

pub const FilterVerdict = struct {
    ok: bool,
    /// First tshark error line, or empty when the filter is accepted.
    detail: []u8,

    pub fn deinit(self: *FilterVerdict, allocator: std.mem.Allocator) void {
        allocator.free(self.detail);
    }
};

pub fn explainDisplayFilter(
    allocator: std.mem.Allocator,
    io: std.Io,
    tshark: []const u8,
    empty_pcap: []const u8,
    filter: []const u8,
    runner: ?process.Runner,
    token: ?*process.CancellationToken,
) !FilterVerdict {
    if (filter.len == 0) return .{ .ok = true, .detail = try allocator.dupe(u8, "") };

    var argv = try process.argvFilterValidate(allocator, tshark, empty_pcap, filter);
    defer argv.deinit(allocator);

    var out = if (runner) |run|
        try run(allocator, io, argv.slice())
    else
        try process.runCaptureCancellable(allocator, io, argv.slice(), token);
    defer out.deinit(allocator);

    if (out.term.success()) return .{ .ok = true, .detail = try allocator.dupe(u8, "") };
    return .{ .ok = false, .detail = try firstErrorLine(allocator, out.stderr) };
}

pub fn validateDisplayFilterRun(
    allocator: std.mem.Allocator,
    io: std.Io,
    tshark: []const u8,
    empty_pcap: []const u8,
    filter: []const u8,
    runner: ?process.Runner,
) !bool {
    var verdict = try explainDisplayFilter(allocator, io, tshark, empty_pcap, filter, runner, null);
    defer verdict.deinit(allocator);
    return verdict.ok;
}

fn firstErrorLine(allocator: std.mem.Allocator, stderr: []const u8) ![]u8 {
    var line = std.mem.trim(u8, stderr, " \t\r\n");
    if (std.mem.indexOfAny(u8, line, "\r\n")) |end| line = std.mem.trim(u8, line[0..end], " \t");
    if (std.mem.startsWith(u8, line, "tshark:")) {
        line = std.mem.trim(u8, line["tshark:".len..], " \t");
    }
    if (line.len == 0) line = "invalid display filter";
    return allocator.dupe(u8, line);
}

test "empty filter is valid" {
    try std.testing.expect(try validateDisplayFilter(
        std.testing.allocator,
        std.testing.io,
        "tshark",
        "tests/fixtures/empty.pcap",
        "",
    ));
}

test "invalid filter keeps the tshark error line" {
    const allocator = std.testing.allocator;
    const runner = struct {
        fn run(alloc: std.mem.Allocator, _: std.Io, _: []const []const u8) !process.RunOutput {
            return .{
                .stdout = try alloc.dupe(u8, ""),
                .stderr = try alloc.dupe(u8, "tshark: \"nope\" was unexpected in this context\n"),
                .term = .{ .exited = 1 },
            };
        }
    }.run;
    var verdict = try explainDisplayFilter(allocator, std.testing.io, "tshark", "empty.pcap", "nope", runner, null);
    defer verdict.deinit(allocator);
    try std.testing.expect(!verdict.ok);
    try std.testing.expectEqualStrings("\"nope\" was unexpected in this context", verdict.detail);
}

test "filter validation with tshark" {
    const io = std.testing.io;
    const tools = @import("tools.zig");
    if (!tools.tsharkAvailable(io)) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var discovered = try tools.discover(allocator, io, .{
        .tshark = "tshark",
        .dumpcap = "dumpcap",
        .capinfos = "capinfos",
    });
    defer discovered.deinit();

    const empty = "tests/fixtures/empty.pcap";
    try std.testing.expect(try validateDisplayFilter(allocator, io, discovered.tshark, empty, "tcp"));
    try std.testing.expect(!try validateDisplayFilter(allocator, io, discovered.tshark, empty, "tcp and ()"));
}
