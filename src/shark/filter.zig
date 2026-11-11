const std = @import("std");
const process = @import("process.zig");

pub fn validateDisplayFilter(
    allocator: std.mem.Allocator,
    io: std.Io,
    tshark: []const u8,
    empty_pcap: []const u8,
    filter: []const u8,
) !bool {
    if (filter.len == 0) return true;

    var argv = try process.argvFilterValidate(allocator, tshark, empty_pcap, filter);
    defer argv.deinit(allocator);

    var out = try process.runCapture(allocator, io, argv.slice());
    defer out.deinit(allocator);

    if (out.term.success()) return true;

    const err_text = out.stderr;
    if (std.mem.indexOf(u8, err_text, "syntax error") != null or
        std.mem.indexOf(u8, err_text, "doesn't support") != null or
        std.mem.indexOf(u8, err_text, "not a valid") != null)
    {
        return false;
    }

  // Non-zero exit without syntax hints still means invalid for empty capture.
    return false;
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
