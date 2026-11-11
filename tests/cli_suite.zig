const std = @import("std");
const cli = @import("zigshark").cli;

test "file shorthand carries the display filter" {
    const allocator = std.testing.allocator;
    const args = [_][]const u8{ "zigshark", "capture.pcap", "-Y", "tcp.port == 443" };
    var opts = try cli.parse(allocator, &args);
    defer opts.deinit(allocator);
    try std.testing.expect(opts.command == .open);
    try std.testing.expectEqualStrings("capture.pcap", opts.file.?);
    try std.testing.expectEqualStrings("tcp.port == 443", opts.display_filter.?);
}

test "stdin dash is a file" {
    const allocator = std.testing.allocator;
    const args = [_][]const u8{ "zigshark", "-r", "-" };
    var opts = try cli.parse(allocator, &args);
    defer opts.deinit(allocator);
    try std.testing.expectEqualStrings("-", opts.file.?);
}

test "capture options accumulate" {
    const allocator = std.testing.allocator;
    const args = [_][]const u8{
        "zigshark", "capture",
        "-i",       "eth0",
        "-i",       "wlan0",
        "-f",       "not port 22",
        "-w",       "out.pcap",
        "-d",       "tcp.port==80,http",
        "-t",       "a",
        "-C",       "work",
    };
    var opts = try cli.parse(allocator, &args);
    defer opts.deinit(allocator);
    try std.testing.expect(opts.command == .capture);
    try std.testing.expectEqual(@as(usize, 2), opts.interfaces.items.len);
    try std.testing.expectEqualStrings("not port 22", opts.capture_filter.?);
    try std.testing.expectEqualStrings("out.pcap", opts.write_file.?);
    try std.testing.expectEqualStrings("tcp.port==80,http", opts.decode_as.items[0]);
    try std.testing.expectEqualStrings("a", opts.timestamp_format.?);
    try std.testing.expectEqualStrings("work", opts.profile.?);
}

test "pass-through modes and forced tty" {
    const allocator = std.testing.allocator;
    const always = [_][]const u8{ "zigshark", "--pass-thru=always", "x.pcap" };
    var always_opts = try cli.parse(allocator, &always);
    defer always_opts.deinit(allocator);
    try std.testing.expect(always_opts.pass_thru == .always);

    const never = [_][]const u8{ "zigshark", "--pass-thru=never" };
    var never_opts = try cli.parse(allocator, &never);
    defer never_opts.deinit(allocator);
    try std.testing.expect(never_opts.pass_thru == .never);

    const tty = [_][]const u8{ "zigshark", "--tty", "/dev/tty", "--log-tty" };
    var tty_opts = try cli.parse(allocator, &tty);
    defer tty_opts.deinit(allocator);
    try std.testing.expect(tty_opts.force_tty);
    try std.testing.expect(tty_opts.log_tty);
}

test "help and version are local commands" {
    const allocator = std.testing.allocator;
    const help_args = [_][]const u8{ "zigshark", "--help" };
    var help_opts = try cli.parse(allocator, &help_args);
    defer help_opts.deinit(allocator);
    try std.testing.expect(help_opts.command == .help);
    try std.testing.expect(help_opts.print_help);

    const version_args = [_][]const u8{ "zigshark", "-vv" };
    var version_opts = try cli.parse(allocator, &version_args);
    defer version_opts.deinit(allocator);
    try std.testing.expect(version_opts.print_version);
    try std.testing.expect(version_opts.version_verbose);
}

test "missing arguments and unknown flags fail" {
    const allocator = std.testing.allocator;
    const missing = [_][]const u8{ "zigshark", "-Y" };
    try std.testing.expectError(error.MissingArgument, cli.parse(allocator, &missing));
    const unknown = [_][]const u8{ "zigshark", "--not-a-flag" };
    try std.testing.expectError(error.UnknownFlag, cli.parse(allocator, &unknown));
}

test "positional text after a file is the display filter" {
    const allocator = std.testing.allocator;
    const args = [_][]const u8{ "zigshark", "a.pcap", "udp" };
    var opts = try cli.parse(allocator, &args);
    defer opts.deinit(allocator);
    try std.testing.expectEqualStrings("udp", opts.display_filter.?);
}
