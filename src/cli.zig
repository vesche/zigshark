const std = @import("std");
const version = @import("version.zig");

pub const Command = enum {
    open,
    capture,
    interfaces,
    help,
    version,
};

pub const Options = struct {
    command: Command = .open,
    file: ?[]const u8 = null,
    interfaces: std.ArrayList([]const u8) = .empty,
    display_filter: ?[]const u8 = null,
    capture_filter: ?[]const u8 = null,
    write_file: ?[]const u8 = null,
    profile: ?[]const u8 = null,
    timestamp_format: ?[]const u8 = null,
    decode_as: std.ArrayList([]const u8) = .empty,
    pass_thru: enum { auto, always, never } = .auto,
    log_tty: bool = false,
    force_tty: bool = false,
    print_help: bool = false,
    print_version: bool = false,
    version_verbose: bool = false,
    positional: ?[]const u8 = null,

    pub fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        self.interfaces.deinit(allocator);
        self.decode_as.deinit(allocator);
    }
};

pub fn parse(allocator: std.mem.Allocator, args: []const []const u8) !Options {
    var opts = Options{};
    var i: usize = 1; // skip argv0
    var saw_command = false;

    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            opts.print_help = true;
            opts.command = .help;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-vv")) {
            if (opts.print_version or std.mem.eql(u8, arg, "-vv")) opts.version_verbose = true;
            opts.print_version = true;
            opts.command = .version;
        } else if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--read") or std.mem.eql(u8, arg, "open")) {
            if (std.mem.eql(u8, arg, "open")) saw_command = true;
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.file = args[i];
            opts.command = .open;
        } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--interface")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            try opts.interfaces.append(allocator, args[i]);
            opts.command = .capture;
        } else if (std.mem.eql(u8, arg, "capture")) {
            saw_command = true;
            opts.command = .capture;
        } else if (std.mem.eql(u8, arg, "-D") or std.mem.eql(u8, arg, "interfaces")) {
            saw_command = true;
            opts.command = .interfaces;
        } else if (std.mem.eql(u8, arg, "-Y") or std.mem.eql(u8, arg, "--display-filter")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.display_filter = args[i];
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--capture-filter")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.capture_filter = args[i];
        } else if (std.mem.eql(u8, arg, "-w") or std.mem.eql(u8, arg, "--write")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.write_file = args[i];
        } else if (std.mem.eql(u8, arg, "-d")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            try opts.decode_as.append(allocator, args[i]);
        } else if (std.mem.eql(u8, arg, "-t")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.timestamp_format = args[i];
        } else if (std.mem.eql(u8, arg, "-C") or std.mem.eql(u8, arg, "--profile")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            opts.profile = args[i];
        } else if (std.mem.eql(u8, arg, "--pass-thru")) {
            opts.pass_thru = .always;
        } else if (std.mem.startsWith(u8, arg, "--pass-thru=")) {
            const v = arg["--pass-thru=".len..];
            if (std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "always")) {
                opts.pass_thru = .always;
            } else if (std.mem.eql(u8, v, "false") or std.mem.eql(u8, v, "never")) {
                opts.pass_thru = .never;
            } else {
                opts.pass_thru = .auto;
            }
        } else if (std.mem.eql(u8, arg, "--log-tty")) {
            opts.log_tty = true;
        } else if (std.mem.eql(u8, arg, "--tty")) {
            opts.force_tty = true;
        } else if (arg.len > 0 and arg[0] != '-') {
            if (!saw_command and (std.mem.eql(u8, arg, "help") or std.mem.eql(u8, arg, "version"))) {
                if (std.mem.eql(u8, arg, "help")) {
                    opts.print_help = true;
                    opts.command = .help;
                } else {
                    opts.print_version = true;
                    opts.command = .version;
                }
            } else if (opts.file == null and opts.interfaces.items.len == 0) {
                // Direct file shorthand or positional filter
                if (looksLikeFile(arg)) {
                    opts.file = arg;
                    opts.command = .open;
                } else {
                    opts.positional = arg;
                }
            } else {
                opts.positional = arg;
            }
        } else {
            return error.UnknownFlag;
        }
    }

    if (opts.positional) |pos| {
        if (opts.file != null or opts.interfaces.items.len != 0) {
            if (opts.display_filter == null) opts.display_filter = pos;
        } else if (opts.capture_filter == null and opts.command == .capture) {
            opts.capture_filter = pos;
        } else if (opts.display_filter == null) {
            opts.display_filter = pos;
        }
    }

    return opts;
}

fn looksLikeFile(s: []const u8) bool {
    if (std.mem.eql(u8, s, "-")) return true;
    if (std.mem.indexOfScalar(u8, s, '.') != null) return true;
    if (std.mem.indexOfScalar(u8, s, '/') != null) return true;
    return false;
}

pub fn printHelp(writer: *std.Io.Writer) !void {
    try writer.print(
        \\{s} — terminal UI for tshark
        \\
        \\Usage:
        \\  zigshark [file.pcap]
        \\  zigshark open <file.pcap> [-Y filter]
        \\  zigshark capture -i <iface> [-f capture-filter] [-w out.pcap]
        \\  zigshark interfaces
        \\  zigshark --help
        \\
        \\Options:
        \\  -r, open FILE          Open a capture file (or FIFO / stdin '-')
        \\  -i IFACE               Capture on interface (repeatable)
        \\  -Y FILTER              Display filter
        \\  -f FILTER              Capture filter
        \\  -w FILE                Write capture to FILE
        \\  -d DECODE              Decode-as (layer==selector,protocol)
        \\  -t FORMAT              Timestamp format (a|ad|adoy|d|dd|e|r|u|ud|udoy)
        \\  -C, --profile NAME     Use named zigshark profile
        \\  -D, interfaces         List capture interfaces
        \\  --pass-thru[=auto]     Pass through to tshark when not a TTY
        \\  --tty                  Force the UI on the controlling terminal
        \\  --log-tty              Mirror logs to stderr
        \\  -v, --version          Print version (-vv includes tshark)
        \\  -h, --help             Show this help
        \\
        \\In the TUI:
        \\  hjkl/arrows  navigate   Tab  switch panes   /  filter
        \\  :            commands   ?    help           q  quit
        \\  Ctrl-F       search     c    copy mode      |  layout
        \\
    , .{version.versionLine()});
}

pub fn printVersion(writer: *std.Io.Writer, tshark_version: ?[]const u8) !void {
    try writer.print("{s}\n", .{version.versionLine()});
    if (tshark_version) |tv| {
        try writer.print("tshark {s}\n", .{tv});
    }
}

test "parse open file shorthand" {
    const allocator = std.testing.allocator;
    const args = [_][]const u8{ "zigshark", "capture.pcap", "-Y", "tcp" };
    var opts = try parse(allocator, &args);
    defer opts.deinit(allocator);
    try std.testing.expect(opts.command == .open);
    try std.testing.expectEqualStrings("capture.pcap", opts.file.?);
    try std.testing.expectEqualStrings("tcp", opts.display_filter.?);
}

test "parse capture interfaces" {
    const allocator = std.testing.allocator;
    const args = [_][]const u8{ "zigshark", "capture", "-i", "eth0", "-i", "wlan0" };
    var opts = try parse(allocator, &args);
    defer opts.deinit(allocator);
    try std.testing.expect(opts.command == .capture);
    try std.testing.expectEqual(@as(usize, 2), opts.interfaces.items.len);
}
