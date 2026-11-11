const std = @import("std");
const vaxis = @import("vaxis");
const zigshark = @import("zigshark");

pub const panic = vaxis.Panic;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const stdin_tty = try std.Io.File.stdin().isTty(io);
    const stdout_tty = try std.Io.File.stdout().isTty(io);
    const force_passthrough = hasArg(args, "--pass-thru") or
        hasArg(args, "--pass-thru=true") or
        hasArg(args, "--pass-thru=always");
    const disable_passthrough = hasArg(args, "--pass-thru=false") or
        hasArg(args, "--pass-thru=never");
    const local_control_command = hasAnyArg(args, &.{
        "-h", "--help", "-v", "-vv", "--version", "-D", "interfaces",
    });
    if (force_passthrough or (!stdout_tty and !disable_passthrough and !local_control_command)) {
        try execTsharkPassthrough(allocator, io, args);
        return;
    }

    var cli_opts = try zigshark.cli.parse(allocator, args);
    defer cli_opts.deinit(allocator);

    if (cli_opts.print_help or cli_opts.command == .help) {
        var stderr_buffer: [4096]u8 = undefined;
        var stderr_writer: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
        try zigshark.cli.printHelp(&stderr_writer.interface);
        try stderr_writer.interface.flush();
        return;
    }

    if (cli_opts.print_version or cli_opts.command == .version) {
        var stderr_buffer: [4096]u8 = undefined;
        var stderr_writer: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
        var owned_tv: ?[]u8 = null;
        defer if (owned_tv) |s| allocator.free(s);
        if (cli_opts.version_verbose) {
            if (zigshark.shark.tools.discover(allocator, io, .{
                .tshark = "tshark",
                .dumpcap = "dumpcap",
                .capinfos = "capinfos",
            })) |tools_val| {
                var tools = tools_val;
                defer tools.deinit();
                owned_tv = try allocator.dupe(u8, tools.tshark_version);
            } else |_| {}
        }
        try zigshark.cli.printVersion(&stderr_writer.interface, owned_tv);
        try stderr_writer.interface.flush();
        return;
    }

    if (cli_opts.command == .interfaces) {
        var tools = try zigshark.shark.tools.discover(allocator, io, .{
            .tshark = "tshark",
            .dumpcap = "dumpcap",
            .capinfos = "capinfos",
        });
        defer tools.deinit();
        const ifaces = try zigshark.shark.tools.listInterfaces(allocator, io, tools.tshark);
        defer {
            for (ifaces) |*iface| {
                allocator.free(iface.name);
                allocator.free(iface.description);
            }
            allocator.free(ifaces);
        }
        var stderr_buffer: [8192]u8 = undefined;
        var stderr_writer: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
        for (ifaces) |iface| {
            try stderr_writer.interface.print("{d}. {s} {s}\n", .{ iface.index, iface.name, iface.description });
        }
        try stderr_writer.interface.flush();
        return;
    }

    const use_tui = cli_opts.force_tty or (stdin_tty and stdout_tty and cli_opts.pass_thru != .always);
    const pass_thru = cli_opts.pass_thru == .always or (cli_opts.pass_thru == .auto and !use_tui);

    if (pass_thru) {
        try execTsharkPassthrough(allocator, io, args);
        return;
    }

    var paths = try zigshark.platform.paths.resolve(allocator, io, init.environ_map);
    defer paths.deinit();
    try zigshark.log.init(allocator, io, paths.log_path);
    defer zigshark.log.deinit();
    zigshark.log.setMirrorTty(cli_opts.log_tty);
    zigshark.log.info("main", "starting {s}", .{zigshark.version.versionLine()});

    const config_path = try paths.configFile(allocator);
    defer allocator.free(config_path);

    var cfg = if (cli_opts.profile) |profile|
        try zigshark.features.profiles.loadProfile(allocator, io, &paths, profile)
    else
        try zigshark.config.Config.loadOrDefault(allocator, io, config_path);
    if (cli_opts.profile) |profile| try cfg.setProfileName(profile);
    defer cfg.deinit();
    defer {
        if (!std.mem.eql(u8, cfg.profile, "default")) {
            zigshark.features.profiles.saveProfile(&cfg, io, &paths, cfg.profile) catch {};
        } else {
            cfg.save(io, config_path) catch {};
        }
    }

    var tools = try zigshark.shark.tools.discover(allocator, io, .{
        .tshark = cfg.tshark,
        .dumpcap = cfg.dumpcap,
        .capinfos = cfg.capinfos,
    });
    defer tools.deinit();
    zigshark.log.info("tools", "using {s}", .{tools.tshark_version});

    var owned_interfaces: ?[][]const u8 = null;
    defer if (owned_interfaces) |values| allocator.free(values);
    var spooled_stdin_path: ?[]u8 = null;
    defer if (spooled_stdin_path) |path| {
        std.Io.Dir.cwd().deleteFile(io, path) catch {};
        allocator.free(path);
    };

    const source: zigshark.shark.process.Source = blk: {
        if (cli_opts.command == .capture) {
            const count: usize = if (cli_opts.interfaces.items.len == 0) 1 else cli_opts.interfaces.items.len;
            const ifaces = try allocator.alloc([]const u8, count);
            if (cli_opts.interfaces.items.len == 0) {
                ifaces[0] = "1";
            } else {
                for (cli_opts.interfaces.items, 0..) |iface, i| ifaces[i] = iface;
            }
            owned_interfaces = ifaces;
            break :blk .{ .interfaces = ifaces };
        }
        if (cli_opts.file) |file| {
            if (std.mem.eql(u8, file, "-")) {
                const path = try spoolStdinToCapture(allocator, io, &paths);
                spooled_stdin_path = path;
                break :blk .{ .file = path };
            }
            break :blk .{ .file = file };
        }
        const ifaces = try allocator.alloc([]const u8, 1);
        ifaces[0] = "1";
        owned_interfaces = ifaces;
        break :blk .{ .interfaces = ifaces };
    };

    var session = zigshark.model.session.Session.init(allocator, source);
    defer session.deinit();

    if (cli_opts.display_filter) |df| try session.setFilter(df, null);
    if (cli_opts.capture_filter) |cf| try session.setFilter(null, cf);
    if (cli_opts.timestamp_format) |format| try session.setTimestampFormat(format);
    if (cfg.wireshark_profile.len != 0) try session.setWiresharkProfile(cfg.wireshark_profile);
    if (cfg.tls_keylog_file.len != 0) try session.setTlsKeylog(cfg.tls_keylog_file);
    for (cli_opts.decode_as.items) |decode_as| try session.addDecodeAs(decode_as);
    if (cli_opts.file) |file| {
        if (!std.mem.eql(u8, file, "-")) try cfg.addRecentFile(file);
    }

    var loader = zigshark.model.loader.CaptureLoader.init(allocator, io, &tools, .{
        .bundle_size = cfg.pcap_bundle_size,
        .cache_size = cfg.pcap_cache_size,
        .tshark_args = cfg.tshark_args,
        .column_format = cfg.column_format,
    });
    defer loader.deinit(io);

    try zigshark.ui.runtime.runTui(init, .{
        .config = &cfg,
        .tools = &tools,
        .session = &session,
        .loader = &loader,
        .paths = &paths,
        .cli = cli_opts,
    });
}

fn execTsharkPassthrough(allocator: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    var tools = try zigshark.shark.tools.discover(allocator, io, .{
        .tshark = "tshark",
        .dumpcap = "dumpcap",
        .capinfos = "capinfos",
    });
    defer tools.deinit();

    var argv = try buildPassthroughArgs(allocator, tools.tshark, args);
    defer argv.deinit(allocator);
    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| std.process.exit(code),
        else => std.process.exit(1),
    }
}

fn buildPassthroughArgs(
    allocator: std.mem.Allocator,
    tshark: []const u8,
    args: []const []const u8,
) !std.ArrayList([]const u8) {
    var argv: std.ArrayList([]const u8) = .empty;
    errdefer argv.deinit(allocator);
    try argv.append(allocator, tshark);
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--pass-thru") or
            std.mem.startsWith(u8, arg, "--pass-thru=") or
            std.mem.eql(u8, arg, "--log-tty"))
        {
            continue;
        }
        if (std.mem.eql(u8, arg, "capture")) continue;
        if (std.mem.eql(u8, arg, "interfaces")) {
            try argv.append(allocator, "-D");
            continue;
        }
        if (std.mem.eql(u8, arg, "open")) {
            if (i + 1 >= args.len) return error.MissingArgument;
            try argv.append(allocator, "-r");
            i += 1;
            try argv.append(allocator, args[i]);
            continue;
        }
        if (arg.len > 0 and arg[0] != '-' and looksLikeCapturePath(arg)) {
            const already_has_read_flag = argv.items.len > 0 and
                std.mem.eql(u8, argv.items[argv.items.len - 1], "-r");
            if (!already_has_read_flag) try argv.append(allocator, "-r");
            try argv.append(allocator, arg);
            continue;
        }
        try argv.append(allocator, arg);
    }
    return argv;
}

fn hasArg(args: []const []const u8, wanted: []const u8) bool {
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, wanted)) return true;
    }
    return false;
}

fn hasAnyArg(args: []const []const u8, wanted: []const []const u8) bool {
    for (wanted) |needle| {
        if (hasArg(args, needle)) return true;
    }
    return false;
}

fn looksLikeCapturePath(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "-") or
        std.mem.indexOfScalar(u8, arg, '/') != null or
        std.mem.endsWith(u8, arg, ".pcap") or
        std.mem.endsWith(u8, arg, ".pcapng") or
        std.mem.endsWith(u8, arg, ".cap");
}

fn spoolStdinToCapture(
    allocator: std.mem.Allocator,
    io: std.Io,
    paths: *const zigshark.platform.paths.Paths,
) ![]u8 {
    const cache_dir = try paths.pcapCacheDir(allocator);
    defer allocator.free(cache_dir);
    const timestamp = std.Io.Timestamp.now(io, .awake).nanoseconds;
    const path = try std.fmt.allocPrint(allocator, "{s}/stdin-{d}.pcap", .{
        cache_dir,
        timestamp,
    });
    errdefer allocator.free(path);

    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var input_buffer: [64 * 1024]u8 = undefined;
    var output_buffer: [64 * 1024]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(io, &input_buffer);
    var writer = file.writer(io, &output_buffer);
    _ = try reader.interface.streamRemaining(&writer.interface);
    try writer.interface.flush();
    return path;
}

test "version line is non-empty" {
    const line = zigshark.version.versionLine();
    try std.testing.expect(line.len > 8);
    try std.testing.expect(std.mem.indexOf(u8, line, "zigshark") != null);
}

test "pass-through strips zigshark flags and translates file shorthand" {
    const allocator = std.testing.allocator;
    const args = [_][]const u8{
        "zigshark",
        "--pass-thru",
        "tests/fixtures/1.pcap",
        "-T",
        "fields",
        "-e",
        "frame.number",
    };
    var result = try buildPassthroughArgs(allocator, "tshark", &args);
    defer result.deinit(allocator);
    try std.testing.expectEqualSlices([]const u8, &.{
        "tshark",
        "-r",
        "tests/fixtures/1.pcap",
        "-T",
        "fields",
        "-e",
        "frame.number",
    }, result.items);
}
