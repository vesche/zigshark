const std = @import("std");
const zigshark = @import("zigshark");
const config = zigshark.config;
const features = zigshark.features;

test "settings round-trip through toml" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var cfg = try config.Config.defaults(allocator);
    defer cfg.deinit();

    try cfg.applySetting("auto-scroll", "false");
    try cfg.applySetting("layout", "focus");
    try cfg.applySetting("stream-view", "raw");
    try cfg.applySetting("search-case-sensitive", "yes");
    try cfg.applySetting("conv-absolute-time", "true");
    try cfg.applySetting("pager", "less");
    try cfg.applySetting("tshark-args", "-2");
    try cfg.applySetting("pcap-bundle-size", "250");
    try cfg.applySetting("wormhole-length", "4");

    const path = "/tmp/zigshark-suite-config.toml";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};
    try cfg.save(io, path);

    var loaded = try config.Config.loadOrDefault(allocator, io, path);
    defer loaded.deinit();
    try std.testing.expect(!loaded.auto_scroll);
    try std.testing.expect(loaded.layout == .focus);
    try std.testing.expectEqualStrings("raw", loaded.stream_view);
    try std.testing.expect(loaded.search_case_sensitive);
    try std.testing.expect(loaded.conv_absolute_time);
    try std.testing.expectEqualStrings("less", loaded.pager);
    try std.testing.expectEqualStrings("-2", loaded.tshark_args);
    try std.testing.expectEqual(@as(u32, 250), loaded.pcap_bundle_size);
    try std.testing.expectEqual(@as(u32, 4), loaded.wormhole_length);
}

test "quoted values and unknown keys are rejected by applySetting" {
    const allocator = std.testing.allocator;
    var cfg = try config.Config.defaults(allocator);
    defer cfg.deinit();
    try std.testing.expectError(error.InvalidValue, cfg.applySetting("pager", "le\"ss"));
    try std.testing.expectError(error.UnknownSetting, cfg.applySetting("not-a-key", "1"));
    try std.testing.expectError(error.InvalidValue, cfg.applySetting("layout", "diagonal"));
}

test "malformed numbers in a file do not discard the rest of the config" {
    const allocator = std.testing.allocator;
    var cfg = try config.Config.defaults(allocator);
    defer cfg.deinit();
    try cfg.parseToml(
        \\[main]
        \\pcap-bundle-size = no
        \\dark-mode = false
        \\not-a-key = 1
    );
    try std.testing.expectEqual(@as(u32, 1000), cfg.pcap_bundle_size);
    try std.testing.expect(!cfg.dark_mode);
}

test "recent files stay unique and capped" {
    const allocator = std.testing.allocator;
    var cfg = try config.Config.defaults(allocator);
    defer cfg.deinit();
    var i: usize = 0;
    while (i < 25) : (i += 1) {
        const path = try std.fmt.allocPrint(allocator, "/tmp/c{d}.pcap", .{i});
        defer allocator.free(path);
        try cfg.addRecentFile(path);
    }
    try cfg.addRecentFile("/tmp/c24.pcap");
    try std.testing.expectEqual(@as(usize, 20), cfg.recent_files.items.len);
    try std.testing.expectEqualStrings("/tmp/c24.pcap", cfg.recent_files.items[0]);
}

test "macros expand a known name and leave an unknown dollar sign" {
    const allocator = std.testing.allocator;
    var cfg = try config.Config.defaults(allocator);
    defer cfg.deinit();
    try cfg.macros.append(allocator, .{
        .name = try allocator.dupe(u8, "web"),
        .value = try allocator.dupe(u8, "tcp.port == 443"),
    });
    const expanded = try features.macros.expand(allocator, &cfg, "$web and $missing");
    defer allocator.free(expanded);
    try std.testing.expectEqualStrings("tcp.port == 443 and $missing", expanded);
}

test "profiles can be created, listed, and deleted" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var paths = zigshark.platform.paths.Paths{
        .allocator = allocator,
        .config_dir = try allocator.dupe(u8, "/tmp/zigshark-suite-home"),
        .cache_dir = try allocator.dupe(u8, "/tmp/zigshark-suite-cache"),
        .data_dir = try allocator.dupe(u8, "/tmp/zigshark-suite-data"),
        .log_path = try allocator.dupe(u8, "/tmp/zigshark-suite.log"),
    };
    defer paths.deinit();

    var cfg = try config.Config.defaults(allocator);
    defer cfg.deinit();
    try cfg.applySetting("dark-mode", "false");
    try features.profiles.saveProfile(&cfg, io, &paths, "suite");

    const names = try features.profiles.listProfiles(allocator, io, &paths);
    defer {
        for (names) |name| allocator.free(name);
        allocator.free(names);
    }
    var found = false;
    for (names) |name| {
        if (std.mem.eql(u8, name, "suite")) found = true;
    }
    try std.testing.expect(found);

    var loaded = try features.profiles.loadProfile(allocator, io, &paths, "suite");
    defer loaded.deinit();
    try std.testing.expect(!loaded.dark_mode);

    try std.testing.expectError(error.InvalidProfile, features.profiles.deleteProfile(allocator, io, &paths, "default"));
    try std.testing.expectError(error.InvalidProfile, features.profiles.deleteProfile(allocator, io, &paths, "../etc"));
    try features.profiles.deleteProfile(allocator, io, &paths, "suite");
}
