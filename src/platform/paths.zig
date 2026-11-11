const std = @import("std");
const builtin = @import("builtin");

pub const Paths = struct {
    config_dir: []u8,
    cache_dir: []u8,
    data_dir: []u8,
    log_path: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Paths) void {
        self.allocator.free(self.config_dir);
        self.allocator.free(self.cache_dir);
        self.allocator.free(self.data_dir);
        self.allocator.free(self.log_path);
    }

    pub fn configFile(self: Paths, allocator: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.config_dir, "config.toml" });
    }

    pub fn themesDir(self: Paths, allocator: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.config_dir, "themes" });
    }

    pub fn profilesDir(self: Paths, allocator: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.config_dir, "profiles" });
    }

    pub fn pcapCacheDir(self: Paths, allocator: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.cache_dir, "pcaps" });
    }

    pub fn emptyPcapPath(self: Paths, allocator: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.cache_dir, "empty.pcap" });
    }

    pub fn fieldsCachePath(self: Paths, allocator: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.cache_dir, "tshark-fields.txt" });
    }

    pub fn columnsCachePath(self: Paths, allocator: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(allocator, &.{ self.cache_dir, "tshark-columns.txt" });
    }
};

pub fn resolve(allocator: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map) !Paths {
    const home = environ.get("HOME") orelse environ.get("USERPROFILE") orelse ".";

    const config_dir = blk: {
        if (environ.get("XDG_CONFIG_HOME")) |xdg| {
            break :blk try std.fs.path.join(allocator, &.{ xdg, "zigshark" });
        }
        if (builtin.os.tag == .windows) {
            if (environ.get("APPDATA")) |appdata| {
                break :blk try std.fs.path.join(allocator, &.{ appdata, "zigshark" });
            }
        }
        if (builtin.os.tag == .macos) {
            break :blk try std.fs.path.join(allocator, &.{ home, "Library", "Application Support", "zigshark" });
        }
        break :blk try std.fs.path.join(allocator, &.{ home, ".config", "zigshark" });
    };
    errdefer allocator.free(config_dir);

    const cache_dir = blk: {
        if (environ.get("XDG_CACHE_HOME")) |xdg| {
            break :blk try std.fs.path.join(allocator, &.{ xdg, "zigshark" });
        }
        if (builtin.os.tag == .windows) {
            if (environ.get("LOCALAPPDATA")) |local| {
                break :blk try std.fs.path.join(allocator, &.{ local, "zigshark", "cache" });
            }
        }
        if (builtin.os.tag == .macos) {
            break :blk try std.fs.path.join(allocator, &.{ home, "Library", "Caches", "zigshark" });
        }
        break :blk try std.fs.path.join(allocator, &.{ home, ".cache", "zigshark" });
    };
    errdefer allocator.free(cache_dir);

    const data_dir = blk: {
        if (environ.get("XDG_DATA_HOME")) |xdg| {
            break :blk try std.fs.path.join(allocator, &.{ xdg, "zigshark" });
        }
        break :blk try std.fs.path.join(allocator, &.{ home, ".local", "share", "zigshark" });
    };
    errdefer allocator.free(data_dir);

    const log_path = try std.fs.path.join(allocator, &.{ cache_dir, "zigshark.log" });
    errdefer allocator.free(log_path);

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, config_dir);
    try cwd.createDirPath(io, cache_dir);
    try cwd.createDirPath(io, data_dir);

    const themes = try std.fs.path.join(allocator, &.{ config_dir, "themes" });
    defer allocator.free(themes);
    try cwd.createDirPath(io, themes);

    const profiles = try std.fs.path.join(allocator, &.{ config_dir, "profiles" });
    defer allocator.free(profiles);
    try cwd.createDirPath(io, profiles);

    const pcaps = try std.fs.path.join(allocator, &.{ cache_dir, "pcaps" });
    defer allocator.free(pcaps);
    try cwd.createDirPath(io, pcaps);

    try ensureEmptyPcap(io, cache_dir);

    return .{
        .config_dir = config_dir,
        .cache_dir = cache_dir,
        .data_dir = data_dir,
        .log_path = log_path,
        .allocator = allocator,
    };
}

fn ensureEmptyPcap(io: std.Io, cache_dir: []const u8) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/empty.pcap", .{cache_dir});
    const cwd = std.Io.Dir.cwd();
    if (cwd.access(io, path, .{})) |_| {
        return;
    } else |_| {}

    const header = [_]u8{
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    };
    try cwd.writeFile(io, .{ .sub_path = path, .data = &header });
}

test "resolve creates expected layout" {
    const io = std.testing.io;
    var map = std.process.Environ.Map.init(std.testing.allocator);
    defer map.deinit();
    try map.put("HOME", "/tmp/zigshark-test-home");
    try map.put("XDG_CONFIG_HOME", "/tmp/zigshark-test-config");
    try map.put("XDG_CACHE_HOME", "/tmp/zigshark-test-cache");
    try map.put("XDG_DATA_HOME", "/tmp/zigshark-test-data");

    var paths = try resolve(std.testing.allocator, io, &map);
    defer paths.deinit();
    try std.testing.expect(std.mem.endsWith(u8, paths.config_dir, "zigshark"));
}
