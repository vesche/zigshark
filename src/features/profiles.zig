const std = @import("std");
const config = @import("../config.zig");
const paths_mod = @import("../platform/paths.zig");

pub fn loadProfile(
    allocator: std.mem.Allocator,
    io: std.Io,
    paths: *const paths_mod.Paths,
    name: []const u8,
) !config.Config {
    const dir = try paths.profilesDir(allocator);
    defer allocator.free(dir);
    const profile_dir = try std.fs.path.join(allocator, &.{ dir, name });
    defer allocator.free(profile_dir);
    try std.Io.Dir.cwd().createDirPath(io, profile_dir);
    const profile_path = try std.fs.path.join(allocator, &.{ profile_dir, "config.toml" });
    defer allocator.free(profile_path);
    return try config.Config.loadOrDefault(allocator, io, profile_path);
}

pub fn saveProfile(cfg: *config.Config, io: std.Io, paths: *const paths_mod.Paths, name: []const u8) !void {
    const dir = try paths.profilesDir(cfg.allocator);
    defer cfg.allocator.free(dir);
    const profile_dir = try std.fs.path.join(cfg.allocator, &.{ dir, name });
    defer cfg.allocator.free(profile_dir);
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, profile_dir);
    const profile_path = try std.fs.path.join(cfg.allocator, &.{ profile_dir, "config.toml" });
    defer cfg.allocator.free(profile_path);
    try cfg.save(io, profile_path);
}

pub fn deleteProfile(allocator: std.mem.Allocator, io: std.Io, paths: *const paths_mod.Paths, name: []const u8) !void {
    if (name.len == 0 or std.mem.eql(u8, name, "default") or std.mem.indexOfScalar(u8, name, '/') != null) {
        return error.InvalidProfile;
    }
    const dir = try paths.profilesDir(allocator);
    defer allocator.free(dir);
    const profile_dir = try std.fs.path.join(allocator, &.{ dir, name });
    defer allocator.free(profile_dir);
    const profile_path = try std.fs.path.join(allocator, &.{ profile_dir, "config.toml" });
    defer allocator.free(profile_path);
    const cwd = std.Io.Dir.cwd();
    cwd.deleteFile(io, profile_path) catch {};
    try cwd.deleteDir(io, profile_dir);
}

pub fn listProfiles(allocator: std.mem.Allocator, io: std.Io, paths: *const paths_mod.Paths) ![][]u8 {
    const dir_path = try paths.profilesDir(allocator);
    defer allocator.free(dir_path);
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch {
        return allocator.alloc([]u8, 0);
    };
    defer dir.close(io);
    var names: std.ArrayList([]u8) = .empty;
    errdefer {
        for (names.items) |name| allocator.free(name);
        names.deinit(allocator);
    }
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        try names.append(allocator, try allocator.dupe(u8, entry.name));
    }
    return names.toOwnedSlice(allocator);
}
