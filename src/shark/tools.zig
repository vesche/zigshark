const std = @import("std");
const builtin = @import("builtin");

pub const min_tshark_version = "1.11.0";

pub const ConfigPaths = struct {
    tshark: []const u8,
    dumpcap: []const u8,
    capinfos: []const u8,
};

pub const Tools = struct {
    allocator: std.mem.Allocator,
    tshark: []u8,
    dumpcap: []u8,
    capinfos: []u8,
    tshark_version: []u8,
    dumpcap_version: []u8,
    capinfos_version: []u8,
    supports_color: bool,
    dumpcap_can_capture: bool,

    pub fn deinit(self: *Tools) void {
        self.allocator.free(self.tshark);
        self.allocator.free(self.dumpcap);
        self.allocator.free(self.capinfos);
        self.allocator.free(self.tshark_version);
        self.allocator.free(self.dumpcap_version);
        self.allocator.free(self.capinfos_version);
    }
};

pub const Interface = struct {
    index: u32,
    name: []u8,
    description: []u8,
};

pub const Version = struct {
    major: u32,
    minor: u32,
    patch: u32,

    pub fn parse(text: []const u8) ?Version {
        var iter = std.mem.tokenizeAny(u8, text, " \t");
        while (iter.next()) |tok| {
            if (parseTriple(tok)) |v| return v;
        }
        return null;
    }

    fn parseTriple(tok: []const u8) ?Version {
        // Accept trailing punctuation from strings like "4.7.4."
        var end = tok.len;
        while (end > 0 and !std.ascii.isDigit(tok[end - 1])) : (end -= 1) {}
        const clean = tok[0..end];
        if (clean.len == 0 or !std.ascii.isDigit(clean[0])) return null;
        var parts: [3]u32 = .{ 0, 0, 0 };
        var pi: usize = 0;
        var num: u32 = 0;
        var have = false;
        for (clean) |c| {
            if (std.ascii.isDigit(c)) {
                num = num * 10 + (c - '0');
                have = true;
            } else if (c == '.') {
                if (!have or pi >= 2) return null;
                parts[pi] = num;
                pi += 1;
                num = 0;
                have = false;
            } else {
                if (!have) return null;
                break;
            }
        }
        if (!have) return null;
        parts[pi] = num;
        return .{
            .major = parts[0],
            .minor = parts[1],
            .patch = parts[2],
        };
    }

    pub fn lessThan(self: Version, other: Version) bool {
        if (self.major != other.major) return self.major < other.major;
        if (self.minor != other.minor) return self.minor < other.minor;
        return self.patch < other.patch;
    }
};

pub fn parseVersion(first_line: []const u8) ?Version {
    const trimmed = std.mem.trim(u8, first_line, " \t\r\n");
    return Version.parse(trimmed);
}

pub fn requireMinimum(version_line: []const u8, minimum: []const u8) !void {
    const found = parseVersion(version_line) orelse return error.InvalidVersion;
    const min = Version.parse(minimum) orelse return error.InvalidVersion;
    if (found.lessThan(min)) return error.TsharkTooOld;
}

pub const ToolsError = error{
    ToolNotFound,
    InvalidVersion,
    TsharkTooOld,
    DumpcapPermissionDenied,
} || std.mem.Allocator.Error || std.process.RunError;

pub fn discover(allocator: std.mem.Allocator, io: std.Io, paths: ConfigPaths) ToolsError!Tools {
    const tshark = try resolveExecutable(allocator, io, paths.tshark);
    errdefer allocator.free(tshark);
    const dumpcap = try resolveExecutable(allocator, io, paths.dumpcap);
    errdefer allocator.free(dumpcap);
    const capinfos = try resolveExecutable(allocator, io, paths.capinfos);
    errdefer allocator.free(capinfos);

    const tshark_ver = try versionString(allocator, io, tshark);
    errdefer allocator.free(tshark_ver);
    try requireMinimum(tshark_ver, min_tshark_version);

    const dumpcap_ver = versionString(allocator, io, dumpcap) catch try allocator.dupe(u8, "unknown");
    errdefer allocator.free(dumpcap_ver);

    const capinfos_ver = versionString(allocator, io, capinfos) catch try allocator.dupe(u8, "unknown");
    errdefer allocator.free(capinfos_ver);

    const color = detectSupportsColor(io, tshark);
    const dump_ok = checkDumpcapCapture(allocator, io, dumpcap);

    return .{
        .allocator = allocator,
        .tshark = tshark,
        .dumpcap = dumpcap,
        .capinfos = capinfos,
        .tshark_version = tshark_ver,
        .dumpcap_version = dumpcap_ver,
        .capinfos_version = capinfos_ver,
        .supports_color = color,
        .dumpcap_can_capture = dump_ok.ok,
    };
}

pub fn listInterfaces(allocator: std.mem.Allocator, io: std.Io, tshark: []const u8) ![]Interface {
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ tshark, "-D" },
        .stdout_limit = .unlimited,
        .stderr_limit = .unlimited,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    // tshark -D may exit non-zero when dumpcap is restricted, but still print interfaces.
    if (result.stdout.len == 0) return error.ToolNotFound;

    var list: std.ArrayList(Interface) = .empty;
    errdefer {
        for (list.items) |*iface| {
            allocator.free(iface.name);
            allocator.free(iface.description);
        }
        list.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, result.stdout, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        const dot = std.mem.indexOfScalar(u8, trimmed, '.') orelse continue;
        const after_dot = std.mem.trim(u8, trimmed[dot + 1 ..], " \t");
        const idx = std.fmt.parseInt(u32, trimmed[0..dot], 10) catch continue;
        const name: []const u8 = blk: {
            if (std.mem.indexOfScalar(u8, after_dot, ' ')) |sp| {
                break :blk after_dot[0..sp];
            }
            break :blk after_dot;
        };
        const desc = if (name.len < after_dot.len)
            std.mem.trim(u8, after_dot[name.len..], " \t")
        else
            "";
        try list.append(allocator, .{
            .index = idx,
            .name = try allocator.dupe(u8, name),
            .description = try allocator.dupe(u8, desc),
        });
    }
    return try list.toOwnedSlice(allocator);
}

fn resolveExecutable(allocator: std.mem.Allocator, io: std.Io, name: []const u8) ![]u8 {
    if (explicitToolPath(name)) {
        std.Io.Dir.cwd().access(io, name, .{}) catch return error.ToolNotFound;
        return try allocator.dupe(u8, name);
    }

    // Git for Windows ships an MSYS `which` that prints `/c/Program Files/...`.
    // Zig treats a leading slash as absolute and then does not search PATH.
    // `where` prints a native path. A missing locator, or a path that does not
    // exist, leaves the bare name for PATH lookup at spawn.
    const locator = if (builtin.os.tag == .windows) "where" else "which";
    const result = std.process.run(allocator, io, .{
        .argv = &.{ locator, name },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    }) catch return try allocator.dupe(u8, name);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (!result.term.success()) return try allocator.dupe(u8, name);

    const path = firstLocatorPath(result.stdout);
    if (path.len == 0) return try allocator.dupe(u8, name);
    std.Io.Dir.cwd().access(io, path, .{}) catch return try allocator.dupe(u8, name);
    return try allocator.dupe(u8, path);
}

fn explicitToolPath(name: []const u8) bool {
    if (std.fs.path.isAbsolute(name)) return true;
    if (std.mem.indexOfScalar(u8, name, std.fs.path.sep) != null) return true;
    // Windows accepts `/` as a separator. Do not hand those paths to `where`.
    if (builtin.os.tag == .windows and std.mem.indexOfScalar(u8, name, '/') != null) return true;
    return false;
}

/// `where` prints every PATH match, one per line. The first is the one spawn would run.
fn firstLocatorPath(text: []const u8) []const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len != 0) return trimmed;
    }
    return "";
}

fn versionString(allocator: std.mem.Allocator, io: std.Io, exe: []const u8) ![]u8 {
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ exe, "-v" },
        .stdout_limit = .limited(8192),
        .stderr_limit = .limited(8192),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (!result.term.success()) return error.ToolNotFound;
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    const first = lines.next() orelse result.stdout;
    return try allocator.dupe(u8, std.mem.trim(u8, first, " \t\r"));
}

fn detectSupportsColor(io: std.Io, tshark: []const u8) bool {
    const result = std.process.run(std.heap.page_allocator, io, .{
        .argv = &.{ tshark, "--help" },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch return false;
    defer std.heap.page_allocator.free(result.stdout);
    defer std.heap.page_allocator.free(result.stderr);
    return std.mem.indexOf(u8, result.stdout, "--color") != null or
        std.mem.indexOf(u8, result.stderr, "--color") != null;
}

const DumpcapCheck = struct { ok: bool, permission_denied: bool };

fn checkDumpcapCapture(allocator: std.mem.Allocator, io: std.Io, dumpcap: []const u8) DumpcapCheck {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ dumpcap, "-D" },
        .stdout_limit = .limited(8192),
        .stderr_limit = .limited(8192),
    }) catch return .{ .ok = false, .permission_denied = false };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    const combined = std.fmt.allocPrint(allocator, "{s}{s}", .{ result.stderr, result.stdout }) catch "";
    defer if (combined.len != 0) allocator.free(combined);

    const denied = (std.mem.indexOf(u8, combined, "permission") != null and
        std.mem.indexOf(u8, combined, "denied") != null) or
        std.mem.indexOf(u8, combined, "couldn't run dumpcap") != null or
        std.mem.indexOf(u8, combined, "not allowed to capture") != null;

    if (denied) return .{ .ok = false, .permission_denied = true };
    return .{ .ok = result.term.success(), .permission_denied = false };
}

pub fn dumpcapPermissionMessage() []const u8 {
    return "Live capture permission denied.\n" ++
        "Grant dumpcap capture capabilities or add your user to the wireshark group.\n" ++
        "Falling back to tshark/extcap.";
}

pub fn tsharkAvailable(io: std.Io) bool {
    const result = std.process.run(std.heap.page_allocator, io, .{
        .argv = &.{ "tshark", "-v" },
        .stdout_limit = .limited(2048),
        .stderr_limit = .limited(2048),
    }) catch return false;
    defer std.heap.page_allocator.free(result.stdout);
    defer std.heap.page_allocator.free(result.stderr);
    return result.term.success() and parseVersion(result.stdout) != null;
}

test "parse version" {
    try std.testing.expectEqual(Version{ .major = 4, .minor = 2, .patch = 0 }, parseVersion("TShark (Wireshark) 4.2.0 (Git commit abc)").?);
    try std.testing.expectEqual(Version{ .major = 4, .minor = 7, .patch = 4 }, parseVersion("TShark (Wireshark) 4.7.4.").?);
    try requireMinimum("TShark (Wireshark) 4.0.0", min_tshark_version);
    try std.testing.expectError(error.TsharkTooOld, requireMinimum("TShark (Wireshark) 1.10.0", min_tshark_version));
}

test "discover tshark when available" {
    if (!tsharkAvailable(std.testing.io)) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tools = try discover(allocator, io, .{
        .tshark = "tshark",
        .dumpcap = "dumpcap",
        .capinfos = "capinfos",
    });
    defer tools.deinit();
    try std.testing.expect(tools.tshark.len > 0);
    try std.testing.expect(parseVersion(tools.tshark_version) != null);
}

test "locator output uses the first path" {
    try std.testing.expectEqualStrings(
        "C:\\Program Files\\Wireshark\\tshark.exe",
        firstLocatorPath("C:\\Program Files\\Wireshark\\tshark.exe\r\nC:\\other\\tshark.exe\r\n"),
    );
    try std.testing.expectEqualStrings("/usr/bin/tshark", firstLocatorPath("/usr/bin/tshark\n"));
    try std.testing.expectEqualStrings("", firstLocatorPath(" \r\n\t\r\n"));
}

test "list interfaces when tshark available" {
    if (!tsharkAvailable(std.testing.io)) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tools = try discover(allocator, io, .{
        .tshark = "tshark",
        .dumpcap = "dumpcap",
        .capinfos = "capinfos",
    });
    defer tools.deinit();
    const ifaces = listInterfaces(allocator, io, tools.tshark) catch |err| switch (err) {
        // Windows CI has tshark but no Npcap, so `tshark -D` prints nothing.
        error.ToolNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer {
        for (ifaces) |*i| {
            allocator.free(i.name);
            allocator.free(i.description);
        }
        allocator.free(ifaces);
    }
    try std.testing.expect(ifaces.len >= 0);
}
