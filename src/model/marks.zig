const std = @import("std");

/// Local marks use a-z; global marks use A-Z and persist by path.
pub const Marks = struct {
    allocator: std.mem.Allocator,
    local: std.AutoHashMap(u8, u32),
    global_path: ?[]u8 = null,
    global: std.AutoHashMap(u8, u32),

    pub fn init(allocator: std.mem.Allocator) Marks {
        return .{
            .allocator = allocator,
            .local = std.AutoHashMap(u8, u32).init(allocator),
            .global = std.AutoHashMap(u8, u32).init(allocator),
        };
    }

    pub fn deinit(self: *Marks) void {
        if (self.global_path) |p| self.allocator.free(p);
        self.local.deinit();
        self.global.deinit();
    }

    pub fn setLocal(self: *Marks, label: u8, frame: u32) void {
        if (label < 'a' or label > 'z') return;
        self.local.put(label, frame) catch {};
    }

    pub fn setGlobal(self: *Marks, label: u8, frame: u32) void {
        if (label < 'A' or label > 'Z') return;
        self.global.put(label, frame) catch {};
    }

    pub fn getLocal(self: *const Marks, label: u8) ?u32 {
        return self.local.get(label);
    }

    pub fn getGlobal(self: *const Marks, label: u8) ?u32 {
        return self.global.get(label);
    }

    pub fn jumpLocal(self: *const Marks, label: u8) ?u32 {
        return self.getLocal(label);
    }

    pub fn jumpGlobal(self: *const Marks, label: u8) ?u32 {
        return self.getGlobal(label);
    }

    pub fn bindGlobalPath(self: *Marks, path: []const u8) !void {
        if (self.global_path) |p| self.allocator.free(p);
        self.global_path = try self.allocator.dupe(u8, path);
    }
};

test "marks local and global" {
    var marks = Marks.init(std.testing.allocator);
    defer marks.deinit();
    marks.setLocal('a', 42);
    marks.setGlobal('A', 7);
    try std.testing.expectEqual(@as(?u32, 42), marks.jumpLocal('a'));
    try std.testing.expectEqual(@as(?u32, 7), marks.jumpGlobal('A'));
}
