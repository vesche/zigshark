const std = @import("std");

pub fn Lru(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        capacity: usize,
        mutex: std.Io.Mutex = .init,
        map: std.AutoHashMap(K, *Node),
        head: ?*Node = null,
        tail: ?*Node = null,
        on_evict: ?*const fn (allocator: std.mem.Allocator, key: K, value: V) void = null,

        const Node = struct {
            key: K,
            value: V,
            prev: ?*Node = null,
            next: ?*Node = null,
        };

        pub fn init(allocator: std.mem.Allocator, capacity: usize) Self {
            return .{
                .allocator = allocator,
                .capacity = @max(capacity, 1),
                .map = std.AutoHashMap(K, *Node).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.clearUnlocked();
            self.map.deinit();
        }

        pub fn setCapacity(self: *Self, io: std.Io, capacity: usize) void {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            self.capacity = @max(capacity, 1);
            while (self.map.count() > self.capacity) {
                const victim = self.tail orelse break;
                self.detach(victim);
                _ = self.map.remove(victim.key);
                if (self.on_evict) |cb| cb(self.allocator, victim.key, victim.value);
                self.allocator.destroy(victim);
            }
        }

        pub fn clear(self: *Self, io: std.Io) void {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            self.clearUnlocked();
        }

        fn clearUnlocked(self: *Self) void {
            var it = self.map.iterator();
            while (it.next()) |entry| {
                const node = entry.value_ptr.*;
                if (self.on_evict) |cb| cb(self.allocator, node.key, node.value);
                self.allocator.destroy(node);
            }
            self.map.clearRetainingCapacity();
            self.head = null;
            self.tail = null;
        }

        pub fn get(self: *Self, io: std.Io, key: K) ?V {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);

            const node = self.map.get(key) orelse return null;
            self.detach(node);
            self.pushFront(node);
            return node.value;
        }

        pub fn put(self: *Self, io: std.Io, key: K, value: V) !void {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);

            if (self.map.getPtr(key)) |existing| {
                existing.*.value = value;
                self.detach(existing.*);
                self.pushFront(existing.*);
                return;
            }

            const node = try self.allocator.create(Node);
            node.* = .{ .key = key, .value = value };
            try self.map.put(key, node);
            self.pushFront(node);

            while (self.map.count() > self.capacity) {
                const victim = self.tail orelse break;
                self.detach(victim);
                _ = self.map.remove(victim.key);
                if (self.on_evict) |cb| cb(self.allocator, victim.key, victim.value);
                self.allocator.destroy(victim);
            }
        }

        pub fn remove(self: *Self, io: std.Io, key: K) ?V {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);

            const node = self.map.fetchRemove(key) orelse return null;
            self.detach(node.value);
            const value = node.value.value;
            self.allocator.destroy(node.value);
            return value;
        }

        pub fn len(self: *Self, io: std.Io) usize {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);
            return self.map.count();
        }

        fn detach(self: *Self, node: *Node) void {
            if (node.prev) |p| p.next = node.next else self.head = node.next;
            if (node.next) |n| n.prev = node.prev else self.tail = node.prev;
            node.prev = null;
            node.next = null;
        }

        fn pushFront(self: *Self, node: *Node) void {
            node.next = self.head;
            node.prev = null;
            if (self.head) |h| h.prev = node;
            self.head = node;
            if (self.tail == null) self.tail = node;
        }
    };
}

test "lru eviction order" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var cache = Lru(u32, u32).init(allocator, 2);
    defer cache.deinit();

    try cache.put(io, 1, 10);
    try cache.put(io, 2, 20);
    _ = cache.get(io, 1);
    try cache.put(io, 3, 30);

    try std.testing.expect(cache.get(io, 2) == null);
    try std.testing.expectEqual(@as(?u32, 10), cache.get(io, 1));
    try std.testing.expectEqual(@as(?u32, 30), cache.get(io, 3));
}
