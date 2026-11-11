const std = @import("std");
const process = @import("../../shark/process.zig");
const convs = @import("../../shark/convs.zig");

pub fn loadConversations(
    allocator: std.mem.Allocator,
    io: std.Io,
    tshark: []const u8,
    path: []const u8,
    conv_type: []const u8,
) ![]u8 {
    var argv = try process.argvConversations(allocator, tshark, path, conv_type);
    defer argv.deinit(allocator);

    var out = try process.runCapture(allocator, io, argv.slice());
    defer out.deinit(allocator);

    if (out.stdout.len == 0) {
        return try std.fmt.allocPrint(allocator, "No conversations ({s}) in {s}\n{s}", .{ conv_type, path, out.stderr });
    }

    const parsed = convs.parse(allocator, out.stdout) catch {
        return try allocator.dupe(u8, out.stdout);
    };
    defer {
        for (parsed) |*conversation| conversation.deinit(allocator);
        allocator.free(parsed);
    }

    var result: std.Io.Writer.Allocating = .init(allocator);
    errdefer result.deinit();
    try result.writer.print(
        "{s} conversations ({d})\n\n" ++
            "Endpoint A <-> Endpoint B                              Frames      Bytes   Duration\n",
        .{ conv_type, parsed.len },
    );
    for (parsed) |conversation| {
        const endpoint_a = if (conversation.port_a) |port|
            try std.fmt.allocPrint(allocator, "{s}:{d}", .{ conversation.addr_a, port })
        else
            try allocator.dupe(u8, conversation.addr_a);
        defer allocator.free(endpoint_a);
        const endpoint_b = if (conversation.port_b) |port|
            try std.fmt.allocPrint(allocator, "{s}:{d}", .{ conversation.addr_b, port })
        else
            try allocator.dupe(u8, conversation.addr_b);
        defer allocator.free(endpoint_b);
        try result.writer.print(
            "{s} <-> {s}  {d: >8}  {d: >9}  {d:.4}s\n",
            .{
                endpoint_a,
                endpoint_b,
                conversation.frames_total,
                conversation.bytes_total,
                conversation.duration,
            },
        );
    }
    try result.writer.writeAll(
        "\nUse a display filter such as tcp.stream == N, " ++
            "ip.addr == ADDRESS, or the :search-filter command.",
    );
    return result.toOwnedSlice();
}

pub fn placeholder(allocator: std.mem.Allocator) ![]u8 {
    return try allocator.dupe(u8, "Conversations\n\nUse :convs [tcp|udp|ip|ipv6|eth]");
}
