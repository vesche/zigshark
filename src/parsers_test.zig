//! Aggregates parser unit tests (run: zig test -Mroot=src/parsers_test.zig).
test {
    _ = @import("xml_util.zig");
    _ = @import("shark/psml.zig");
    _ = @import("shark/pdml.zig");
    _ = @import("shark/hexdump.zig");
    _ = @import("shark/columns.zig");
    _ = @import("shark/fields.zig");
    _ = @import("shark/convs.zig");
    _ = @import("shark/streams.zig");
    _ = @import("shark/capinfo.zig");
}
