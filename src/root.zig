//! zigshark library root.
const std = @import("std");

pub const version = @import("version.zig");
pub const config = @import("config.zig");
pub const log = @import("log.zig");
pub const cli = @import("cli.zig");
pub const xml_util = @import("xml_util.zig");

pub const platform = struct {
    pub const paths = @import("platform/paths.zig");
    pub const clipboard = @import("platform/clipboard.zig");
    pub const browser = @import("platform/browser.zig");
    pub const pager = @import("platform/pager.zig");
    pub const signals = @import("platform/signals.zig");
};

pub const cache = struct {
    pub const lru = @import("cache/lru.zig");
};

pub const shark = struct {
    pub const tools = @import("shark/tools.zig");
    pub const process = @import("shark/process.zig");
    pub const filter = @import("shark/filter.zig");
    pub const psml = @import("shark/psml.zig");
    pub const pdml = @import("shark/pdml.zig");
    pub const hexdump = @import("shark/hexdump.zig");
    pub const columns = @import("shark/columns.zig");
    pub const fields = @import("shark/fields.zig");
    pub const streams = @import("shark/streams.zig");
    pub const convs = @import("shark/convs.zig");
    pub const capinfo = @import("shark/capinfo.zig");
};

pub const model = struct {
    pub const packet = @import("model/packet.zig");
    pub const session = @import("model/session.zig");
    pub const marks = @import("model/marks.zig");
    pub const loader = @import("model/loader.zig");
    pub const search = @import("model/search.zig");
};

pub const features = struct {
    pub const copy = @import("features/copy.zig");
    pub const recents = @import("features/recents.zig");
    pub const macros = @import("features/macros.zig");
    pub const profiles = @import("features/profiles.zig");
    pub const transfer = @import("features/transfer.zig");
};

pub const ui = struct {
    pub const theme = @import("ui/theme.zig");
    pub const app = @import("ui/app.zig");
    pub const runtime = @import("ui/runtime.zig");
    pub const views = struct {
        pub const help = @import("ui/views/help.zig");
        pub const streams = @import("ui/views/streams.zig");
        pub const convs = @import("ui/views/convs.zig");
        pub const capinfo = @import("ui/views/capinfo.zig");
    };
    pub const widgets = struct {
        pub const packet_table = @import("ui/widgets/packet_table.zig");
        pub const protocol_tree = @import("ui/widgets/protocol_tree.zig");
        pub const hex_view = @import("ui/widgets/hex_view.zig");
        pub const hsplit = @import("ui/widgets/hsplit.zig");
        pub const vsplit = @import("ui/widgets/vsplit.zig");
        pub const overlay = @import("ui/widgets/overlay.zig");
        pub const command_palette = @import("ui/widgets/command_palette.zig");
        pub const filter_bar = @import("ui/widgets/filter_bar.zig");
        pub const status_bar = @import("ui/widgets/status_bar.zig");
        pub const text_util = @import("ui/widgets/text_util.zig");
        pub const header_bar = @import("ui/widgets/header_bar.zig");
    };
    pub const field_filter = @import("ui/field_filter.zig");
    pub const color_rules = @import("ui/color_rules.zig");
};

comptime {
    _ = cache.lru;
    _ = shark.tools;
    _ = shark.process;
    _ = shark.filter;
    _ = shark.psml;
    _ = shark.pdml;
    _ = shark.hexdump;
    _ = shark.columns;
    _ = shark.fields;
    _ = shark.convs;
    _ = shark.streams;
    _ = shark.capinfo;
    _ = xml_util;
    _ = model.packet;
    _ = model.session;
    _ = model.marks;
    _ = model.loader;
    _ = model.search;
    _ = cli;
    _ = config;
    _ = ui.theme;
    _ = ui.widgets.command_palette;
    _ = ui.widgets.packet_table;
    _ = ui.widgets.protocol_tree;
    _ = ui.widgets.hex_view;
    _ = ui.widgets.status_bar;
    _ = ui.widgets.header_bar;
    _ = ui.field_filter;
    _ = ui.color_rules;
    _ = features.macros;
    _ = features.recents;
    _ = platform.clipboard;
    _ = platform.paths;
}
