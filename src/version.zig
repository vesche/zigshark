pub const app_name = "zigshark";
pub const app_version = "0.1.0";
pub const app_description = "A terminal UI for tshark, rewritten in Zig with libvaxis";

pub fn versionLine() []const u8 {
    return app_name ++ " " ++ app_version;
}
