pub const text =
    \\zigshark — keys
    \\
    \\hjkl / arrows     Navigate the focused pane
    \\Tab / Ctrl-W      Cycle list → tree → hex → filter
    \\Click a pane      Focus it. Click [+] or [-] to expand
    \\Tree +/- Enter    Expand or collapse the selected field
    \\Tree ← / →        Collapse / expand (h / l)
    \\Hex click / hjkl  Select a byte; the tree jumps to that field
    \\/                 Focus display filter
    \\:                 Command palette
    \\?                 This help
    \\|                 Toggle layout
    \\\                 Zoom/unzoom focused pane
    \\+ / -             In the list: resize panes. In the tree: expand
    \\< / >             Resize tree / hex
    \\m[a-z] / '[a-z]   Set / jump local mark
    \\m[A-Z] / '[A-Z]   Set / jump global mark
    \\Ctrl-F            Search focused pane
    \\:search-regex     . * + ? [] ^ $ across list, tree, or hex
    \\:search-filter    Jump to the next packet matching a filter
    \\Tab / Shift-Tab   Cycle display-filter field names
    \\:convs            Conversations; j/k and Enter apply a filter
    \\:streams          Follow this packet's stream; Enter filters it
    \\:profile          list, create, use, delete
    \\:theme list       Bundled and installed theme packs
    \\n / N             Next / previous search hit
    \\c                  Enter/leave copy mode
    \\Ctrl-C             Copy in copy mode; otherwise quit
    \\q / ZZ            Quit (confirm / immediate)
    \\Ctrl-Z            Suspend to the shell; fg resumes
    \\:columns          default, delta, absolute, or a tshark column format
    \\:tail             Follow a growing capture file
    \\Ctrl-L            Redraw
    \\Esc               Dismiss overlays
    \\
    \\Commands: load, search, search-hex, streams,
    \\convs, capinfo, columns, set, profile, theme,
    \\recents, wormhole, clear-filter, quit
    \\
;
