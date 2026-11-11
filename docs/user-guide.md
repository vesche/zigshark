# zigshark user guide

## Install

1. Install Zig 0.17 and Wireshark (`tshark`, optionally `dumpcap` / `capinfos`).
2. Build: `zig build`
3. Run: `./zig-out/bin/zigshark file.pcap`

### Live capture permissions (Linux)

```bash
# Arch / Debian-style
sudo usermod -aG wireshark "$USER"
# then re-login
```

Without dumpcap rights, zigshark still opens PCAPs and will surface a clear error for live capture.

## Opening captures

```bash
zigshark file.pcap
zigshark open file.pcap -Y 'http'
zigshark -r -            # stdin / FIFO (Unix)
```

## Live capture

```bash
zigshark interfaces
zigshark capture -i eth0
zigshark capture -i eth0 -f 'port 53' -w /tmp/out.pcap
```

## Keys

| Key | Action |
|-----|--------|
| `hjkl` / arrows | Move in the focused pane |
| `Tab` / `Ctrl-W` | Cycle list, tree, hex, and filter |
| `/` | Focus the display filter. `Tab` / `Shift-Tab` complete field names |
| Up / Down | In the filter bar, recall recent filters. `<Recent>` opens them as a list; Enter applies one |
| Enter | Apply the display filter immediately. A valid expression also applies after a short pause |
| `=` | On a field: equals, not-equals, and, or, not, contains. On a row: conversation filter. Apply reloads; Prepare only fills the bar |
| `g` / `:goto 1234` | Select that frame. A missing frame is a message |
| `:` | Command palette. The selected row shows the command's arguments |
| `?` | Help |
| `\|` | Toggle stacked and side-by-side layout |
| `\` | Zoom the focused pane |
| `+` / `-` | Resize the packet list. In the tree, expand or collapse |
| `<` / `>` | Resize the tree and hex panes |
| `m` / `'` | Set or jump a mark. Lower case is local, upper case is global |
| `Ctrl-F`, `n` / `N` | Search the focused pane, then next or previous hit |
| `c`, then `Ctrl-C` | Copy. A protocol field copy includes `tcp.port == 443`, the raw value, and the visible subtree |
| `q` / `ZZ` | Quit, with or without confirmation |
| `Ctrl-Z` | Suspend. `fg` resumes |
| `Esc` | Dismiss an overlay |
| Home / `G` | First or last packet. Hex has an offset ruler, a gap after 8 bytes, and the cursor stays distinct inside the selected field |

The filter bar is neutral while empty, green when tshark accepts the expression, and red when it does not. The tshark error line is on the status line. The check runs after a short pause so typing does not wait on tshark, and a valid expression then reloads the packet list. Enter applies it immediately. `<Clear>` removes the filter and reloads the full capture. `<Recent>` lists recent filters; j/k and Enter, or a click, apply one. A `$name` macro shows its expansion on the status line before it is applied.

`:filters` lists saved filters and Enter applies one. `:filters save <name>` stores the current expression, separate from the recent list. `:filters <name>` applies that saved filter.

Rows painted by tshark `--color` use those colors. Profile coloring rules in `[coloring]` are checked in file order and the first match overrides that layer. A rule filter is a protocol name, `contains text` against any column, or empty to match every remaining row. It is not a tshark display filter. The protocol tint is only the fallback when neither tshark nor a profile rule painted the row. A compact stream sequence diagram waits until a followed chunk knows its frame number.

Header menus: Analysis (field filter, go to frame, streams, conversations, capture info) and Misc (columns, theme, profile, marks, tail). Expert, hierarchy, endpoints, and export are listed and not built yet.

## Commands

| Command | Arguments |
|---------|-----------|
| `:goto <frame>` | Select a frame |
| `:streams [tcp\|udp] [index] [ascii\|hex\|raw]` | Follow the selected stream |
| `:convs [tcp\|udp\|ip\|ipv6\|eth]` | Conversations. Enter filters |
| `:columns default\|delta\|absolute\|set <format>\|add <field>\|drop <field>` | Packet-list columns. `add` uses the selected field |
| `:expert` | Expert info on the open packet. Enter opens the field |
| `:hierarchy` | Protocol hierarchy. Enter adds that protocol to the filter |
| `:endpoints [tcp\|udp\|ip\|ipv6\|eth]` | Loudest addresses, sorted by bytes. Enter filters |
| `:export packets\|packet\|json\|csv <path>` | Write the displayed packets. `y` confirms an overwrite |
| `:export objects http\|smb <dir>` | Export objects with tshark |
| `:decode-as [layer==selector,protocol]` | No arguments uses the selected packet |
| `:time-ref` | Set or clear time zero. `Ctrl-T` does the same |
| `:search <text>` | Search the focused pane |
| `:search-regex <pattern>` | `. * + ? [] ^ $`, not PCRE |
| `:search-hex <hex bytes>` | Search packet bytes |
| `:search-filter <display filter>` | Jump to the next matching frame |
| `:load <path>` | Open a capture |
| `:set [<key> <value>]` | List or change a setting. A bad value is not saved |
| `:set tls-keylog-file <path>` | Pass a TLS key log to tshark. The status line shows `tls-keys` |
| `:profile list\|create\|use\|delete <name>` | Profiles |
| `:theme [list\|<name>]` | Theme. `:no-theme` restores the built-in theme |
| `:recent <number>` / `:recent-filter <number>` | Open a recent file or filter |
| `:filters [name\|save <name>\|delete <name>]` | Saved filters, separate from the recent list |
| `:tail` | Follow a growing file. `:clear-packets` hides rows already shown |
| `:capinfo`, `:marks`, `:recents`, `:config`, `:logs`, `:help`, `:quit` | As named |
| `:wormhole [file]` | Send a file with the wormhole CLI |

`:convs` and `:streams` stop after 200 rows, or after 1 MiB of tshark output. The overlay says when that happens. `:expert` does not exist yet; it will use the same cap.

Capture filters are `-f` on the command line. Display-filter checks use `tshark -Y` against an empty pcap.

Click a packet-list heading to sort, and click it again to reverse. Split dividers are mouse-draggable.

## Configuration

`~/.config/zigshark/config.toml`:

```toml
[main]
tshark = "tshark"
dark-mode = true
packet-colors = true
pcap-bundle-size = 1000
pcap-cache-size = 64
layout = "stacked"
theme = "default"

[filters]
"web" = "tcp.port == 443"

[macros]
"web" = "tcp.port == 443"

[coloring]
"dns" = "dns|#010203|#040506"
```

Profiles live under `~/.config/zigshark/profiles/<name>/`. Cache under `~/.cache/zigshark/`.

`pcap-bundle-size` is how many packet-list rows are appended while tshark is still reading. A later chunk leaves the selected row where it is. `pcap-cache-size` is how many dissected packets stay in memory; `:set pcap-cache-size` applies to the open cache. Detail for the previous and next frames is loaded with the selected frame, and selecting that frame again does not start tshark when the cache still has it.

Use `:profile create NAME`, `:profile use NAME`, or `-C NAME`.

Custom themes live at `~/.config/zigshark/themes/NAME.toml`:

```toml
[theme]
fg = "#dcdcdc"
bg = "#1e1e1e"
selected-fg = "#ffffff"
selected-bg = "#3c5078"
header-fg = "#b4b4c8"
header-bg = "#2d2d37"
status-fg = "#c8c8c8"
status-bg = "#282832"
filter-ok-fg = "#78c878"
filter-bad-fg = "#f06464"
pane-border = "#505064"
```

Apply it with `:theme NAME`; `:no-theme` restores the built-in theme.

## Pass-through

When stdout is not a TTY (or `--pass-thru`), zigshark execs `tshark` with the remaining arguments so pipelines keep working.

## Platforms

- **Linux / macOS / BSD**: full feature set including FIFOs and stdin.
- **Windows**: file open, TUI, and tool discovery; dumpcap/extcap paths may need `capture-command` style configuration; Unix job control is unavailable.
- **Android/Termux**: not supported.
