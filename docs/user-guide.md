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

## Filters

- Display filter: `/` then enter a Wireshark display filter; Enter applies it.
- Up/Down in the filter bar recalls recent filters. An empty bar lists them.
- `=` on a protocol field opens equals, not-equals, and, or, not, and contains. Apply reloads. Prepare only fills the bar. And/or appends to the current expression.
- `=` on the packet list builds a conversation filter from the address pair, including tcp/udp ports when the columns have them.
- `g` or `:goto 1234` selects that frame. A missing frame is a message.
- Capture filter: `-f` on the CLI for live capture.
- Validation uses `tshark -Y … -r empty.pcap`.

## Analysis views

| Command | Description |
|---------|-------------|
| `:streams [n]` | Follow TCP stream `n` (ascii) |
| `:convs [tcp\|udp\|ip\|…]` | Conversation table |
| `:capinfo` | `capinfos` summary |
| `:recents` | Recent files |
| `:theme` | Toggle dark/light |

Marks: `ma` set local mark a, `'a` jump.

Search: focus a pane and press `Ctrl-F`. Use `:search-hex de ad be ef`
for byte patterns and `:search-filter <display filter>` for tshark-backed frame
search. `n` / `N` repeat forward/backward.

Copy: press `c` to copy the focused packet row, protocol field, highlighted
bytes, or filter using OSC52 (or `copy-command`).

Resize: `+`/`-` changes packet-list height, `</>` changes the protocol/hex
split, and `|` toggles the alternate layout. Split dividers are mouse-draggable.

Click a packet-table heading to sort; click it again to reverse.

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
```

Profiles live under `~/.config/zigshark/profiles/<name>/`. Cache under `~/.cache/zigshark/`.

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
