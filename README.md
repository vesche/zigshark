# zigshark

A terminal UI for [tshark](https://www.wireshark.org/), rewritten in [Zig](https://ziglang.org/) with [libvaxis](https://github.com/rockorager/libvaxis).

zigshark is an active clean-room rewrite of [termshark](https://github.com/gcla/termshark). The offline analysis path is usable today: aligned packet list, nested protocol tree, highlighted hex view, filters, search, marks, streams, conversations, profiles, and live-capture orchestration. Some advanced termshark workflows are still being ported; [docs/parity.md](docs/parity.md) tracks them without treating parser-only or stub code as complete.

## Requirements

- Zig **0.17.x**
- Wireshark tools: `tshark` (required), `dumpcap` / `capinfos` (recommended)
- A real TTY (truecolor terminals work best)

Live capture needs dumpcap permissions (for example membership in the `wireshark` group on Linux). Offline PCAP analysis works without that.

## Build

```bash
zig build
zig build test
./zig-out/bin/zigshark --help
```

## Usage

```bash
zigshark capture.pcap
zigshark open capture.pcap -Y 'tcp.port == 443'
zigshark capture -i eth0 -f 'tcp'
zigshark interfaces
zigshark -vv
```

Non-TTY stdout auto-forwards to `tshark` (`--pass-thru=auto`).

### TUI keys

| Key | Action |
|-----|--------|
| `hjkl` / arrows | Navigate focused pane |
| `Tab` / `Ctrl-W` | Cycle panes |
| `/` | Focus display filter |
| `:` | Command palette |
| `?` | Help |
| `\|` | Toggle layout |
| `\` | Zoom focused pane |
| `m` / `'` + letter | Set / jump local mark |
| `Ctrl-F` | Search focused pane |
| `n` / `N` | Next / previous search hit |
| `c` | Enter copy mode (`Ctrl-C` copies, `Esc` cancels) |
| `+` / `-` | Resize packet list |
| `<` / `>` | Resize protocol/hex panes |
| `q` | Quit (confirm) |
| `ZZ` | Quit immediately |
| `Esc` | Dismiss overlays |

### Commands

`quit`, `help`, `filter`, `clear-filter`, `load`, `search`, `search-hex`, `streams`, `convs`, `capinfo`, `columns`, `set`, `profile`, `theme`, `recents`, `recent`, `marks`, `wormhole`, …

## Configuration

Default path: `$XDG_CONFIG_HOME/zigshark/config.toml` (or `~/.config/zigshark/config.toml`).

See [docs/user-guide.md](docs/user-guide.md) and [docs/parity.md](docs/parity.md).

## Architecture

Packet capture and dissection stay in Wireshark tools. zigshark owns:

- Process orchestration and cancellation
- PSML / PDML / hexdump parsing and lazy detail loading
- Bounded caches and session state
- libvaxis / vxfw TUI

## License

MIT. Wireshark / tshark remain under their own licenses.
