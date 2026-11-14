# zigshark

A terminal UI for [tshark](https://www.wireshark.org/), written in [Zig](https://ziglang.org/) with [libvaxis](https://github.com/rockorager/libvaxis).

zigshark is an active clean-room rewrite of [termshark](https://github.com/gcla/termshark). The offline analysis path is usable today: aligned packet list, nested protocol tree, highlighted hex view, filters, search, marks, streams, conversations, profiles, and live-capture orchestration. [docs/parity.md](docs/parity.md) is the termshark baseline. [docs/roadmap.md](docs/roadmap.md) is what to build next. [docs/roadmap-1.md](docs/roadmap-1.md) is the finished pass.

https://github.com/vesche/zigshark/raw/main/demo.mp4

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
| `m` / `'` + letter | Set / jump a mark |
| `[` / `]` | Previous / next packet in this conversation |
| `Ctrl-P` | Previous display filter |
| `Ctrl-F` | Search focused pane |
| `n` / `N` | Next / previous search hit |
| `c` | Enter copy mode (`Ctrl-C` copies, `Esc` cancels) |
| `+` / `-` | Resize packet list |
| `<` / `>` | Resize protocol/hex panes |
| `q` | Quit (confirm) |
| `ZZ` | Quit immediately |
| `Esc` | Dismiss overlays |

### Commands

`quit`, `help`, `filter`, `clear-filter`, `back`, `load`, `search`, `search-hex`, `search-regex`, `streams`, `convs`, `capinfo`, `columns`, `set`, `profile`, `theme`, `recents`, `recent`, `marks`, `mark`, `goto`, `expert`, `hierarchy`, `endpoints`, `iograph`, `dns`, `http`, `compare`, `export`, `decode-as`, `color`, `comment`, `lua`, `related`, `wormhole`. The full list is in [docs/user-guide.md](docs/user-guide.md) and `?` inside the TUI.

## Configuration

Default path: `$XDG_CONFIG_HOME/zigshark/config.toml` (or `~/.config/zigshark/config.toml`).

See [docs/user-guide.md](docs/user-guide.md), [docs/parity.md](docs/parity.md), and [docs/roadmap.md](docs/roadmap.md).

## Architecture

Packet capture and dissection stay in Wireshark tools. zigshark owns:

- Process orchestration and cancellation
- PSML / PDML / hexdump parsing and lazy detail loading
- Bounded caches and session state
- libvaxis / vxfw TUI

## License

MIT. Wireshark / tshark remain under their own licenses.
