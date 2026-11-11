# termshark parity checklist

Baseline: termshark v2.4.0 / master. zigshark intentionally uses a clean-break CLI/config.

Legend:

- **done** — wired into the application and verified
- **partial** — usable, but termshark has a richer workflow
- **missing** — not ported yet
- **deferred** — implemented far enough to run, but not verified until capture VMs are available
- **out of scope** — will not be built

| Area | Status | Notes / tests |
|------|--------|---------------|
| Open PCAP file | **done** | Async `model/loader` + PTY smoke |
| Display filter apply/validate | **done** | Macro expansion, validation, async reload |
| Display-filter completion | **done** | Lazy field cache. Tab and Shift-Tab cycle matches for the token being typed and show `n/total` |
| Capture filter (CLI) | **done** | Applied to dumpcap/tshark live capture |
| Interface list `-D` | done | `shark/tools.listInterfaces` |
| Live capture dumpcap + tshark fallback | **deferred** | Dumpcap, the tshark fallback, multi-interface selection, and growing-file refresh are implemented. `:clear-packets` during a capture hides frames already on screen and keeps packets that arrive after that. Privileged capture will be verified later on VMs, not on this machine |
| Stdin | **done** | Spools stdin to a temporary PCAP so details remain seekable |
| FIFO / continuously streaming input | **done** | Named pipes are tailed automatically. `:tail` toggles the same refresh for a capture another process is still writing |
| PSML packet list | **done** | Stable seven-column format, aligned responsive columns, sorting, Wireshark colors |
| PDML protocol tree | **done** | Nested proto/field hierarchy, expansion, scrolling and byte ranges |
| Hex/bytes view + highlight | **done** | Responsive 4/8/16-byte rows, field and search highlights |
| Async list/detail loading + LRU | **done** | Background tshark workers, stale-request generations, bounded detail cache |
| Background-worker process cancellation | **done** | A new list or detail request, and shutdown, kill the tshark child instead of waiting for it to finish |
| Packet colors | **done** | `tshark --color` foreground/background PSML attributes |
| Layouts and resizing | **done** | Vertical list/tree/hex default, side-by-side alternate, keyboard and mouse split resizing |
| Column formats parser | **done** | Modern two/three-field rows covered |
| Column editor / arbitrary Wireshark columns | **done** | `:columns default`, `delta`, `absolute`, or `set gui.column.format:...`. The list uses the PSML titles tshark returns. Click a heading to sort |
| Follow TCP/UDP streams | **done** | `:streams` follows the current packet. Yaml follow supplies the frame number and Enter selects it. Without that output, Enter still searches with `frame contains` and the status line says `guess` |
| Conversations | **done** | `:convs [tcp\|udp\|ip\|ipv6\|eth]` is a selectable list. Enter builds a two-endpoint display filter and applies it |
| Capinfos | **done** | Scrollable `:capinfo` view |
| Search list/details/bytes/hex | **done** | Focus-aware `Ctrl-F`, `n`/`N`, literal and hex byte search |
| Regex and display-filter search | **done** | `:search-regex` (`. * + ? [] ^ $`) on the list, tree, or hex pane. `:search-filter` jumps to the next matching frame |
| Local/global marks | **done** | Lowercase marks are per session. Uppercase marks are written to `config.toml` and reopen the right file |
| Copy / clipboard | **done** | OSC52 or the configured copy command. Copy mode on the protocol tree copies the selected field and the children currently shown under it |
| Recents | **done** | Persisted numbered recents with `:recents` / `:recent` |
| Macros | **done** | Expanded before display-filter validation |
| Profiles | **done** | `:profile list`, `create`, `use`, and `delete` |
| Wireshark profile | **done** | Configured profile passed to summary/detail tshark commands |
| Themes | **done** | Light/dark plus TOML packs. `:theme midnight` loads `themes/midnight.toml` or `~/.config/zigshark/themes/`. `:theme list` |
| Wormhole transfer | **done** | `:wormhole` runs in the background and the overlay shows the code and transfer output as wormhole prints it |
| Pass-through to tshark | **done** | Auto/explicit modes, zigshark-only flag stripping, file shorthand tests |
| Decode-as / timestamp CLI | **done** | Applied to summary and detail tshark commands |
| Config TOML | **done** | `:set` lists every key and writes it back to `config.toml`. Load ignores unknown or malformed keys so an old file still opens |
| Help, menus and command palette | **done** | Keyboard help, clickable header menus, fuzzy command palette |
| Terminal restore / Ctrl-C | **done** | PTY test verifies clean alternate-screen exit with no allocator dump |
| Unix suspend/resume and `--tty` | **done** | Ctrl-Z restores the terminal and stops the process; `fg` resumes the UI. `--tty` forces the interface onto the controlling terminal |
| Windows/macOS/FreeBSD build | **done** | Native Linux tests plus successful release cross-compiles |
| Platform-specific live capture behavior | **deferred** | Same as live capture: the code paths exist, and host checks wait for VMs |
| Android/Termux | **out of scope** | Not planned. zigshark targets desktop Linux, macOS, BSD, and Windows |
| termshark config migration | **n/a** | Clean break by design |

## Known upstream fixes included

- Modern `tshark -G column-formats` rows with missing third field parse correctly (`shark/columns` tests).
- Trailing punctuation in tshark version strings like `4.7.4.` is accepted (`shark/tools` tests).
- `tshark -D` may exit non-zero when dumpcap is restricted; zigshark still lists interfaces from stdout.
