# termshark parity checklist

Baseline: termshark v2.4.0 / master. zigshark intentionally uses a clean-break CLI/config.

Legend:

- **done** — wired into the application and verified
- **partial** — usable, but termshark has a richer workflow
- **missing** — not ported yet
- **deferred** — outside the first desktop release scope

| Area | Status | Notes / tests |
|------|--------|---------------|
| Open PCAP file | **done** | Async `model/loader` + PTY smoke |
| Display filter apply/validate | **done** | Macro expansion, validation, async reload |
| Display-filter completion | **partial** | Lazy `tshark -G fields` cache; first-match Tab completion, no popup list yet |
| Capture filter (CLI) | **done** | Applied to dumpcap/tshark live capture |
| Interface list `-D` | done | `shark/tools.listInterfaces` |
| Live capture dumpcap + tshark fallback | **partial** | Multi-interface and growing-file refresh work; fake-dumpcap integration passes. Privileged local capture is unavailable on the development host |
| Stdin | **done** | Spools stdin to a temporary PCAP so details remain seekable |
| FIFO / continuously streaming input | **partial** | File/FIFO source exists; continuous tail semantics still need hardening |
| PSML packet list | **done** | Stable seven-column format, aligned responsive columns, sorting, Wireshark colors |
| PDML protocol tree | **done** | Nested proto/field hierarchy, expansion, scrolling and byte ranges |
| Hex/bytes view + highlight | **done** | Responsive 4/8/16-byte rows, field and search highlights |
| Async list/detail loading + LRU | **done** | Background tshark workers, stale-request generations, bounded detail cache |
| Background-worker process cancellation | **partial** | Stale results are dropped; already-running one-shot tshark children finish before final teardown |
| Packet colors | **done** | `tshark --color` foreground/background PSML attributes |
| Layouts and resizing | **done** | Vertical list/tree/hex default, side-by-side alternate, keyboard and mouse split resizing |
| Column formats parser | **done** | Modern two/three-field rows covered |
| Column editor / arbitrary Wireshark columns | **partial** | Fixed parity-oriented columns plus mouse sorting; editor still missing |
| Follow TCP/UDP streams | **partial** | Scrollable `:streams` view; chunk/frame navigation and display modes still missing |
| Conversations | **partial** | Scrollable tshark table; structured row actions/filter builders still missing |
| Capinfos | **done** | Scrollable `:capinfo` view |
| Search list/details/bytes/hex | **done** | Focus-aware `Ctrl-F`, `n`/`N`, literal and hex byte search |
| Regex and display-filter search | **missing** | Models exist but no complete UI/runtime implementation |
| Local/global marks | **partial** | Lower/uppercase mark bindings work; cross-PCAP persistence is still missing |
| Copy / clipboard | **partial** | Focused row/tree/hex/filter copy via OSC52 or configured command; termshark's expandable copy mode is still missing |
| Recents | **done** | Persisted numbered recents with `:recents` / `:recent` |
| Macros | **done** | Expanded before display-filter validation |
| Profiles | **partial** | `-C`, `:profile create/use`; profile management UI/delete/link remains |
| Wireshark profile | **done** | Configured profile passed to summary/detail tshark commands |
| Themes | **partial** | Propagated light/dark runtime theme; external theme TOML packs still missing |
| Wormhole transfer | **partial** | External CLI integration with missing-tool error; no progress UI |
| Pass-through to tshark | **done** | Auto/explicit modes, zigshark-only flag stripping, file shorthand tests |
| Decode-as / timestamp CLI | **done** | Applied to summary and detail tshark commands |
| Config TOML | **partial** | Core runtime settings persist; not every planned key has a UI |
| Help, menus and command palette | **done** | Keyboard help, clickable header menus, fuzzy command palette |
| Terminal restore / Ctrl-C | **done** | PTY test verifies clean alternate-screen exit with no allocator dump |
| Unix suspend/resume and `--tty` | **missing** | Job-control parity remains |
| Windows/macOS/FreeBSD build | **done** | Native Linux tests plus successful release cross-compiles |
| Platform-specific live capture behavior | **partial** | Requires real-host integration tests on macOS/BSD/Windows |
| Android/Termux | **deferred** | Outside first desktop scope |
| termshark config migration | **n/a** | Clean break by design |

## Known upstream fixes included

- Modern `tshark -G column-formats` rows with missing third field parse correctly (`shark/columns` tests).
- Trailing punctuation in tshark version strings like `4.7.4.` is accepted (`shark/tools` tests).
- `tshark -D` may exit non-zero when dumpcap is restricted; zigshark still lists interfaces from stdout.
