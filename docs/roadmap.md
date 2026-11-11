# zigshark roadmap

Tracking doc for work after the termshark parity pass. [parity.md](parity.md) stays the checklist for that baseline. This file is what to build next, and what to leave alone until the machines exist to test it.

Dissection stays in tshark. zigshark should be the fastest way to *drive* that dissection from a terminal: filter, jump, compare, export, and keep your place in a large capture. A feature earns a place here when it removes a reason to open the Wireshark GUI.

Legend:

- **now** — highest leverage, no new machines required
- **next** — do after the now items
- **blocked** — implemented or designed, waiting on capture VMs
- **later** — worth doing, not on the critical path
- **out of scope** — will not be built

Suggested order, once someone sits down to build: field filters, then the small analysis views (expert, hierarchy, endpoints, go-to-frame, time reference), then export and apply-as-column, then the large-capture performance work, then the code-quality pass. Live capture UI waits for VMs. Each feature ships with tests; do not grow the suite as a separate project ahead of the features.

## 1. Still open from parity

Nothing here is a code gap to start on this machine. Android is not a future task.

| Item | Status | What "done" requires |
|------|--------|----------------------|
| Privileged live capture | **blocked** | dumpcap, the tshark fallback, multi-interface selection, growing-file refresh, and `:clear-packets` are implemented. Verify on Linux as a user in the capture group, including a permission failure that stays a message instead of a hang. |
| Platform live capture | **blocked** | Same code paths on macOS, FreeBSD, and Windows. Cover interface names, promiscuous mode, a non-root failure, and stopping a capture without leaving dumpcap behind. |
| Android / Termux | **out of scope** | Desktop Linux, macOS, BSD, and Windows only. |
| termshark config migration | **out of scope** | Clean break. zigshark reads only its own TOML. |

VM checklist, for whenever those hosts exist:

- [ ] Linux: dumpcap as a `wireshark` group member, one interface, `-f` capture filter, stop, reopen the written file
- [ ] Linux: dumpcap missing or unprivileged, tshark fallback, error text when both fail
- [ ] Linux: two interfaces in one capture, `:clear-packets` hides frames already shown
- [ ] macOS: interface list and a short capture without a panic on Ctrl-C
- [ ] FreeBSD: same
- [ ] Windows: interface list, file open, and a capture if Npcap is present; Ctrl-Z is a no-op
- [ ] Record the host, Wireshark version, and result in [parity.md](parity.md), then move the two deferred rows to **done** or file the real bug

## 2. Test coverage

`zig build test` is the bar. It already covers CLI parsing, config and profiles, the `tests/fixtures/1.pcap` PSML/PDML/hex fixtures, conversations, streams, columns, fields, capinfos, session sort and marks, search, frame retention, cancellation before spawn, the detail LRU, theme files, hex hit testing, protocol-tree jump on the real PDML, column hit testing, the command palette, and a live tshark integration test that skips when tshark is absent. Linux CI also runs `tests/pty_smoke.py` for a render and a clean Ctrl-C.

The hole was `src/ui/app.zig`: command dispatch, filter completion, hex-to-tree linking, and `:clear-packets` lived only in the draw loop. `tests/app_suite.zig` now drives those without a TTY. The Next cases are covered in the parser, model, loader, and UI suites. The PTY smoke test still only checks that the process draws and dies cleanly. It does not press keys. Tail refresh, and the items under Later, are still untested.

### Now

Headless coverage lives in `tests/app_suite.zig`. `AppModel.initOffline` builds the controller and `runCommand` / `completeFilter` / `applyMark` / `activatePick` run without a TTY. tshark is not spawned; a scripted runner supplies stdout, and the loader records the PSML argv. Splitting `src/ui/app.zig` itself stays in section 6, now that these tests exist.

- [x] Pull command handling out of the draw loop far enough that tests can run `:convs`, `:streams`, `:columns`, `:set`, `:clear-packets`, `:search-filter`, and mark jumps without a TTY
- [x] Filter completion: Tab and Shift-Tab cycle the original stem, the `n/total` note matches, and a new stem resets the index
- [x] `:clear-packets` during tail or live capture sets the cutoff and the next PSML load keeps only newer frames. Opening a file clears the cutoff
- [x] Hex cursor calls `selectCovering` once per move. The link guard stops the tree from moving the cursor back
- [x] `:columns default|delta|absolute|set` changes the format string passed into the PSML argv
- [x] Stream-from-packet uses `tcp.stream` then `udp.stream`. A chunk builds `frame contains` from its first bytes and does not replace the list filter
- [x] Conversation Enter builds the display filter for tcp, udp, eth, and ip/ipv6
- [x] `:set` of a bad value does not persist, and an unknown key does not wipe the file

### Next

- [x] Sort: reverse the same column, numeric versus text columns, and keep the selected frame when the row moves
- [x] PSML with more than seven columns, and a packet whose column count is short
- [x] Truncated PDML, a hidden field nested under a visible field, and a field with no `pos`
- [x] Hexdump with a short last line, a blank line, and a packet longer than one row
- [x] Regex: class at end of input, `^` not at the start, `$` in the middle, an escaped metacharacter, an odd trailing hex nibble
- [x] Loader: a stale generation drops its result, a second request cancels the first child, cache eviction frees the bundle
- [x] Recent files: one policy. `addRecentFile` moves the newest path to index 0. The old `pushRecent` behavior is gone (see section 6)
- [x] Wormhole job: missing binary, a line of progress, failure text. No network
- [x] Theme load falls back from `~/.config/zigshark/themes` to `themes/<name>.toml`
- [x] Narrow packet list (width under 70) and a click past the last column

### Later, with the performance work

- [ ] A capture large enough to show time-to-first-row and time-to-detail. Check the numbers in, do not assert a laptop-specific millisecond
- [ ] PTY script that opens the fixture, focuses the tree, expands a node, moves in the hex view, and quits with `ZZ`. Linux CI only, next to the existing smoke test
- [ ] Windows CI installs tshark so `tests/integration_tools.zig` does not skip there. macOS already tries Homebrew and ignores failure

Do not turn `tests/suite.zig` back into an importer. Each suite file is its own test root because a child module cannot see the root's `zigshark` import.

## 3. UI and UX

The three panes work. What still feels like a tool you have to already know is the filter bar, the menus, and the lack of a way to act on the field under the cursor.

### Filtering

| Item | Status | Notes |
|------|--------|-------|
| Apply or prepare a filter from the selected field | **done** | `=` on the protocol tree opens equals, not-equals, and, or, not, and contains. Apply reloads. Prepare only fills the bar. And/or appends to the current expression. |
| Filter from the packet list | **done** | `=` on the selected row builds an `ip.addr` pair, or tcp/udp with ports when the columns have them. Apply reloads. Prepare only fills the bar. Time reference waits until that feature exists. |
| Recent filters on the filter bar | **done** | Up/Down while the filter bar is focused recalls recent filters. `<Recent>` opens a list and Enter applies the selected one. `<Clear>` removes the display filter. |
| Filter expression feedback | **done** | Empty is neutral, a valid filter is green, and an invalid one is red. The check runs after a short pause. A valid expression reloads the packet list; Enter applies it immediately. The tshark error line is on the status line. |
| Saved filter library | **done** | Named filters live in the profile `[filters]` section, separate from the recent list. `:filters` lists them, Enter or `:filters <name>` applies one, and `:filters save <name>` stores the current expression. |
| Display-filter macros in the bar | **done** | `$name` still expands before validation. The status line shows the expanded expression while the bar still contains the macro, before Enter applies it. |

### Menus and commands

| Item | Status | Notes |
|------|--------|-------|
| Header menus match the commands that exist | **done** | Analysis reaches filter-from-field, go-to-frame, streams, conversations, and capture info. Expert, hierarchy, endpoints, and export are listed and say they are not built yet. Misc reaches columns, theme, profile, marks, and tail. `:goto` is in the palette. |
| Go to frame | **done** | `g` opens `:goto`, and `:goto 1234` selects that frame and loads its detail. Out-of-range is a message. |
| Command help on the palette row | **done** | The selected command shows its arguments, including `:streams [tcp\|udp] [index] [ascii\|hex\|raw]`, `:columns … set <format>`, and `:decode-as layer==selector,protocol`. |
| Field copy includes the filter form | **done** | Copying a protocol field includes the display-filter atom (`tcp.port == 443`), the raw value, and the visible subtree. |
| User guide matches the binary | **done** | `docs/user-guide.md` and the in-app help list the keys and commands the binary actually has. |

### Beautification

Keep the stacked list / tree / hex layout. Polish is in the details, not a new theme.

- [x] **now** — One selected row treatment. Focused pane is bright. Unfocused selection stays readable and is not the same color as a protocol tint
- [x] **now** — Tree guides that survive narrow terminals: marker, name, and value stay aligned when the value is truncated
- [x] **now** — Status line: frame `n/total`, display filter active, capture or tail state, and the current key hint. Drop duplicated text
- [x] **next** — Packet colors from tshark win over the protocol tint. The tint is only the fallback when `--color` did not paint the row
- [x] **next** — Hex: offset ruler, a gap at 8 bytes, and the selected field's range visible while the cursor byte stays distinct
- [x] **later** — User coloring rules (`name`, filter, fg, bg) stored in the profile, evaluated in order, with tshark's colors as the default layer. A rule matches a protocol name, `contains` text in any column, or every row when the filter is empty
- [ ] **later** — A compact sequence diagram for the followed stream (client left, server right, one line per chunk). This waits until follow-stream frame mapping is honest; a chunk jump is still a `frame contains` guess

## 4. Performance

The UI is not the bottleneck. tshark is. The packet list now appends rows while that process is still running, and the detail cache keeps the neighboring frames from the same dissection. A newly selected packet that is not in the cache still pays for a PDML parse plus a hex dump.

Measure before swapping formats. PSML load, detail load, and filter validation write a timing line on a multi-megabyte capture. Keep `tests/fixtures/1.pcap` as the correctness fixture.

| Item | Status | Notes |
|------|--------|-------|
| Paint the first packet rows before tshark exits | **done** | PSML is parsed as stdout arrives. Rows are appended in `pcap-bundle-size` chunks, and a later chunk keeps the selected frame. The log records how many rows were visible and how many milliseconds that took. |
| Prefetch detail for the next and previous frame | **done** | The detail request covers the previous frame and the following frames that fit in `pcap-cache-size`. Those bundles go into the LRU. Selecting one of them does not spawn tshark. A new selection cancels the in-flight request. |
| Resize the detail cache when the setting changes | **done** | `:set pcap-cache-size` changes the live LRU and drops the oldest bundles when the new cap is smaller. |
| Stop reloading for a no-op | **done** | Submitting the display filter that is already loaded does not start another PSML run. A cached packet's detail is cloned from the LRU instead of spawning tshark. |
| Debounce filter validation | **done** | The filter bar waits out a short pause, and a verdict is dropped when the text has changed. The log records how long the check took. |
| Bound conversation, stream, and expert output | **done** | `:convs` and `:streams` stop at 200 rows or 1 MiB of tshark output, and the overlay says the rest was not loaded. `:expert` is still a section 5 view; it has to use the same cap. |
| Choose PDML versus JSON from data | **done** | On `tests/fixtures/1.pcap` with tshark 4.7.4, JSON is smaller (6 KB vs 19 KB for frame 1, 96 KB vs 307 KB for the file) and both finishes are under a second. That size win does not pay for a new detail parser, so the detail path stays PDML. |
| File-backed list for captures that do not fit | **later** | Streaming PSML is in place. This stays unstarted until a real capture forces the process to swap. |

What not to chase: redrawing fewer cells, a custom dissector, or a packet-list virtualization pass. The table already draws the visible window.

## 5. Features past termshark

These are the Wireshark workflows that still make people leave a terminal. They are ordered by how often they come up in a normal analysis session, not by how impressive they sound.

### Now — the session loop

**Field filters.** Covered in section 3. This is the feature. Wireshark's "Apply as Filter" is why the GUI is faster than a typed display filter for almost every investigation.

**Expert information.** **done** for the open packet. `:expert` reads `_ws.expert` from the packet already loaded, groups error, warning, note, and chat, and Enter selects that field. The status line shows `expert N` when the packet has any. A full-file `tshark -z expert` index is still a follow-up.

**Go to frame and time reference.** **done.** `:goto N` and `g` select a frame. `Ctrl-T` or `:time-ref` sets that frame as time zero and clears it on a second press. The Time column shows seconds since that frame without a tshark reload. `:columns delta` stays the previous-packet preset.

**Apply field as column.** **done.** `:columns add` uses the selected tree field, or `:columns add <field>`, and reloads PSML with `%Cus:<field>`. `:columns drop` removes that custom column.

**Protocol hierarchy and endpoints.** **done.** `:hierarchy` reads `tshark -z io,phs` and Enter appends that protocol to the display filter. `:endpoints [tcp|udp|ip|ipv6|eth]` lists addresses sorted by bytes. Enter filters to that address; a tcp or udp row also includes its port. The list stops at 200 rows.

**Export.** **done.** `:export packets <path>` writes the displayed packets as pcapng. `:export packet <path>` writes the selected frame. `:export json <path>` and `:export csv <path>` write the rows on screen. `:export objects http|smb <dir>` uses `--export-objects`. An existing file asks for `y` before it is replaced. A tshark failure shows its stderr.

**Decode As on the selection.** **done.** `:decode-as layer==selector,protocol` still adds a raw rule. With no arguments it lists the open packet's tcp ports, udp ports, and ethertype, then a short list of protocols that `tshark -G protocols` actually has (http, tls, dns, and a few others). Enter reloads.

**TLS key log.** **done.** `:set tls-keylog-file <path>` is passed as `-o tls.keylog_file:...` on summary and detail, and the status line shows `tls-keys` while it is set. Clear it with an empty value. The list and the open packet reload so a still-encrypted handshake is obvious.

### Next — depth on what is already there

**Stream follow that knows frames.** tshark's follow text has no frame numbers, so a chunk jump uses `frame contains` on the first bytes and can hit the wrong packet. Prefer a dissection that carries frame numbers if the installed tshark can emit one (`-z follow` with a format that includes them, or PDML `tcp.payload` ranges). Fall back to the current search and say when the match is only a guess.

**Related packets.** Without changing the display filter: next/previous packet in this conversation, next/previous with the same address, and the other side of a request/response when the protocol field exists (DNS, ICMP, HTTP). Wireshark hides this under a pop-up. A couple of keys is the better version.

**Name resolution toggle.** `:set name-resolution` maps to tshark `-N` and reloads. Show resolved names and the raw address in the tree the way PDML already can, and make the column choice explicit so a capture does not silently depend on DNS.

**Capture display filter while a file is growing.** `:tail` reloads the file. Applying a display filter during tail must keep the cutoff from `:clear-packets` and must not drop the tail flag.

**Marks with notes.** Lowercase and uppercase marks stay. Add a one-line note per mark, shown in `:marks` and stored with the global marks. A note is the difference between a bookmark and a letter.

**Filter the list without losing the unfiltered capture.** Wireshark keeps the file and swaps the displayed set. zigshark already reloads via tshark, which is the right model. Make the previous filter one key away, and show `shown/total` when the total is known from the unfiltered load. Cache the unfiltered PSML only if the measurement in section 4 says the reload hurts.

### Later — after the session loop is good

**In-UI capture options.** Depends on the VM work in section 1. A capture screen: interface multi-select, capture filter, snaplen, promiscuous, ring buffer (`-b`), stop conditions, and a display filter that does not change what is written. Not a second CLI.

**Extcap sources.** sshdump, ciscodump, and the rest show up in `tshark -D`. Treat them as interfaces with extra fields, after local capture is verified.

**File sets.** `mergecap` a directory of ring-buffer files into the session, and next/previous file when the capture was `-b`. Skip until someone has a real ring buffer to open.

**IO graph.** An ASCII packets-per-interval strip from `tshark -z io,stat`. Useful, and easy to build badly. Do it after hierarchy and endpoints, which answer the same question more directly.

**DNS and HTTP tables.** `:dns` and `:http` as filtered tables (query, response code, host, URI) via tshark statistics or a field dump. Enter applies a filter. Add other protocols only when a capture in hand needs them. Do not pre-build a statistics catalog.

**Coloring-rule editor.** Listed under beautification. It matters more once field filters exist, because rules and filters are the same language.

**Packet comments.** Read and write pcapng comments with `editcap` / tshark where the tool can. Session notes stay in marks if the file format cannot round-trip a comment cleanly.

**Two-capture compare.** Load a second file as a reference and show frames whose identity (stream, ports, payload hash) differs. This is a zigshark feature, not a port. It waits until export and field filters are solid enough to trust the identity.

**Lua.** Run an existing tshark Lua script with `-X lua_script:`. Do not invent a zigshark plugin API.

### Out of scope

- Reimplementing dissectors, or reading libwireshark in-process
- A bit-level packet diagram that needs a mouse-pixel layout
- Android, Termux, and termshark config import
- Cloning every Wireshark statistics dialog. New stats have to earn a command

## 6. Code quality audit

A dedicated pass, after the field-filter and analysis views, not mixed into them. The goal is to make the next feature smaller. Fix what the audit proves; do not restyle files that are only older.

### Known debt

These are already visible. Confirm each one before deleting anything.

| Item | Where | What to do |
|------|--------|------------|
| The UI controller is one file | `src/ui/app.zig`, about 2,200 lines | The section 2 command tests now exist (`tests/app_suite.zig`). Split command dispatch, capture/tail, and filter completion from drawing. The tests are there so the split does not change behavior unnoticed. |
| Settings that persist and do nothing | `src/config.zig` | `disk-cache-size-mb`, `ui-cache-size`, `stream-cache-size`, `disable-shark-fin`, `conv-absolute-time`, `capture-command`, `tail-command`, `wormhole-length`, `wormhole-rendezvous-url`, and `wormhole-transit-relay` are saved and listed by `:set`. Either wire them (wormhole flags into the job argv, conversation time into the convs view, capture command into the live argv) or stop presenting them as live options. |
| Detail cache size is sticky | `src/ui/app.zig` `:set pcap-cache-size` | Resolved. `:set pcap-cache-size` resizes the live LRU and evicts the oldest bundles when the cap shrinks. |
| Two recent-file policies | `src/features/recents.zig`, `Config.addRecentFile` | Resolved. Opening a capture calls `addRecentFile`, which moves the newest path to index 0 and drops the oldest from the end. The separate `pushRecent` policy is gone. |
| `--tty PATH` does not retarget the terminal | `src/cli.zig`, `src/main.zig` | The flag forces the TUI onto the controlling terminal. vaxis still opens `/dev/tty`. Say that in the help text until it is true. |
| Palette match line is a no-op | `command_palette.zig` `matching` | `startsWith(..., "")` is always true. Use the parsed command as the needle and test an empty palette against a typed prefix. |
| Copy is the expanded rows only | protocol tree copy mode | Fine if the command says "visible subtree". A "copy field" action should be the one node. Do not pretend it is a PDML export. |
| Custom regex | `src/model/search.zig` | The engine is a small greedy matcher (`. * + ? [] ^ $` and escapes). Keep it if the tests in section 2 stay honest about what it will not do. Do not let `:search-regex` claim to be PCRE. |

### Audit pass

- [ ] Read every `:set` key and mark it used, used-on-restart, or dead. The dead list above is the starting point
- [ ] Trace one packet from `requestDetail` to the hex highlight, including the cancel path, and note leaks on the error returns
- [ ] Check worker threads on quit: a PSML child, a detail child, the field-completion thread, and a wormhole job all stop
- [ ] Look for parsers that accept the fixture and reject the next tshark version's extra attribute, instead of the reverse
- [ ] Run `zig build test` under a memory allocator that reports leaks after the command-dispatch tests exist
- [ ] Re-read `docs/user-guide.md` and `README.md` against `:help` and delete commands the binary does not have

### Leave alone

- The PSML, PDML, and hex parsers, unless a fixture fails. They have tests and they match the files tshark emits
- The stacked layout and the focus model. Reworking them is a UX project, not a cleanup
- `termshark_reference/`. It is a reference tree, not a source of patches
