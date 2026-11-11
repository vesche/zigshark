# zigshark roadmap

What to build after the parity-through-audit pass. That pass is the record in [roadmap-1.md](roadmap-1.md). [parity.md](parity.md) stays the termshark baseline. This file is the living plan.

Dissection stays in tshark. zigshark should be the fastest way to drive that dissection from a terminal: filter, jump, compare, export, and keep your place in a large capture. A feature earns a place here when it removes a reason to open the Wireshark GUI.

Legend:

- **now** — highest leverage, no new machines required
- **next** — do after the now items
- **blocked** — waiting on a capture host
- **later** — worth doing, not on the critical path
- **out of scope** — will not be built

Suggested order: cancel tshark on quit, then correct the detail timing log, then the stream sequence diagram, then measure one large capture and only then change how detail or the packet list is stored. The capture screen waits for a host that can run dumpcap. Each feature ships with tests. `zig build` and `zig build test` stay the bar.

## 1. Still open

Carried from [roadmap-1.md](roadmap-1.md). These are the only unfinished items from that pass.

### Blocked on a capture host

The code paths exist. Nothing here is a bug to start on a machine that cannot capture.

| Item | Status | What "done" requires |
|------|--------|----------------------|
| Privileged live capture | **blocked** | dumpcap, the tshark fallback, multi-interface selection, growing-file refresh, and `:clear-packets` are implemented. Verify on Linux as a user in the capture group, including a permission failure that stays a message instead of a hang. |
| Platform live capture | **blocked** | Same code paths on macOS, FreeBSD, and Windows. Cover interface names, promiscuous mode, a non-root failure, and stopping a capture without leaving dumpcap behind. |
| In-UI capture screen | **blocked** | After the rows above are verified. Interface multi-select, capture filter, snaplen, promiscuous, ring buffer (`-b`), stop conditions, and a display filter that does not change what is written. |
| Extcap sources | **blocked** | sshdump, ciscodump, and the rest show up in `tshark -D`. Treat them as interfaces with extra fields, after local capture is verified. |
| File sets | **later** | `mergecap` a directory of ring-buffer files into the session, and next/previous file when the capture was `-b`. Skip until someone has a real ring buffer to open. |

VM checklist, for whenever those hosts exist:

- [ ] Linux: dumpcap as a `wireshark` group member, one interface, `-f` capture filter, stop, reopen the written file
- [ ] Linux: dumpcap missing or unprivileged, tshark fallback, error text when both fail
- [ ] Linux: two interfaces in one capture, `:clear-packets` hides frames already shown
- [ ] macOS: interface list and a short capture without a panic on Ctrl-C
- [ ] FreeBSD: same
- [ ] Windows: interface list, file open, and a capture if Npcap is present; Ctrl-Z is a no-op
- [ ] Record the host, Wireshark version, and result in [parity.md](parity.md), then move the deferred rows to **done** or file the real bug

### Unblocked leftovers

- [ ] **now** — Compact sequence diagram for the followed stream. Yaml follow already stores a frame number on each chunk. Draw client left, server right, one line per chunk, and Enter selects that frame. A chunk with no frame number stays unlabeled. `docs/user-guide.md` still says this diagram is waiting on frame numbers. That sentence is stale and goes away with the feature.
- [ ] **next** — File-wide expert info. `:expert` reads `_ws.expert` on the open packet. A full-file `tshark -z expert` list is the missing half: severity, summary, and Enter selects the frame. Keep the open-packet view.
- [ ] **later** — A capture large enough to record time-to-first-row and time-to-detail. Check the numbers in. Do not assert a laptop-specific millisecond. See section 4 before changing the loader from those numbers.
- [ ] **later** — PTY script that opens `tests/fixtures/1.pcap`, focuses the tree, expands a node, moves in the hex view, and quits with `ZZ`. Linux CI only, next to `tests/pty_smoke.py`. The current smoke test draws and dies on Ctrl-C. It does not press keys. vaxis paints by cell diff, so assertions go through the terminal in that script, not a search of the raw PTY bytes.
- [ ] **later** — Windows CI installs tshark so `tests/integration_tools.zig` does not skip there. macOS already tries Homebrew and ignores failure. `.github/workflows/ci.yml` installs tshark on Linux only.

### Out of scope

- Reimplementing dissectors, or reading libwireshark in-process
- A bit-level packet diagram that needs a mouse-pixel layout
- Android, Termux, and termshark config import
- Cloning every Wireshark statistics dialog. A new protocol table has to earn a command the way `:dns` and `:http` did

## 2. New features

Ordered by how often they come up in a session, after the carried items in section 1. The sequence diagram and the file-wide expert list are the two features already named. These are the ones that are not on that list yet.

| Item | Status | Notes |
|------|--------|-------|
| Filter the list to this stream | **now** | `:streams` jumps to a chunk's frame and does not change the display filter. That split is right. The missing action is applying `tcp.stream == N` or `udp.stream == N` from the open stream, as its own key or command, then reloading the list. Enter keeps selecting the frame. |
| Packets with a comment | **next** | `:comment` reads and writes one frame. There is no way to find the other commented frames without opening them. A short list from `frame.comment`, Enter selects the frame. |
| Compare opens the other file | **later** | `:compare` lists identities only in this file and only in the other file, and Enter selects a frame that is in this file. An identity that exists only in the other file cannot be opened. Do this after the list and detail paths are cheap enough that a second capture is not a second full dissection of both files. |

Leave the header menus as they are. Analysis already runs expert, hierarchy, endpoints, and streams. Export fills the command palette with `export ` because the command needs a path.

## 3. Bugs

Confirmed in the current tree. Each one is a behavior a person can hit.

| Item | Where | What is wrong |
|------|--------|----------------|
| Quit waits on the first field dump | `AppModel.loadFieldCompletions` | `fields_cancelled` is checked while splitting lines, after `runCapture` returns. `tshark -G fields` is not on a cancel token. Quitting during that first dump joins the thread until tshark exits. The on-disk field cache is already the fast path. The running child is the gap. |
| Quit waits on filter validation | `AppModel.runFilterCheck` | The check calls tshark and the worker is joined in `deinit`. A slow `-Y` check holds quit. The list and detail children are already killed from their cancel tokens. These two should use that same kill. |
| A menu click can fail silently | `AppModel.activateHeaderItem` | Analysis and Misc call `runMenuChoice(index) catch {}`. An error from opening a field filter, a stream, or a conversation becomes a click that does nothing. |
| Detail timing hides the wait | `runDetailWorker` in `src/model/loader.zig` | The "frame N loaded in M ms" line starts after both tshark processes have returned. It measures the parse. The log understates the time the UI waited. Fix the clock before using it to decide section 4. |

Watch, and do not treat a single sighting as a regression: `model_suite` once panicked in `runOnce` because stdout was already null when a child had exited. It did not reproduce on a fresh test run. If it shows up again, the null pipe is the bug to fix.

## 4. Efficiency

The UI is not the bottleneck. tshark is, and the way zigshark starts it. Measure before swapping formats or storing the packet list on disk. `tests/fixtures/1.pcap` stays the correctness fixture.

What the code does today:

- The packet list appends PSML rows while tshark is still running, in `pcap-bundle-size` chunks. Every summary stays in `Session.packets` until the file is closed or the filter reloads.
- A display-filter change runs PSML again for the whole file. `:back` does too. The unfiltered list is not cached. That was a choice. Do not add a second in-memory copy of the list unless a measured capture says the reload is the wait.
- Selecting an uncached frame runs two tshark processes, one after the other, on the same frame window: PDML (`-T pdml`), then hex (`-x`). The detail cache then serves the previous and next frames from that window.
- `:convs`, `:streams`, `:hierarchy`, `:endpoints`, `:iograph`, `:dns`, `:http`, and `:compare` each spawn their own tshark and stop at 200 rows or 1 MiB. That cap stays.

| Item | Status | Notes |
|------|--------|-------|
| Time the whole detail load | **now** | Include both tshark runs and the parse. Log one line a person can compare across captures. |
| One detail spawn for the window | **next** | After the log is honest. PDML and hex for the same frame range should be one tshark invocation, or two that overlap, still on `cancel_token`. The parsers stay. A new selection still cancels the in-flight request. |
| Reap finished loader threads | **next** | `CaptureLoader.workers` appends every list and detail thread and joins them all in `deinit`. Finished threads only need a join so the handle can be dropped. Quit should join work that is still running. |
| File-backed packet list | **later** | Streaming PSML is in place. Start this only when a real capture forces the process to swap, and only after the large-capture numbers in section 1 exist. |

What not to chase: redrawing fewer cells, a custom dissector, or a packet-list virtualization pass. The table already draws the visible window. JSON instead of PDML was measured on the fixture and rejected. Do not reopen it without a capture where PDML parse time dominates the two tshark runs.

## 5. Code audit

`src/ui/app.zig` is still about 4,000 lines. Command dispatch lives in `src/ui/commands.zig` and `runCommand` forwards there. Filter apply, the analysis views, and drawing stayed on `AppModel` because they share the session. The next feature will land in `app.zig` again unless the analysis views move first.

- [ ] **now** — Move the analysis views into their own file: expert, hierarchy, endpoints, conversations, streams, IO graph, DNS, HTTP, compare, export, color, comment, and lua. `commands.zig` keeps the switch and calls those functions. Filter reload timing and the two cancel tokens stay where they are.
- [ ] **next** — Menu actions and palette commands share one path. Export is the exception, and it should stay a palette command because it needs a path. A new analysis view is a command first and a menu row second.
- [ ] **next** — Read `AppModel.deinit` against a quit during field completion, filter validation, a held PSML child, a detail child, and a wormhole job. The PSML hold is already tested. The other four are joins. Section 3 is the missing cancel.

Leave alone:

- The PSML, PDML, and hex parsers, unless a fixture fails
- The stacked layout, the focus model, and the floating dialogs
- The filter reload path and the separate list and detail cancel tokens
- `termshark_reference/`. It is a reference tree, not a source of patches
