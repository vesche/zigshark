# zigshark roadmap

This file is the work queue. It is the only plan an agent should follow. [roadmap-1.md](roadmap-1.md) is the archive of the parity pass. [parity.md](parity.md) is the termshark baseline, not a queue. Do not edit either of those unless a blocked item below says to record a host result in parity.md.

Prompt that starts a session:

```text
Read docs/roadmap.md and carry out the agent contract from the top. Keep going until the contract tells you to stop. Update the roadmap as you go.
```

## Agent contract

Follow these steps in order. Do not ask which item to do.

1. Read this file. Trust it over memory of an older roadmap.
2. If an item has status `active`, resume it from its **Resume** note. Otherwise start the first item under Ready.
3. Set that item to `active` and write a one-line **Resume** note (`where you are`) before changing code. That is the checkpoint if the session dies.
4. Do that item only. If you discover other work, add a new item. Do not start it.
5. Stay inside the item's **Touch** list and **Do not** list. A file outside **Touch** may change only when the compiler or an existing test forces it.
6. Verify with `zig build` and `zig build test`. An item that names another check runs that check too.
7. When the **Done when** lines are true, move the whole item into Done, newest first, with the date, what changed, and the checks you ran. Delete it from Ready. Clear `active`.
8. Start the next Ready item at step 3.
9. Stop when any of these is true:
   - The next item is under Blocked, or Ready is empty.
   - `zig build test` fails and the failure is not in the files this item touched. Record it under Hazards. Re-run once. If it fails again, add a Ready item ranked by the priority rule and stop.
   - Finishing the item would require breaking its **Do not** list or a rule under Do not build. Mark the item `blocked`, name the gate, and stop.
10. Before you stop, the roadmap must match the tree: no `active` item without a **Resume** note, no finished work still sitting in Ready.

Do not create a git commit unless the user asked. Do not push. Do not weaken a test, a cap, or a **Do not** line to make an item look done.

New work discovered during an item is inserted into Ready or Blocked. Give it the next free id (`R-` or `B-`). Place a Ready item by the priority rule and write one sentence on why it sits above the item under it. Do not renumber existing ids.

## Product

zigshark is a terminal UI that drives tshark. Dissection stays in tshark. zigshark is worth opening when it is the fastest way to filter, jump, compare, export, and keep your place. A change belongs in Ready only when it removes a hang, a leak, a wrong answer, a wait on the selection or quit path, or a repeated reason to open the Wireshark GUI.

A change is done when a person can observe the outcome, `zig build test` passes, and the user-guide plus the in-app help text match the binary if a key or command changed.

## Priority rule

Use this order when inserting an item. Higher bands outrank lower bands. Inside a band, the item that hits more sessions ranks first. A dependency ranks above the item that needs it.

1. Hang, leak, lost write, or a frame that is not the frame the UI named.
2. Time the user waits on every packet selection, filter reload, or quit.
3. A workflow that still sends a person to the Wireshark GUI on an ordinary capture.
4. A missing test on a path that already exists.
5. Structure that the next Ready item would otherwise duplicate.
6. Polish.

Host-gated work is Blocked, not a low Ready rank. Do not generate stand-in captures, skip checks, or "simulate" a host to unblock it.

## Do not build

- Dissectors, or reading libwireshark in-process.
- A second in-memory copy of the unfiltered packet list. `:back` reloads. That was a choice.
- A file-backed packet list, until B-01 has numbers that show the list, not tshark, is what forces swapping.
- JSON instead of PDML. That was measured and rejected.
- Fewer redraws, or virtualizing the packet list. The table already draws the visible window.
- A new protocol statistics table. `:dns` and `:http` earned their commands. Another one needs a repeated workflow written into Ready first.
- The in-UI capture screen, extcap sources, or ring-buffer file sets, until the blocked capture checks say the current capture paths work.
- Android, Termux, and importing termshark config.
- A bit-level packet diagram.

Leave these alone unless a failing test forces a change: the PSML, PDML, and hex parsers; the stacked layout, focus model, and floating dialogs; the filter reload path; the separate list and detail cancel tokens.

## Ready

Items are in rank order. Take the first one.

### R-01 Overlap the two detail tshark runs

- Status: ready
- Outcome: Choosing an uncached frame no longer waits for the PDML process to exit before the hex process starts. The detail log still reports one total and the pdml, hex, and parse parts.
- Why first: Every cache miss pays two process startups, one after the other, in `runDetailWorker`. That is the wait on the hottest path. The log already includes both runs, so this is not a guess.
- Touch: `src/model/loader.zig`, `src/shark/process.zig` only if argv must change, `tests/model_suite.zig`
- Done when:
  - PDML and hex for the same frame window run at the same time, or in one tshark invocation if that invocation's stdout is still the PDML and hex the current parsers accept.
  - Both children, or the single child, use the detail `cancel_token`. A newer selection cancels the in-flight window and its result is not cached.
  - The log line is still `frame N loaded in M ms (pdml A ms, hex B ms, parse C ms)`. The total starts before the dissection work and ends after the parse.
  - A test shows a second selection cancels the first window, and a test shows one window still fills the detail cache for the requested frame.
- Do not: Change `parsePdmlPackets` or `parseHexdumpPackets`. Do not switch the detail format to JSON. Do not cache the unfiltered packet list.

### R-02 Join loader threads when they finish

- Status: ready
- Outcome: A finished list or detail thread is joined and dropped while the session continues. Quit cancels work that is still running and joins only that work.
- Why here: `CaptureLoader.workers` keeps every thread until `deinit`. A long session of selections holds a thread handle per selection. Quit then joins the whole history. R-01 adds more concurrent children, so the leak gets worse if this stays.
- Touch: `src/model/loader.zig`, `tests/model_suite.zig`
- Done when:
  - After a list or detail worker returns, its thread has been joined and is no longer in `workers`.
  - `deinit` cancels the list and detail tokens, then joins only threads that have not been reaped yet.
  - A test with a child that exits immediately shows the handle is gone before the next request returns.
  - A test with a child that would sleep past the test shows `deinit` returns because the child was killed, not because the test waited out the sleep.
- Do not: Change PSML streaming, the packet array, or the cancel-token rules. Do not start R-01's overlap design here if R-01 is already done; call the existing worker.

### R-03 List packets that have a comment

- Status: ready
- Outcome: A person can see every commented frame and press Enter to select one, without opening each packet.
- Why here: `:comment` reads and writes a single frame. Finding the other comments is a reason to open Wireshark. The read and write paths already exist.
- Touch: `src/ui/views/analysis.zig`, `src/ui/commands.zig`, `src/ui/views/help.zig`, `docs/user-guide.md`, `tests/app_suite.zig`, `src/shark/process.zig` only if a new argv helper is required
- Done when:
  - `:comment` with no text still shows the selected frame's `frame.comment`. `:comment <text>` still writes with editcap to a new `<file>.commented.pcapng` and opens that file. The original file stays in place.
  - `:comment list` shows frames whose `frame.comment` is non-empty: frame number and the comment text, one line each. The list stops at 200 rows or 1 MiB and the overlay says so.
  - Enter selects that frame and does not change the display filter. A frame that is not in the current list is a message, not a filter change.
  - A headless test supplies tshark stdout through the scripted runner. It does not need a real editcap or a real capture.
  - The user-guide and the in-app help name `:comment list`.
- Do not: Add a menu arm inside `runMenuChoice`. R-04 attaches commands to the menu. Do not open each packet in the UI to hunt for comments.

### R-04 Menu rows name commands

- Status: ready
- Outcome: A header menu row runs a command that already exists. Adding an analysis command does not require a second switch.
- Why here: `runMenuChoice` is a parallel switch beside `commands.zig`. R-03 must not grow that switch. This item removes it before the next analysis command.
- Touch: `src/ui/app.zig`, `src/ui/commands.zig`, `src/ui/widgets/header_bar.zig`, `tests/app_suite.zig`
- Done when:
  - Analysis and Misc menu rows are command names resolved through `runCommand`, except the rows that are not commands today: field filter (`=`) and the export palette prefill.
  - Export still only fills the palette with `export ` and waits for a path. It does not gain a menu implementation of its own.
  - `:comment list` is a menu row if R-03 is done. If R-03 is not done, do not invent the comment list here.
  - A test activates an analysis menu row and observes the same outcome as the command.
- Do not: Add a menu row for every command. Do not move filter reload or the cancel tokens. Do not redesign the header.

### R-05 Lock quit against the remaining children

- Status: ready
- Outcome: Quitting while a detail load or a wormhole job is in flight returns because those children were cancelled, and tests keep it that way.
- Why here: Field-dump cancel, filter-check cancel, and the held PSML child are already tested. Detail children and wormhole are the quit paths still untested. R-01 and R-02 change the loader, so the tests belong after them.
- Touch: `tests/app_suite.zig`, `tests/model_suite.zig`, and the cancel call site only if a test proves quit still waits
- Done when:
  - A test starts a detail child that would sleep, cancels it the way quit does, and returns well before that sleep ends.
  - A test starts a wormhole job with a stand-in that would sleep, destroys or cancels it the way `AppModel.deinit` does, and returns well before that sleep ends. No network.
  - Existing field-dump, filter-check, and PSML-hold tests still pass.
- Do not: Rewrite `deinit`. Do not add a new cancellation mechanism if the current tokens already kill the child.

### R-06 PTY script covers the tree, the hex pane, and ZZ

- Status: ready
- Outcome: Linux CI drives the fixture through the protocol tree and the hex pane, then quits with `ZZ`.
- Why here: `tests/pty_smoke.py` already renders the fixture, searches, opens `:capinfo`, checks copy-mode Ctrl-C, and checks a clean Ctrl-C. It does not expand the tree, move in hex, or quit with `ZZ`. Headless tests do not see vaxis.
- Touch: `tests/pty_smoke.py`, `.github/workflows/ci.yml` only if the script is not already the Linux step
- Done when:
  - The script opens `tests/fixtures/1.pcap`, focuses the tree, expands a node, moves in the hex view, and quits with `ZZ`.
  - Assertions use the terminal model already in that file. They do not search the raw PTY byte stream for pane text.
  - The script stays Linux-only, next to the existing smoke test, and CI runs it on Linux.
- Do not: Add a second PTY harness. Do not assert colors or timing.

### R-07 Compare can open the other capture

- Status: ready
- Outcome: An identity that exists only in the other file can be opened, instead of stopping at "only in the other capture".
- Why here: `:compare` can select a frame only when it is in the file already open. This is a real gap, and it is a second dissection of both files, so it waits until R-01 has made a detail load cheaper.
- Touch: `src/ui/views/analysis.zig`, `src/ui/commands.zig`, `docs/user-guide.md`, `src/ui/views/help.zig`, `tests/app_suite.zig`
- Done when:
  - Enter on a row that exists only in the other file opens that file and selects the frame. The current file is left as the previous capture the user can reopen, or the message names the path if opening fails.
  - Enter on a row in the current file still selects that frame and does not change the display filter.
  - A headless test covers both rows with the scripted runner. It does not dissect two real files.
- Do not: Dissect both files a second time for the packet list. Do not cache a full second PSML table.

### R-08 Windows CI installs tshark

- Status: ready
- Outcome: `tests/integration_tools.zig` runs on Windows CI instead of skipping for a missing tshark.
- Why here: Linux CI installs tshark. macOS tries Homebrew and ignores failure. Windows skips the integration tests. This is confidence, not a session workflow, so it ranks last among Ready.
- Touch: `.github/workflows/ci.yml`
- Done when:
  - The Windows job installs tshark, or Wireshark's tshark, non-interactively.
  - `zig build test` on that job does not skip `tests/integration_tools.zig` for a missing binary.
  - If the image cannot install tshark, move this item to Blocked with the exact error and the command that failed. Do not leave a red CI hack in the workflow.
- Do not: Change the tests to pass without tshark. Do not fail the macOS job when Homebrew fails.

## Blocked

Do not start these. Do not build a fake host, a generated multi-gig capture, or a partial capture UI to get around the gate.

### B-01 Record one large capture

- Unblock when: A capture file is already in the repo or the user names a path. Do not download one and do not synthesize one.
- Outcome: Time-to-first-row and time-to-detail are written under this item, from the existing log lines. No millisecond assertion.
- Next decision: Only if those numbers show the packet list, not tshark, is what forces swapping, B-02 becomes Ready. Otherwise B-02 stays blocked and the note says which number was tshark.

### B-02 File-backed packet list

- Unblock when: B-01's note says the in-memory list is the problem.
- Outcome: The session does not hold every PSML row in RAM. Streaming PSML stays. `tests/fixtures/1.pcap` stays the correctness fixture.
- Do not start this from a hunch about memory.

### B-03 Verify Linux live capture

- Unblock when: The user says this machine, or a named host, can capture as a member of the capture group.
- Check, in order, and write the host, the Wireshark version, and the result into [parity.md](parity.md):
  - dumpcap as a group member, one interface, `-f` capture filter, stop, reopen the written file.
  - dumpcap missing or unprivileged, tshark fallback, and an error message when both fail. The failure must be a message, not a hang.
  - Two interfaces in one capture. `:clear-packets` hides frames already shown.
- The code paths already exist. A failure becomes a Ready bug ranked by the priority rule. Do not redesign capture while verifying it.

### B-04 Verify macOS, FreeBSD, and Windows capture

- Unblock when: B-03 is done and the user names that host.
- Check: interface names, promiscuous mode, a non-root failure that is a message, and stopping a capture without leaving dumpcap behind. On Windows, also open a file, and capture only if Npcap is present. Ctrl-Z is a no-op there.
- Record the result in [parity.md](parity.md).

### B-05 In-UI capture screen

- Unblock when: B-03 is recorded as passing.
- Outcome: A capture screen for interface multi-select, capture filter, snaplen, promiscuous mode, ring buffer (`-b`), and stop conditions. The display filter does not change what is written.
- Do not build this before the gate. The CLI capture path is the one B-03 checks.

### B-06 Extcap sources

- Unblock when: B-03 is recorded as passing.
- Outcome: sshdump, ciscodump, and the other sources `tshark -D` lists are interfaces with extra fields.
- Do not build this before local capture is verified.

### B-07 Ring-buffer file sets

- Unblock when: The user has a directory of `-b` ring-buffer files.
- Outcome: `mergecap` that directory into the session, and next or previous file when the capture used `-b`.

## Hazards

These are not Ready items. If one happens twice in a session, add a Ready item. If it happens once and a re-run passes, leave it here.

- `model_suite` once panicked in `runOnce` because stdout was already null after a child had exited. It did not reproduce on a fresh run. The null pipe is the bug if it returns. Do not rewrite process spawning from a single sighting.

## Done

Newest first. One short entry. Do not move these back to Ready.

### 2026-11-12 — File-wide expert info

`:expert` still reads `_ws.expert` on the open packet and Enter opens that field. `:expert all` lists `tshark -z expert` (severity and summary, 200 rows or 1 MiB) and Enter selects the frame. Verified with `zig build test`.

### 2026-11-12 — Analysis views left app.zig

Expert, hierarchy, endpoints, conversations, streams, IO graph, DNS, HTTP, compare, export, color, comment, and Lua live in `src/ui/views/analysis.zig`. `commands.zig` calls those functions. Filter reload and the cancel tokens stayed in `src/ui/app.zig`. Verified with `zig build test`.

### 2026-11-12 — Quit, detail timing, stream diagram

Quit kills the field dump and the display-filter check. Menu failures show `Menu action failed: …`. The detail log includes both tshark runs and the parse. `:streams` draws client left and server right; `f` or `:streams filter` applies `tcp.stream == N` or `udp.stream == N`. Enter still selects the frame. Verified with `zig build test`.

## How to edit this file

When an item finishes:

1. Cut it from Ready or Blocked.
2. Paste it under Done with the date and the checks.
3. Drop the **Touch**, **Done when**, and **Do not** bullets from the Done copy. Keep the outcome sentence.
4. If the work revealed a follow-up, add that follow-up under Ready or Blocked before you start it.

When an item blocks:

1. Move it under Blocked.
2. Replace **Why** with **Unblock when**.
3. Leave the code compiling and the tests passing. Do not leave a half-command in the binary.

When you add an item:

1. Use the next free `R-` or `B-` id.
2. Put a Ready item in rank order and say which priority-rule band put it there.
3. Keep **Done when** observable. "Improve" and "clean up" are not outcomes.
