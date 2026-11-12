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

None.

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

### 2026-11-12 — Windows CI installs tshark

The Windows job installs Wireshark with winget, non-interactively, and adds `C:\Program Files\Wireshark` to PATH before `zig build test`. The install step fails if `tshark.exe` is missing, so the integration tests are not skipped for a missing binary. The macOS Homebrew failure is still ignored. Verified with `zig build` and `zig build test` on this Linux host. The Windows runner itself was not executed here.

### 2026-11-12 — Compare can open the other capture

Enter on a row in the current file selects that frame and leaves the display filter unchanged. Enter on a row that exists only in the other file opens that file, selects its frame when the list loads, and keeps the previous file in recent files. If opening fails, the message names the path. Verified with `zig build` and `zig build test`.

### 2026-11-12 — PTY script covers the tree, hex, and ZZ

The Linux smoke test focuses the protocol tree, expands a node, moves in the hex pane, and quits with `ZZ`. Assertions use the terminal model. CI already runs the script on Linux. Verified with `python3 tests/pty_smoke.py`, `zig build`, and `zig build test`.

### 2026-11-12 — Quit cancels detail and wormhole

Quitting cancels a sleeping detail load through the loader, and `AppModel.deinit` destroys a wormhole job by killing that child. Neither path waits out the sleep. Field-dump, filter-check, and held-PSML quit tests still pass. Verified with `zig build` and `zig build test`.

### 2026-11-12 — Menu rows name commands

Analysis and Misc menu rows are command names passed to `runCommand`. `=` still opens the field filter, and `export` still only fills the palette with `export `. `:comment list` is a menu row. Verified with `zig build` and `zig build test`.

### 2026-11-12 — List packets that have a comment

`:comment` still reads `frame.comment` on the selected frame, and `:comment <text>` still writes it with editcap to a new `.commented.pcapng`. `:comment list` lists commented frames (200 rows or 1 MiB) and Enter selects one without changing the display filter. Verified with `zig build` and `zig build test`.

### 2026-11-12 — Join loader threads when they finish

A finished list or detail thread is joined and dropped on the next request or when events are drained. Quit cancels work that is still running and joins only that work. Verified with `zig build` and `zig build test`.

### 2026-11-12 — Overlap the two detail tshark runs

Choosing an uncached frame starts the PDML and hex tshark processes together. Both use the detail cancel token, so a newer selection drops the in-flight window instead of caching it. The log line is still `frame N loaded in M ms (pdml A ms, hex B ms, parse C ms)`. Verified with `zig build` and `zig build test`.

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
