#!/usr/bin/env python3
"""Linux PTY smoke test for rendering, search, the tree, hex, and a ZZ quit.

vaxis paints by diff. A later frame often rewrites a single changed cell, so the
PTY byte stream does not contain the text a person would read. Assertions about
visible text go through a small terminal, not a search of the raw bytes.
"""

from __future__ import annotations

import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time
import unicodedata

ROWS = 40
COLS = 120


class Terminal:
    """Enough of a VT100 to fold vaxis's cell diffs back into a screen."""

    def __init__(self, rows: int = ROWS, cols: int = COLS) -> None:
        self.rows = rows
        self.cols = cols
        self.grid = [[" "] * cols for _ in range(rows)]
        self.cy = 0
        self.cx = 0
        self.pending = bytearray()

    def feed(self, data: bytes) -> None:
        self.pending.extend(data)
        self._drain()

    def text(self) -> str:
        return "\n".join("".join(row).rstrip() for row in self.grid)

    def contains(self, needle: str) -> bool:
        return needle in self.text()

    def _drain(self) -> None:
        data = self.pending
        index = 0
        while index < len(data):
            byte = data[index]
            if byte == 0x1B:
                consumed = self._escape(data, index)
                if consumed is None:
                    break
                index += consumed
                continue
            if byte == 0x0D:
                self.cx = 0
                index += 1
                continue
            if byte == 0x0A:
                self.cy = min(self.rows - 1, self.cy + 1)
                index += 1
                continue
            if byte == 0x08:
                self.cx = max(0, self.cx - 1)
                index += 1
                continue
            if byte < 0x20 or byte == 0x7F:
                index += 1
                continue
            needed = _utf8_length(byte)
            if index + needed > len(data):
                break
            try:
                text = data[index : index + needed].decode("utf-8")
            except UnicodeDecodeError:
                index += 1
                continue
            self._put(text)
            index += needed
        del data[:index]

    def _put(self, text: str) -> None:
        width = 2 if unicodedata.east_asian_width(text) in ("F", "W") else 1
        if self.cx >= self.cols:
            self.cx = 0
            self.cy = min(self.rows - 1, self.cy + 1)
        if self.cy < self.rows and self.cx < self.cols:
            self.grid[self.cy][self.cx] = text
            if width == 2 and self.cx + 1 < self.cols:
                self.grid[self.cy][self.cx + 1] = ""
            self.cx += width

    def _escape(self, data: bytearray, start: int) -> int | None:
        if start + 1 >= len(data):
            return None
        kind = data[start + 1]
        if kind == ord("["):
            end = start + 2
            while end < len(data) and data[end] < 0x40:
                end += 1
            if end >= len(data):
                return None
            self._csi(data[start + 2 : end], data[end])
            return end + 1 - start
        if kind == ord("]"):
            end = start + 2
            while end < len(data):
                if data[end] == 0x07:
                    return end + 1 - start
                if data[end] == 0x1B and end + 1 < len(data) and data[end + 1] == ord("\\"):
                    return end + 2 - start
                if data[end] == 0x1B and end + 1 >= len(data):
                    return None
                end += 1
            return None
        if kind in (ord("P"), ord("X"), ord("^"), ord("_")):
            end = start + 2
            while end < len(data):
                if data[end] == 0x1B and end + 1 < len(data) and data[end + 1] == ord("\\"):
                    return end + 2 - start
                if data[end] == 0x1B and end + 1 >= len(data):
                    return None
                end += 1
            return None
        return 2

    def _csi(self, params: bytes, final: int) -> None:
        if params.startswith(b"?"):
            return
        numbers = _csi_numbers(params)

        def number(index: int, default: int = 1) -> int:
            if index < len(numbers) and numbers[index] > 0:
                return numbers[index]
            return default

        if final in (ord("H"), ord("f")):
            self.cy = max(0, min(self.rows - 1, number(0) - 1))
            self.cx = max(0, min(self.cols - 1, number(1) - 1))
        elif final == ord("A"):
            self.cy = max(0, self.cy - number(0))
        elif final == ord("B"):
            self.cy = min(self.rows - 1, self.cy + number(0))
        elif final == ord("C"):
            self.cx = min(self.cols - 1, self.cx + number(0))
        elif final == ord("D"):
            self.cx = max(0, self.cx - number(0))
        elif final == ord("G"):
            self.cx = max(0, min(self.cols - 1, number(0) - 1))
        elif final == ord("d"):
            self.cy = max(0, min(self.rows - 1, number(0) - 1))
        elif final == ord("J") and (not numbers or numbers[0] == 2):
            self.grid = [[" "] * self.cols for _ in range(self.rows)]
            self.cy = 0
            self.cx = 0
        elif final == ord("K"):
            mode = numbers[0] if numbers else 0
            if 0 <= self.cy < self.rows:
                if mode == 0:
                    for col in range(self.cx, self.cols):
                        self.grid[self.cy][col] = " "
                elif mode == 1:
                    for col in range(0, min(self.cx + 1, self.cols)):
                        self.grid[self.cy][col] = " "
                elif mode == 2:
                    self.grid[self.cy] = [" "] * self.cols


def _utf8_length(byte: int) -> int:
    if byte < 0x80:
        return 1
    if byte < 0xE0:
        return 2
    if byte < 0xF0:
        return 3
    return 4


def _csi_numbers(params: bytes) -> list[int]:
    if not params:
        return []
    numbers: list[int] = []
    for part in params.split(b";"):
        if part.isdigit():
            numbers.append(int(part))
        else:
            numbers.append(0)
    return numbers


def _check_terminal() -> None:
    screen = Terminal(2, 20)
    screen.feed(b"Frame 1:")
    screen.feed(b"\x1b[1;7H7")
    if "Frame 7:" not in screen.text():
        raise RuntimeError("terminal diff fixture failed")
    screen.feed(b"\x1b[2;1H\x1b[1mNumber of packets:\x1b[m")
    if "Number of packets:" not in screen.text():
        raise RuntimeError("terminal SGR fixture failed")


def read_available(fd: int, output: bytearray, screen: Terminal, timeout: float = 0.05) -> bool:
    readable, _, _ = select.select([fd], [], [], timeout)
    if fd not in readable:
        return True
    try:
        chunk = os.read(fd, 65536)
    except OSError:
        return False
    if not chunk:
        return False
    output.extend(chunk)
    screen.feed(chunk)
    return True


def wait_until(fd: int, output: bytearray, screen: Terminal, needle: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not screen.contains(needle):
        if not read_available(fd, output, screen):
            break
    return screen.contains(needle)


def drain(fd: int, output: bytearray, screen: Terminal, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        read_available(fd, output, screen)


def fail(message: str, screen: Terminal) -> int:
    sys.stderr.write(message + "\n")
    sys.stderr.write(screen.text() + "\n")
    return 1


def main() -> int:
    _check_terminal()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    binary = os.path.join(root, "zig-out", "bin", "zigshark")
    fixture = os.path.join(root, "tests", "fixtures", "1.pcap")

    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.chdir(root)
        os.execv(binary, [binary, fixture])

    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    output = bytearray()
    screen = Terminal()

    if not wait_until(fd, output, screen, "Application Data", 10):
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        return fail("zigshark did not render the fixture within 10 seconds", screen)

    # Modal command input must receive every character without global bindings
    # intercepting letters such as "m".
    os.write(fd, b"\x06")  # Ctrl-F
    drain(fd, output, screen, 0.3)
    os.write(fd, b"SSDP\r")
    if not wait_until(fd, output, screen, "Frame 7:", 5):
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        return fail("packet-list search did not navigate to frame 7", screen)

    os.write(fd, b":")
    drain(fd, output, screen, 0.3)
    os.write(fd, b"capinfo\r")
    if not wait_until(fd, output, screen, "Number of packets:", 5):
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        return fail(":capinfo did not open its analysis view", screen)
    os.write(fd, b"\x1b")
    drain(fd, output, screen, 0.4)

    # Copy mode must consume Ctrl-C rather than terminating the application.
    os.write(fd, b"c")
    if not wait_until(fd, output, screen, "COPY MODE", 2):
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        return fail("zigshark did not enter copy mode", screen)
    os.write(fd, b"\x03")
    drain(fd, output, screen, 0.3)
    waited_pid, _ = os.waitpid(pid, os.WNOHANG)
    if waited_pid:
        return fail("Ctrl-C terminated zigshark while copy mode was active", screen)

    # Focus the protocol tree and expand the selected frame node.
    os.write(fd, b"\t")
    if not wait_until(fd, output, screen, "= field filter", 3):
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        return fail("Tab did not focus the protocol tree", screen)
    if screen.contains("Encapsulation type"):
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        return fail("the frame node was already expanded", screen)
    os.write(fd, b"l")
    if not wait_until(fd, output, screen, "Encapsulation type", 3):
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        return fail("the protocol tree did not expand a node", screen)

    # Focus the hex pane and move the cursor so the tree follows that byte.
    os.write(fd, b"\t")
    if not wait_until(fd, output, screen, "hjkl byte", 3):
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        return fail("Tab did not focus the hex pane", screen)
    os.write(fd, b"l")
    if not wait_until(fd, output, screen, "LG bit", 3):
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        return fail("the hex cursor did not move onto a new field", screen)

    # ZZ quits immediately and must restore the terminal.
    os.write(fd, b"ZZ")
    status = None
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        read_available(fd, output, screen)
        waited_pid, waited_status = os.waitpid(pid, os.WNOHANG)
        if waited_pid:
            status = waited_status
            break

    if status is None:
        os.kill(pid, signal.SIGTERM)
        _, status = os.waitpid(pid, 0)
        return fail("zigshark did not exit after ZZ", screen)

    exit_code = os.waitstatus_to_exitcode(status)
    forbidden = (
        b"panic",
        b"General protection",
        b"error(SafeAllocator)",
        b"leaked [",
        b"Segmentation",
    )
    failures = [token.decode("ascii") for token in forbidden if token in output]
    restored_alt_screen = b"\x1b[?1049l" in output
    if exit_code != 0 or failures or not restored_alt_screen:
        sys.stderr.write(
            f"unclean shutdown: exit={exit_code}, diagnostics={failures}, "
            f"restored_alt_screen={restored_alt_screen}\n"
        )
        sys.stderr.write(screen.text() + "\n")
        return 1

    print("PTY smoke: rendered the tree and hex pane, then quit with ZZ")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
