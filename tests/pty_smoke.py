#!/usr/bin/env python3
"""Linux/macOS PTY smoke test for rendering and clean Ctrl-C teardown."""

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


def read_available(fd: int, output: bytearray, timeout: float = 0.05) -> bool:
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
    return True


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    binary = os.path.join(root, "zig-out", "bin", "zigshark")
    fixture = os.path.join(root, "tests", "fixtures", "1.pcap")

    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.chdir(root)
        os.execv(binary, [binary, fixture])

    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    output = bytearray()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and b"Application Data" not in output:
        if not read_available(fd, output):
            break

    if b"Application Data" not in output:
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        sys.stderr.write("zigshark did not render the fixture within 10 seconds\n")
        return 1

    # Modal command input must receive every character without global bindings
    # intercepting letters such as "m".
    os.write(fd, b"\x06")  # Ctrl-F
    deadline = time.monotonic() + 0.15
    while time.monotonic() < deadline:
        read_available(fd, output)
    os.write(fd, b"SSDP\r")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and b"Frame 7:" not in output:
        if not read_available(fd, output):
            break
    if b"Frame 7:" not in output:
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        sys.stderr.write("packet-list search did not navigate to frame 7\n")
        return 1

    os.write(fd, b":")
    deadline = time.monotonic() + 0.15
    while time.monotonic() < deadline:
        read_available(fd, output)
    os.write(fd, b"capinfo\r")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and b"Number of packets:" not in output:
        if not read_available(fd, output):
            break
    if b"Number of packets:" not in output:
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        sys.stderr.write(":capinfo did not open its analysis view\n")
        return 1
    os.write(fd, b"\x1b")
    deadline = time.monotonic() + 0.25
    while time.monotonic() < deadline:
        read_available(fd, output)

    # Copy mode must consume Ctrl-C rather than terminating the application.
    os.write(fd, b"c")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and b"COPY MODE" not in output:
        if not read_available(fd, output):
            break
    if b"COPY MODE" not in output:
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        sys.stderr.write("zigshark did not enter copy mode\n")
        return 1
    os.write(fd, b"\x03")
    deadline = time.monotonic() + 0.3
    while time.monotonic() < deadline:
        read_available(fd, output)
    waited_pid, _ = os.waitpid(pid, os.WNOHANG)
    if waited_pid:
        sys.stderr.write("Ctrl-C terminated zigshark while copy mode was active\n")
        return 1

    # Outside copy mode Ctrl-C exits and must restore the terminal.
    os.write(fd, b"\x03")
    status = None
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        read_available(fd, output)
        waited_pid, waited_status = os.waitpid(pid, os.WNOHANG)
        if waited_pid:
            status = waited_status
            break

    if status is None:
        os.kill(pid, signal.SIGTERM)
        _, status = os.waitpid(pid, 0)
        sys.stderr.write("zigshark did not exit after Ctrl-C\n")
        return 1

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
        return 1

    print("PTY smoke: rendered fixture and restored terminal cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
