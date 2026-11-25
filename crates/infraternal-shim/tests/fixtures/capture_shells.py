#!/usr/bin/env python3
"""Record real interactive shell sessions, resizes included, for the exact
snapshot corpus (#521, #583).

Each session runs one shell on its own PTY with a scratch HOME and no startup
files, types a fixed script one key at a time (wrapped commands, scrolling
output, a continuation prompt, a clear, resizes in the middle of an edit), and
writes `shell-<name>.events`. The file is a list of records, in the order the
shim would see them:

    O <length>\\n<length raw PTY bytes>   output read from the PTY
    R <cols> <rows>\\n                    the PTY was resized here

`tests/unit/shell_snapshot_corpus.rs` replays these through the shim's engine.
Run it again only when the corpus should change; the shells' output is not
byte-for-byte reproducible (timing decides how reads split), but every
recording is a valid session.

Usage: capture_shells.py [shell-name ...]  (default: all; needs bash, zsh, fish)
"""
import fcntl
import os
import pathlib
import pty
import select
import shutil
import signal
import struct
import sys
import tempfile
import termios
import time

ROOT = pathlib.Path(__file__).parent
COLS, ROWS = 40, 12

# What every session types. ("k", bytes) types the bytes one key at a time;
# ("r", cols, rows) resizes the PTY, which sends the shell SIGWINCH.
SCRIPT = [
    ("k", b"echo " + b"wrapped-" * 9 + b"end\r"),
    ("k", b"seq 1 120\r"),
    ("k", b"echo resize-" + b"0123456789" * 4),
    ("r", 30, 12),
    ("k", b"-narrow"),
    ("r", 70, 14),
    ("k", b"-wide\r"),
    ("k", b"for i in 1 2; do\r"),
    ("k", b"echo loop-$i\r"),
    ("k", b"done\r"),
    ("k", b"printf '%0300d\\n' 0\r"),
    ("r", 52, 14),
    ("k", b"\x0c"),
    ("k", b"echo after-clear\r"),
    ("k", b"echo left-at-the-prompt-" + b"abcdefghij" * 5),
    ("r", 44, 13),
]

# name -> (argv, extra environment). Prompts are fixed so recordings do not
# carry the recording host's user or host name.
SHELLS = {
    "bash": (["bash", "--norc", "--noprofile", "-i"], {"PS1": "user@host:~/dir$ "}),
    "bash-multiline": (
        ["bash", "--norc", "--noprofile", "-i"],
        {"PS1": "\\[\\e[1;32m\\]user@host\\[\\e[0m\\] ~/a/long/working/directory\\n\\$ "},
    ),
    "zsh": (["zsh", "-f", "-i"], {"PS1": "%F{blue}user@host%f %~ %# ", "RPS1": "[%?]"}),
    # fish marks its prompt with OSC 133 itself; the corpus keeps that.
    "fish": (
        ["fish", "--no-config", "-i", "-C", "function fish_prompt; echo -n 'user@host ~> '; end"],
        {},
    ),
}


# Primary device attributes (DA1). fish asks for them after its other
# terminal queries and waits for the answer before it draws a prompt; the
# shim's engine answers DA1 in production (D307). Other queries stay
# unanswered, as a terminal without those features would leave them.
DA1_QUERIES = (b"\x1b[c", b"\x1b[0c")
DA1_REPLY = b"\x1b[?62;22c"


def drain(master, out, seconds):
    """Read everything the shell writes for `seconds`, as separate records,
    answering DA1 the way the shim does."""
    until = time.monotonic() + seconds
    while (left := until - time.monotonic()) > 0:
        if select.select([master], [], [], left)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return
            if not chunk:
                return
            out.append(b"O %d\n" % len(chunk) + chunk)
            if any(query in chunk for query in DA1_QUERIES):
                os.write(master, DA1_REPLY)


def record(name):
    argv, extra = SHELLS[name]
    if shutil.which(argv[0]) is None:
        sys.exit(f"{argv[0]} is not on PATH")
    home = tempfile.mkdtemp(prefix="corpus-home-")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": home,
        "XDG_CONFIG_HOME": f"{home}/.config",
        "XDG_DATA_HOME": f"{home}/.local/share",
        "TERM": "xterm-256color",
        "LANG": "C.UTF-8",
        "HISTFILE": "/dev/null",
        **extra,
    }
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    pid = os.fork()
    if pid == 0:
        os.close(master)
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        for fd in range(3):
            os.dup2(slave, fd)
        os.close(slave)
        os.chdir(home)
        os.execvpe(argv[0], argv, env)
    os.close(slave)
    out = [b"R %d %d\n" % (COLS, ROWS)]
    drain(master, out, 1.5)
    for step in SCRIPT:
        if step[0] == "r":
            _, cols, rows = step
            drain(master, out, 0.3)
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            out.append(b"R %d %d\n" % (cols, rows))
            drain(master, out, 0.5)
            continue
        for key in step[1]:
            os.write(master, bytes([key]))
            drain(master, out, 0.02)
        drain(master, out, 0.4)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    os.close(master)
    shutil.rmtree(home)
    (ROOT / f"shell-{name}.events").write_bytes(b"".join(out))


for shell in sys.argv[1:] or SHELLS:
    record(shell)
