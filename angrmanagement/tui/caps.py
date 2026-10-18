"""
What the terminal can do.

:func:`detect` fills a :class:`TerminalCaps` from the environment and, on a real terminal, from the replies to a few
queries written before the Textual app starts (afterwards Textual's own input thread would read the replies as keys):
XTVERSION for the terminal's name, ``CSI ? u`` for the kitty keyboard protocol, a kitty graphics query, and DA1, which
also says whether the terminal speaks Sixel. ``AM_TUI_TIER`` forces the tier.

The tier decides which key bindings are used (see angrmanagement.present.keymap) and what the status bar advertises:
0 is any terminal; 1 adds true colour; 2 adds the kitty keyboard protocol; 3 adds graphics.
"""

from __future__ import annotations

import contextlib
import os
import re
import select
import sys
from dataclasses import dataclass, field

TIER_ENV = "AM_TUI_TIER"

_KITTY_KEYBOARD_REPLY = re.compile(rb"\x1b\[\?(\d+)u")
_XTVERSION_REPLY = re.compile(rb"\x1bP>\|([^\x1b]*)\x1b\\")
_GRAPHICS_REPLY = re.compile(rb"\x1b_Gi=31;([^\x1b]*)\x1b\\")
_DA1_REPLY = re.compile(rb"\x1b\[\?([\d;]*)c")

# terminals known to speak the kitty keyboard protocol, by TERM_PROGRAM or XTVERSION name
_KITTY_KEYBOARD_TERMINALS = ("kitty", "foot", "wezterm", "ghostty", "alacritty", "rio")


@dataclass
class TerminalCaps:
    """The features of the terminal the app runs in."""

    term: str = ""
    term_program: str = ""
    version: str = ""
    truecolor: bool = False
    kitty_keyboard: bool = False
    kitty_graphics: bool = False
    sixel: bool = False
    kitty: bool = False
    forced_tier: int | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def tier(self) -> int:
        if self.forced_tier is not None:
            return self.forced_tier
        if self.kitty_keyboard:
            return 3 if self.graphics else 2
        return 1 if self.truecolor else 0

    @property
    def graphics(self) -> bool:
        return self.kitty_graphics or self.sixel

    def summary(self) -> str:
        """A few words for the status bar."""
        parts = [f"tier {self.tier}"]
        if self.kitty_keyboard or self.tier >= 2:
            parts.append("kitty keys")
        if self.graphics:
            parts.append("graphics")
        return ", ".join(parts)


#: What each tier adds, as Help > Terminal capabilities lists it.
TIER_FEATURES = (
    (0, "Any terminal: the key chords it reports, with an alternative for each Qt chord it cannot; braille pictures"),
    (1, "True colour, angr:// links (OSC 8) on addresses, copying to the system clipboard (OSC 52)"),
    (2, "The kitty keyboard protocol: every Qt chord, as the Qt window binds it"),
    (3, "Graphics (kitty or Sixel): pictures for the logo, the minimap, the feature map, the trace map and exports"),
)


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def capability_rows(caps: TerminalCaps, env: dict[str, str] | None = None) -> list[tuple[str, str]]:
    """``(feature, what was detected)`` for each thing :func:`detect` looks for, then the tier and its source."""
    env = dict(os.environ) if env is None else env
    forced = env.get(TIER_ENV)
    source = "detected"
    if caps.forced_tier is not None:
        source = f"forced by {TIER_ENV}={forced}" if forced else "forced"
    return [
        ("TERM", caps.term or "(unset)"),
        ("TERM_PROGRAM", caps.term_program or "(unset)"),
        ("Terminal version (XTVERSION)", caps.version or "(no reply)"),
        ("True colour", yes_no(caps.truecolor)),
        ("Kitty keyboard protocol", yes_no(caps.kitty_keyboard)),
        ("Kitty graphics protocol", yes_no(caps.kitty_graphics)),
        ("Sixel graphics", yes_no(caps.sixel)),
        ("Kitty (remote control, notifications)", yes_no(caps.kitty)),
        ("Tier", f"{caps.tier} ({source})"),
        *(("Note", note) for note in caps.notes),
    ]


def osc99(title: str, body: str, ident: str = "am") -> str:
    """kitty's desktop notification (OSC 99): ``title``, then ``body``, as one notification ``ident``."""

    def clean(text: str) -> str:
        # the payload runs to the string terminator: no escapes or control characters in it
        return "".join(char for char in text if char >= " " and char != "\x7f")

    return f"\x1b]99;i={ident}:d=0;{clean(title)}\x1b\\\x1b]99;i={ident}:d=1:p=body;{clean(body)}\x1b\\"


def caps_from_environment(env: dict[str, str] | None = None) -> TerminalCaps:
    """What the environment alone says about the terminal."""
    env = dict(os.environ) if env is None else env
    caps = TerminalCaps(term=env.get("TERM", ""), term_program=env.get("TERM_PROGRAM", ""))
    caps.truecolor = env.get("COLORTERM", "").lower() in ("truecolor", "24bit")
    caps.kitty = "KITTY_WINDOW_ID" in env or caps.term == "xterm-kitty"
    if caps.kitty:
        caps.kitty_keyboard = True
        caps.kitty_graphics = True
        caps.truecolor = True
    program = caps.term_program.lower()
    if any(name in program for name in _KITTY_KEYBOARD_TERMINALS):
        caps.kitty_keyboard = True
    forced = env.get(TIER_ENV)
    if forced:
        with contextlib.suppress(ValueError):
            caps.forced_tier = max(0, min(3, int(forced)))
    return caps


def parse_replies(caps: TerminalCaps, data: bytes) -> TerminalCaps:
    """Update ``caps`` from the bytes a terminal sent back to :data:`QUERIES`."""
    match = _XTVERSION_REPLY.search(data)
    if match:
        caps.version = match.group(1).decode("utf-8", "replace")
        if any(name in caps.version.lower() for name in _KITTY_KEYBOARD_TERMINALS):
            caps.notes.append(f"terminal: {caps.version}")
    if _KITTY_KEYBOARD_REPLY.search(data):
        caps.kitty_keyboard = True
    match = _GRAPHICS_REPLY.search(data)
    if match and match.group(1).startswith(b"OK"):
        caps.kitty_graphics = True
    match = _DA1_REPLY.search(data)
    if match and b"4" in match.group(1).split(b";"):
        caps.sixel = True
    return caps


#: The queries, in order; DA1 goes last because every terminal answers it, so its reply ends the wait.
QUERIES = b"\x1b[>0q" + b"\x1b[?u" + b"\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\" + b"\x1b[c"


def query_terminal(timeout: float = 0.3) -> bytes:
    """Write :data:`QUERIES` to the controlling terminal and read what comes back until DA1 answers or time runs out."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return b""
    try:
        import termios  # pylint:disable=import-outside-toplevel
        import tty  # pylint:disable=import-outside-toplevel
    except ImportError:
        return b""
    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except termios.error:
        return b""
    data = b""
    try:
        tty.setraw(fd)
        os.write(sys.stdout.fileno(), QUERIES)
        while True:
            ready, _, _ = select.select([fd], [], [], timeout)
            if not ready:
                break
            data += os.read(fd, 1024)
            if _DA1_REPLY.search(data):
                break
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return data


def detect(probe: bool = True) -> TerminalCaps:
    """The terminal's features: the environment, then the terminal's own answers when ``probe`` and it is a tty."""
    caps = caps_from_environment()
    if probe:
        parse_replies(caps, query_terminal())
    return caps
