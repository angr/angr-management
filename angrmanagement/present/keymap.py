"""
Key bindings without a toolkit.

A :class:`Keymap` is a named scope ("global", "table", ...) and a list of :class:`Binding` objects, each a key chord in
Qt's notation (``"Ctrl+Shift+P"``), the name of the action it runs and a description. :class:`Chord` parses that
notation and converts it to Textual's key names and to a ``QKeySequence``.

A terminal reports some chords only when it speaks the kitty keyboard protocol: Ctrl+Shift+letter arrives as
Ctrl+letter, Ctrl+Tab and Ctrl+, arrive as nothing distinct, Ctrl+I is Tab and Ctrl+M is Enter. A binding whose chord
needs the protocol has ``tier`` 2 and names an ``alternative`` chord that any terminal reports;
:meth:`Keymap.for_tier` returns the chords that are bound in a terminal of a given tier, so menus and the palette show
the key that actually works.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

#: The tier of terminals that report every chord (the kitty keyboard protocol).
KITTY_KEYBOARD_TIER = 2
#: What separates the presses of a key sequence, as in Qt: ``"Shift, Shift"``.
SEQUENCE_SEPARATOR = ", "

_MODIFIER_NAMES = {
    "ctrl": "ctrl",
    "control": "ctrl",
    "alt": "alt",
    "option": "alt",
    "shift": "shift",
    "meta": "meta",
    "cmd": "meta",
    "super": "meta",
}

# Qt key names (lower case) and the Textual names of the same keys.
_NAMED_KEYS = {
    "tab": "tab",
    "backtab": "shift+tab",
    "esc": "escape",
    "escape": "escape",
    "return": "enter",
    "enter": "enter",
    "space": "space",
    "backspace": "backspace",
    "del": "delete",
    "delete": "delete",
    "ins": "insert",
    "insert": "insert",
    "home": "home",
    "end": "end",
    "pgup": "pageup",
    "pageup": "pageup",
    "pgdown": "pagedown",
    "pagedown": "pagedown",
    "up": "up",
    "down": "down",
    "left": "left",
    "right": "right",
    "comma": "comma",
}

# Textual's names for characters whose Unicode names it shortens (textual.keys.KEY_NAME_REPLACEMENTS).
_TEXTUAL_CHARACTER_NAMES = {
    "solidus": "slash",
    "reverse_solidus": "backslash",
    "commercial_at": "at",
    "hyphen_minus": "minus",
    "plus_sign": "plus",
    "low_line": "underscore",
}

# Ctrl+letter chords a legacy terminal cannot tell from another key: Ctrl+H is Backspace, Ctrl+I is Tab, Ctrl+J is
# a newline, Ctrl+M is Enter and Ctrl+[ is Escape.
_CTRL_LETTERS_LEGACY_LOSES = frozenset("hijm[")
# Ctrl+punctuation a legacy terminal does report, as an ASCII control byte.
_CTRL_PUNCTUATION_LEGACY_KEEPS = frozenset("\\]^@ ")
# Keys that a legacy terminal reports with Ctrl, Shift or both held, through CSI 1;<mod> sequences.
_LEGACY_MODIFIABLE_KEYS = frozenset(
    {"up", "down", "left", "right", "home", "end", "pageup", "pagedown", "delete", "insert"}
)
# Alt+key arrives as Escape and the key. Textual reads Escape-b and Escape-f as word movement (Ctrl+Left and
# Ctrl+Right), Escape-digit as the macOS Option character of the digit, and Escape-punctuation as the bare key.
_ALT_LETTERS_LEGACY_LOSES = frozenset("bf")


def textual_character_name(character: str) -> str:
    """The name Textual gives the key that types ``character``: ``","`` is ``"comma"``, ``"a"`` is ``"a"``."""
    if character.isalnum():
        return character
    try:
        name = unicodedata.name(character).lower().replace("-", "_").replace(" ", "_")
    except ValueError:
        return character
    return _TEXTUAL_CHARACTER_NAMES.get(name, name)


@dataclass(frozen=True)
class Chord:
    """
    One key with its modifiers, as Qt writes it: ``Chord.parse("Ctrl+Shift+P")``.

    ``key`` is the key's Qt name: a single character in upper case for letters (``"P"``), ``"F4"``, ``"Tab"`` and so
    on. A chord made of modifiers only (such as the Shift of the double-Shift goto palette) has the modifier as its
    key, in lower case.
    """

    key: str
    ctrl: bool = False
    alt: bool = False
    shift: bool = False
    meta: bool = False

    @classmethod
    def parse(cls, text: str) -> Chord:
        """Parse Qt's portable notation. ``"Ctrl++"`` is Ctrl and the plus key."""
        text = text.strip()
        if not text:
            raise ValueError("empty key chord")
        parts = text.split("+")
        if text.endswith("+"):
            # the key itself is "+": "Ctrl++" splits into ["Ctrl", "", ""]
            parts = [*parts[:-2], "+"]
        *mods, key = parts
        flags = {"ctrl": False, "alt": False, "shift": False, "meta": False}
        for mod in mods:
            name = _MODIFIER_NAMES.get(mod.strip().lower())
            if name is None:
                raise ValueError(f"unknown modifier {mod!r} in {text!r}")
            flags[name] = True
        key = key.strip()
        if not key:
            raise ValueError(f"no key in {text!r}")
        if key.lower() in _MODIFIER_NAMES:
            key = _MODIFIER_NAMES[key.lower()]
        elif len(key) == 1:
            key = key.upper()
        else:
            key = key[0].upper() + key[1:]
        return cls(key, **flags)

    @property
    def is_modifier_only(self) -> bool:
        return self.key in ("ctrl", "alt", "shift", "meta")

    def __str__(self) -> str:
        parts = []
        if self.ctrl:
            parts.append("Ctrl")
        if self.alt:
            parts.append("Alt")
        if self.shift:
            parts.append("Shift")
        if self.meta:
            parts.append("Meta")
        parts.append(self.key.capitalize() if self.is_modifier_only else self.key)
        return "+".join(parts)

    def _textual_key(self) -> str:
        key = self.key
        lowered = key.lower()
        if self.is_modifier_only:
            return "left_" + {"ctrl": "control"}.get(key, key)
        if lowered in _NAMED_KEYS:
            return _NAMED_KEYS[lowered]
        if len(key) > 1 and key[0] == "F" and key[1:].isdigit():
            return lowered
        if len(key) == 1:
            if key.isalpha():
                return lowered
            return textual_character_name(key)
        return lowered

    def to_textual(self) -> str:
        """
        The key name Textual reports for this chord: modifiers in alphabetical order and the key, such as
        ``"ctrl+shift+p"``. A shifted letter with no other modifier is the upper-case letter (``"P"``), as Textual
        reports it.
        """
        key = self._textual_key()
        if "+" in key:
            # Backtab is already a chord
            return key
        if self.shift and not (self.ctrl or self.alt or self.meta) and len(key) == 1 and key.isalpha():
            return key.upper()
        mods = [name for name, held in (("alt", self.alt), ("ctrl", self.ctrl), ("meta", self.meta)) if held]
        if self.shift:
            mods.append("shift")
        return "+".join([*sorted(mods), key])

    def legacy_reportable(self) -> bool:
        """Whether a terminal without the kitty keyboard protocol can report this chord as itself."""
        if self.meta or self.is_modifier_only:
            return False
        key = self._textual_key()
        named = len(self.key) > 1
        if self.alt and named and key in ("up", "down", "left", "right"):
            # Alt+arrow arrives as Escape followed by the arrow
            return False
        if named and key == "f3" and (self.shift or self.ctrl):
            # CSI 1;2R and CSI 1;5R read as cursor position reports
            return False
        if self.alt and not named:
            if self.ctrl:
                # Escape and a control byte reads as the control key alone
                return False
            return self.key.isalpha() and self.key.lower() not in _ALT_LETTERS_LEGACY_LOSES
        if self.ctrl:
            if named:
                if key in ("tab", "enter", "escape", "backspace", "space"):
                    # Ctrl+Space arrives as NUL, which Textual names ctrl+@
                    return False
                return key in _LEGACY_MODIFIABLE_KEYS or key.startswith("f")
            if self.shift:
                # Ctrl+Shift+letter sends the same byte as Ctrl+letter
                return False
            if self.key.isalpha():
                return self.key.lower() not in _CTRL_LETTERS_LEGACY_LOSES
            return self.key in _CTRL_PUNCTUATION_LEGACY_KEEPS
        if self.shift and named:
            return key in _LEGACY_MODIFIABLE_KEYS or key.startswith("f") or key == "tab"
        return True

    def to_qkeysequence(self):
        """The chord as a QKeySequence (imports Qt)."""
        from PySide6.QtGui import QKeySequence  # pylint:disable=import-outside-toplevel

        return QKeySequence(str(self))


@dataclass(frozen=True)
class Binding:
    """
    A chord bound to an action.

    :param chord:       The chord in Qt notation; ``"Shift, Shift"`` is a sequence of two presses.
    :param action:      The action's name; each frontend maps names to its own handlers.
    :param description: What the action does, for menus, the palette and help.
    :param tier:        The lowest terminal tier that reports ``chord`` (see :data:`KITTY_KEYBOARD_TIER`).
    :param alternative: The chord bound instead on a terminal below ``tier``; None if there is none.
    """

    chord: str
    action: str
    description: str = ""
    tier: int = 0
    alternative: str | None = None
    args: tuple[Any, ...] = field(default=())

    @property
    def chords(self) -> list[Chord]:
        """The chord, as the presses that make it up."""
        return [Chord.parse(part) for part in self.chord.split(SEQUENCE_SEPARATOR)]

    @property
    def is_sequence(self) -> bool:
        """Whether the chord is several presses, such as ``"Shift, Shift"``."""
        return SEQUENCE_SEPARATOR in self.chord

    def effective(self, tier: int) -> Binding | None:
        """This binding as it applies on a terminal of ``tier``: itself, its alternative, or None."""
        if tier >= self.tier:
            return self
        if self.alternative is None:
            return None
        return replace(self, chord=self.alternative, tier=0, alternative=None)

    def textual_key(self) -> str | None:
        """The chord as a Textual key name; None for a sequence of presses, which Textual cannot bind."""
        if self.is_sequence:
            return None
        return Chord.parse(self.chord).to_textual()


def tier_of(caps: Any) -> int:
    """The tier of ``caps``, which is a tier number or an object with a ``tier`` attribute."""
    if isinstance(caps, int):
        return caps
    return int(getattr(caps, "tier", 0))


class Keymap:
    """The bindings of one scope, such as the whole application ("global") or a table."""

    def __init__(self, scope: str, bindings: Iterable[Binding] = ()) -> None:
        self.scope = scope
        self.bindings: list[Binding] = list(bindings)

    def __repr__(self) -> str:
        return f"<Keymap {self.scope} with {len(self.bindings)} bindings>"

    def __iter__(self):
        return iter(self.bindings)

    def __len__(self) -> int:
        return len(self.bindings)

    def add(self, binding: Binding) -> None:
        self.bindings.append(binding)

    def extend(self, bindings: Iterable[Binding]) -> None:
        self.bindings.extend(bindings)

    def for_tier(self, caps: Any) -> list[Binding]:
        """The bindings in effect on a terminal of the tier of ``caps``, with alternatives substituted."""
        tier = tier_of(caps)
        effective = (binding.effective(tier) for binding in self.bindings)
        return [binding for binding in effective if binding is not None]

    def find(self, action: str, args: tuple[Any, ...] = ()) -> Binding | None:
        for binding in self.bindings:
            if binding.action == action and binding.args == args:
                return binding
        return None

    def chord_for(self, action: str, caps: Any = KITTY_KEYBOARD_TIER, args: tuple[Any, ...] = ()) -> str | None:
        """The chord, in Qt notation, that runs ``action`` on a terminal of the tier of ``caps``; None if none does."""
        binding = self.find(action, args)
        if binding is None:
            return None
        effective = binding.effective(tier_of(caps))
        return effective.chord if effective is not None else None

    def effective_shortcut(self, shortcut: str | None, caps: Any) -> str | None:
        """
        The chord that stands in for the Qt shortcut ``shortcut`` on a terminal of the tier of ``caps``: the
        shortcut itself if the terminal reports it, else the alternative of the binding with that chord.
        """
        if not shortcut:
            return None
        tier = tier_of(caps)
        wanted = Chord.parse(shortcut)
        for binding in self.bindings:
            if not binding.is_sequence and Chord.parse(binding.chord) == wanted:
                effective = binding.effective(tier)
                return effective.chord if effective is not None else None
        return shortcut if tier >= KITTY_KEYBOARD_TIER or wanted.legacy_reportable() else None


def _kitty(chord: str, action: str, description: str, alternative: str | None, *args: Any) -> Binding:
    return Binding(chord, action, description, KITTY_KEYBOARD_TIER, alternative, args)


def _any(chord: str, action: str, description: str, *args: Any) -> Binding:
    return Binding(chord, action, description, 0, None, args)


def global_keymap() -> Keymap:
    """The application-wide bindings: the main window's shortcuts and the menu bar's."""
    bindings = [
        _any("Ctrl+O", "open_file", "Load a new binary"),
        _kitty("Ctrl+Shift+T", "open_trace_file", "Load a trace file", "Alt+T"),
        _kitty("Ctrl+Alt+F", "load_signatures", "Load a FLIRT signature file", "Alt+L"),
        _any("Ctrl+W", "close_project", "Close project"),
        _any("Ctrl+L", "load_database", "Load angr database"),
        _any("Ctrl+S", "save_database", "Save angr database"),
        _kitty("Ctrl+Shift+S", "save_database_as", "Save angr database as", "Alt+S"),
        _kitty("Ctrl+,", "preferences", "Preferences", "Alt+O"),
        _kitty("Ctrl+Shift+P", "command_palette", "Command palette", "Ctrl+P"),
        _kitty("Shift, Shift", "goto_palette", "Goto anything", "Ctrl+G"),
        _kitty("Ctrl+Tab", "next_tab", "Next tab", "Ctrl+PgDown"),
        _kitty("Ctrl+Shift+Tab", "previous_tab", "Previous tab", "Ctrl+PgUp"),
        _any("Ctrl+N", "new_graph_disassembly", "New graph disassembly view"),
        _kitty("Ctrl+Shift+F", "show_view", "Search", "Alt+E", "search"),
        _any("F4", "run_analysis", "Run analysis"),
        _any("F5", "decompile", "Decompile"),
        _any("Ctrl+B", "proximity", "View in proximity browser"),
        _kitty("Ctrl+I", "llm_refine_all", "LLM: refine all", "Alt+R"),
        _any("Alt+H", "documentation", "Documentation"),
        _kitty("Ctrl+Shift+I", "interrupt_job", "Interrupt the current job", "Ctrl+\\"),
        _any("F2", "toggle_exec_breakpoint", "Toggle execution breakpoint"),
        _any("F7", "step_forward", "Step forward"),
        _any("F9", "continue_forward", "Continue"),
        _kitty("Ctrl+M", "toggle_bookmark", "Toggle bookmark", "Alt+K"),
        _kitty("Ctrl+Shift+M", "next_bookmark", "Go to next bookmark", "Alt+M"),
        _any("F10", "open_menu_bar", "Open the menu bar"),
    ]
    # a legacy terminal cannot report Alt+digit to Textual; Ctrl+PgUp and Ctrl+PgDown cycle the tabs there
    for idx in range(1, 10):
        bindings.append(_kitty(f"Alt+{idx}", "raise_view_by_index", f"Raise view {idx}", None, idx - 1))
    bindings.append(_kitty("Alt+0", "raise_view_by_index", "Raise view 10", None, 9))
    return Keymap("global", bindings)


def table_keymap() -> Keymap:
    """Bindings of the fast tables (functions, comments) and the other tables."""
    return Keymap(
        "table",
        [
            _any("Up", "cursor_up", "Previous row"),
            _any("Down", "cursor_down", "Next row"),
            _any("PgUp", "page_up", "Previous page"),
            _any("PgDown", "page_down", "Next page"),
            _any("Home", "scroll_home", "First row"),
            _any("End", "scroll_end", "Last row"),
            _any("Shift+Up", "extend_up", "Extend the selection up"),
            _any("Shift+Down", "extend_down", "Extend the selection down"),
            _any("Return", "activate", "Open the row"),
            _any("Esc", "clear_filter", "Clear the filter"),
            _any("Shift+F10", "context_menu", "Context menu"),
        ],
    )


def strings_keymap() -> Keymap:
    return Keymap("strings", [_any("X", "xrefs", "Cross-references to the string")])


def log_keymap() -> Keymap:
    return Keymap("log", [_any("Ctrl+C", "copy_selected_messages", "Copy the selected messages")])


def search_keymap() -> Keymap:
    return Keymap("search", [_any("Esc", "cancel_search", "Cancel the search")])
