"""
The decompilation options sheet without a toolkit.

The pseudocode view lets the user change the decompiler's options, its optimization passes and its peephole
optimizations, starting from a preset. :class:`DecompilationOptionsSheet` holds those choices as a plain dict from
each option, pass or peephole optimization to its value, and answers what a decompilation job is given
(``option_and_values``, ``selected_passes``, ``selected_peephole_opts``). The functions at the top are where the
choices come from; the Qt options widget uses them too.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angr.analyses.decompiler import DECOMPILATION_PRESETS
from angr.analyses.decompiler.decompilation_options import options as dec_options
from angr.analyses.decompiler.optimization_passes import get_optimization_passes
from angr.analyses.decompiler.peephole_optimizations import EXPR_OPTS, MULTI_STMT_OPTS, STMT_OPTS

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from angr.analyses.decompiler.decompilation_options import DecompilationOption

    from angrmanagement.data.instance import Instance

#: The group names of the passes and the peephole optimizations in the sheet.
PASSES_GROUP = "Optimization Passes"
PEEPHOLE_GROUP = "Peephole Optimizations"


def preset_names() -> list[str]:
    """The presets the user picks from: every named preset but the "default" alias, sorted."""
    return sorted(n for n in DECOMPILATION_PRESETS if n != "default")


def default_preset_name() -> str:
    """The name of the preset the "default" alias stands for."""
    return next(n for n in preset_names() if DECOMPILATION_PRESETS[n] is DECOMPILATION_PRESETS["default"])


def default_options() -> list[DecompilationOption]:
    """Every decompilation option."""
    return dec_options


def _has_project(instance: Instance | None) -> bool:
    return instance is not None and not instance.project.am_none


def all_passes(instance: Instance | None, plugin_passes: Iterable[tuple[Any, bool]]) -> list:
    """Every optimization pass for the project's architecture and OS, then the plugins' passes."""
    if not _has_project(instance):
        return []
    assert instance is not None
    project = instance.project
    return get_optimization_passes(project.arch, project.simos.name) + [x for x, _ in plugin_passes]


def default_passes(instance: Instance | None, plugin_passes: Iterable[tuple[Any, bool]], preset: str) -> list:
    """The passes ``preset`` turns on for the project, then the plugins' passes that are on by default."""
    if not _has_project(instance):
        return []
    assert instance is not None
    project = instance.project
    return DECOMPILATION_PRESETS[preset].get_optimization_passes(project.arch, project.simos.name) + [
        x for x, enabled in plugin_passes if enabled
    ]


def all_peephole_opts() -> list:
    """Every peephole optimization."""
    return MULTI_STMT_OPTS + STMT_OPTS + EXPR_OPTS


def default_peephole_opts() -> list:
    """The peephole optimizations that are on by default: all of them."""
    return MULTI_STMT_OPTS + STMT_OPTS + EXPR_OPTS


def value_kind(option: Any) -> str:
    """How the sheet edits an option: "choice", "bool", "float", "int" or "text" (shown, not editable)."""
    if getattr(option, "candidate_values", None) is not None:
        return "choice"
    value_type = getattr(option, "value_type", bool)
    if issubclass(value_type, bool):
        return "bool"
    if issubclass(value_type, float):
        return "float"
    if issubclass(value_type, int):
        return "int"
    return "text"


class DecompilationOptionsSheet:
    """
    The options, passes and peephole optimizations a pseudocode view decompiles with.

    :param instance:        The instance whose project picks the passes.
    :param plugin_passes:   Called for the plugins' optimization passes, as ``(pass, enabled by default)`` pairs.
    """

    def __init__(self, instance: Instance | None, plugin_passes: Callable[[], Iterable[tuple[Any, bool]]]) -> None:
        self.instance = instance
        self._plugin_passes = plugin_passes
        self.preset = default_preset_name()
        self.options: list = []
        self.passes: list = []
        self.peephole_opts: list = []
        #: option, pass or peephole optimization -> its value (a pass or an optimization is on or off)
        self.values: dict[Any, Any] = {}
        #: whether a change asks for a new decompilation, not just new text
        self.dirty = True
        self.reload(force=True)

    def reload(self, force: bool = False) -> None:
        """Read the options and passes again; with ``force``, their values go back to the preset's."""
        if force or not self.options:
            self.options = sorted(default_options(), key=lambda x: x.NAME)
        if force or not self.passes:
            self.passes = all_passes(self.instance, self._plugin_passes())
        if force or not self.peephole_opts:
            self.peephole_opts = all_peephole_opts()
        old = self.values
        values: dict[Any, Any] = {}
        for option in self.options:
            values[option] = option.default_value if force else old.get(option, option.default_value)
        enabled_passes = set(default_passes(self.instance, self._plugin_passes(), self.preset))
        for pass_ in self.passes:
            values[pass_] = pass_ in enabled_passes if force else bool(old.get(pass_, False))
        default_peephole = default_peephole_opts()
        for opt in self.peephole_opts:
            values[opt] = opt in default_peephole if force else bool(old.get(opt, False))
        self.values = values
        self.dirty = True

    def set_preset(self, name: str) -> None:
        """Start again from the preset ``name``."""
        if name in DECOMPILATION_PRESETS:
            self.preset = name
            self.reload(force=True)

    def set_value(self, item: Any, value: Any) -> None:
        """Change an option's value, or turn a pass or a peephole optimization on or off."""
        if item not in self.values:
            raise KeyError(item)
        self.values[item] = value
        if getattr(item, "clears_cache", True):
            self.dirty = True

    def groups(self) -> list[tuple[str, list[Any]]]:
        """The sheet's groups in order: one per option category, then the passes, then the peephole optimizations."""
        categories: dict[str, list[Any]] = {}
        for option in self.options:
            categories.setdefault(option.category, []).append(option)
        return [*categories.items(), (PASSES_GROUP, list(self.passes)), (PEEPHOLE_GROUP, list(self.peephole_opts))]

    @property
    def option_and_values(self) -> list[tuple[Any, Any]]:
        return [(option, self.values[option]) for option in self.options]

    @property
    def selected_passes(self) -> list:
        return [p for p in self.passes if self.values.get(p)]

    @property
    def selected_peephole_opts(self) -> list:
        return [p for p in self.peephole_opts if self.values.get(p)]


__all__ = [
    "PASSES_GROUP",
    "PEEPHOLE_GROUP",
    "DecompilationOptionsSheet",
    "all_passes",
    "all_peephole_opts",
    "default_options",
    "default_passes",
    "default_peephole_opts",
    "default_preset_name",
    "preset_names",
    "value_kind",
]
