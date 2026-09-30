from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from angr.analyses.decompiler.optimization_passes import PatternOutliner
from angr.analyses.decompiler.pattern_match.region import largest_single_entry_subrun, snap
from angr.analyses.decompiler.pattern_match.search import find_template_occurrences
from angr.analyses.decompiler.presets import DECOMPILATION_PRESETS

from .job import InstanceJob

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from angr.analyses.decompiler.known_patterns import KnownPattern
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(__name__)


@dataclass
class PatternMatchRow:
    """One occurrence of a pattern, as the match table shows it."""

    func_addr: int
    func_name: str
    start_addr: int | None
    end_addr: int | None
    similarity: float
    identity: float
    verified: bool
    outlinable: bool
    reason: str
    #: indices of the template leaves that failed the structural match
    failed_leaves: list[int]
    #: when the occurrence cannot be outlined as it is: the address range of its largest
    #: single-entry sub-run, and the share of the occurrence it covers
    suggested_start: int | None = None
    suggested_end: int | None = None
    suggested_coverage: float = 0.0


@dataclass
class CurrentDecompilation:
    """The parts of a cached decompilation the pattern tools read."""

    ail_graph: Any
    codegen: Any


def current_decompilation(instance: Instance, func: Function):
    """The function's decompilation as the pseudocode view shows it.

    The view decompiles with its own options, passes and peephole settings; a Decompiler
    call without them misses the cache, decompiles again, and overwrites the view's cache.
    So a cached decompilation that still carries its AIL graph is used as it is. Only
    without one is the function decompiled, and the result kept out of the cache.
    """
    cache = instance.kb.decompilations.get((func.addr, "pseudocode"))
    if cache is not None and cache.codegen is not None:
        # a cache spilled to disk comes back without its AIL graph
        graph = getattr(cache.clinic, "cc_graph", None)
        if graph is not None:
            return CurrentDecompilation(graph, cache.codegen)
    return instance.project.analyses.Decompiler(func, cfg=instance.cfg, use_cache=True, update_cache=False)


def decompile_without_patterns(instance: Instance, func: Function):
    """The function's decompilation as a pattern would see it: before the outliner pass.

    Once a pattern is enabled in the project, a decompilation may already carry its
    occurrences as calls, and a search of that graph would find nothing. So with any
    enabled pattern this decompiles afresh with the pass left out and keeps the result
    out of the cache; with none, the cached decompilation is as good.
    """
    project = instance.project
    if not instance.kb.patterns.enabled_patterns():
        return current_decompilation(instance, func)
    platform = project.simos.name if project.simos is not None else None
    passes = DECOMPILATION_PRESETS["default"].get_optimization_passes(
        project.arch, platform, disable_opts=[PatternOutliner]
    )
    return project.analyses.Decompiler(
        func, cfg=instance.cfg, optimization_passes=passes, use_cache=False, update_cache=False
    )


class PatternSearchJob(InstanceJob):
    """
    Searches functions for occurrences of one pattern.

    Each function is decompiled (from the cache when it is there) and its AIL graph
    aligned against the pattern; every hit is reported with its similarity, whether
    it verifies structurally, and whether the region it covers could be outlined.
    """

    def __init__(
        self,
        instance: Instance,
        pattern: KnownPattern,
        functions: Sequence[Function],
        on_finish: Callable[[list[PatternMatchRow]], None] | None = None,
        blocking: bool = False,
    ) -> None:
        super().__init__(f"Searching for {pattern.display_name}", instance, on_finish=on_finish, blocking=blocking)
        self.pattern = pattern
        self.functions = list(functions)

    def _decompile(self, func: Function):
        return decompile_without_patterns(self.instance, func)

    def run(self, ctx: JobContext) -> list[PatternMatchRow]:
        rows: list[PatternMatchRow] = []
        total = max(1, len(self.functions))
        for i, func in enumerate(self.functions):
            ctx.set_progress(100.0 * i / total, f"searching {func.name}")
            try:
                dec = self._decompile(func)
            except Exception:  # pylint:disable=broad-except
                _l.debug("decompiling %s for the pattern search failed", func.name, exc_info=True)
                continue
            graph = dec.ail_graph
            if graph is None:
                continue
            entry = next((b for b in graph if b.addr == func.addr and b.idx is None), None)
            if entry is None:
                continue
            stream, matches = find_template_occurrences(self.pattern, graph, entry, kb=self.instance.kb)
            for match in matches:
                region = snap(stream, graph, match.interval, entry_loc=(func.addr, None))
                start, end = stream.addr_range(match.interval.start, match.interval.end)
                suggested = (None, None, 0.0)
                if not region.outlinable and "entered from outside" in region.reason:
                    subrun = largest_single_entry_subrun(stream, graph, match.interval, entry_loc=(func.addr, None))
                    if subrun is not None:
                        sub_start, sub_end = stream.addr_range(subrun.interval.start, subrun.interval.end)
                        suggested = (sub_start, sub_end, len(subrun.interval) / max(1, len(match.interval)))
                rows.append(
                    PatternMatchRow(
                        func_addr=func.addr,
                        func_name=func.name,
                        start_addr=start,
                        end_addr=end,
                        similarity=match.similarity,
                        identity=match.identity,
                        verified=bool(match.verified),
                        outlinable=region.outlinable,
                        reason=region.reason,
                        failed_leaves=[c.leaf for c in match.columns if c.verified is False],
                        suggested_start=suggested[0],
                        suggested_end=suggested[1],
                        suggested_coverage=suggested[2],
                    )
                )
        ctx.set_progress(100.0, "done")
        rows.sort(key=lambda r: (-r.similarity, r.func_addr, r.start_addr or 0))
        return rows
