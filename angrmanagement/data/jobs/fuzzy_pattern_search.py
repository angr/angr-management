from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from angr.analyses.fuzzy_patterns.region import snap
from angr.analyses.fuzzy_patterns.search import find_template_occurrences

from .job import InstanceJob

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from angr.analyses.decompiler.known_patterns import KnownPattern
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(__name__)


@dataclass
class FuzzyMatchRow:
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


class FuzzyPatternSearchJob(InstanceJob):
    """
    Searches functions for occurrences of one fuzzy pattern.

    Each function is decompiled (from the cache when it is there) and its AIL graph
    aligned against the pattern; every hit is reported with its similarity, whether
    it verifies structurally, and whether the region it covers could be outlined.
    """

    def __init__(
        self,
        instance: Instance,
        pattern: KnownPattern,
        functions: Sequence[Function],
        on_finish: Callable[[list[FuzzyMatchRow]], None] | None = None,
        blocking: bool = False,
    ) -> None:
        super().__init__(f"Searching for {pattern.display_name}", instance, on_finish=on_finish, blocking=blocking)
        self.pattern = pattern
        self.functions = list(functions)

    def run(self, ctx: JobContext) -> list[FuzzyMatchRow]:
        rows: list[FuzzyMatchRow] = []
        total = max(1, len(self.functions))
        for i, func in enumerate(self.functions):
            ctx.set_progress(100.0 * i / total, f"searching {func.name}")
            try:
                dec = self.instance.project.analyses.Decompiler(func, cfg=self.instance.cfg, use_cache=True)
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
                rows.append(
                    FuzzyMatchRow(
                        func_addr=func.addr,
                        func_name=func.name,
                        start_addr=start,
                        end_addr=end,
                        similarity=match.similarity,
                        identity=match.identity,
                        verified=bool(match.verified),
                        outlinable=region.outlinable,
                        reason=region.reason,
                    )
                )
        ctx.set_progress(100.0, "done")
        rows.sort(key=lambda r: (-r.similarity, r.func_addr, r.start_addr or 0))
        return rows
