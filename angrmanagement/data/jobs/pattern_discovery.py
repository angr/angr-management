from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from angr.analyses.decompiler.known_patterns.edit import PatternEditor
from angr.analyses.decompiler.known_patterns.generator import PatternGenerationError, PatternGenerator, stmt_ins_addrs
from angr.analyses.patterns import AlignParams, Checkpoint, FuzzyPatternFinder
from angr.analyses.patterns.search import find_template_occurrences

from angrmanagement.data.jobs.job import JobState
from angrmanagement.logic.jobmanager import JobCancelled

from .job import InstanceJob

if TYPE_CHECKING:
    from collections.abc import Callable

    from angr.analyses.decompiler.known_patterns import KnownPattern
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(__name__)


@dataclass
class DiscoveredFamily:
    """A family of similar code the finder reported, with a pattern lifted from its first copy."""

    copies: int
    size: int
    identity: float
    outlinable: int
    start_addr: int | None
    end_addr: int | None
    #: None when the first copy has nothing the pattern generator can lift
    pattern: KnownPattern | None
    #: verified occurrences of ``pattern`` in the function; can exceed ``copies``, since
    #: discovery drops copies that sit close together and search does not
    found: int = 0
    #: how many of the family's own copies ``pattern`` finds verified
    covered: int = 0
    #: for each copy, the instruction addresses its statements and their subexpressions
    #: carry: what the pseudocode view needs to find the lines the copy renders at
    copy_addrs: list[frozenset[int]] = field(default_factory=list)


@dataclass
class DiscoveryResult:
    func_addr: int
    func_name: str
    tokens: int
    seconds: float
    families: list[DiscoveredFamily] = field(default_factory=list)


def _stmt_key(stream, token: int) -> tuple:
    loc = stream.locs[token]
    return loc.block_loc, loc.stmt_idx


def discovery_params(min_size: int, min_identity: float) -> AlignParams:
    """Alignment knobs from the two a user sets: a seed no longer than the smallest
    family, and a score a family of that size at full identity just reaches."""
    return AlignParams(
        k=max(2, min(4, min_size)),
        min_size=min_size,
        min_score=3.0 * min_size,
        min_anchors=1 if min_size < 8 else 2,
        min_identity=min_identity,
    )


class PatternDiscoveryJob(InstanceJob):
    """
    Finds families of similar code in one function and lifts a pattern from each.

    Each pattern is loosened the way the editor's one-click actions would and searched
    for in the function, so a family's row says whether its pattern is ready to use.
    """

    def __init__(
        self,
        instance: Instance,
        func: Function,
        min_size: int = 4,
        min_identity: float = 0.6,
        on_finish: Callable[[DiscoveryResult], None] | None = None,
        blocking: bool = True,
    ) -> None:
        # blocking by default: the main window shows a modal progress dialog with Cancel
        super().__init__(f"Discovering patterns in {func.name}", instance, on_finish=on_finish, blocking=blocking)
        self.func = func
        self.min_size = min_size
        self.min_identity = min_identity

    def _check_cancelled(self) -> None:
        if self.state == JobState.CANCELLED:
            raise JobCancelled

    def run(self, ctx: JobContext) -> DiscoveryResult:
        func = self.func
        t0 = time.monotonic()
        ctx.set_progress(0.0, f"decompiling {func.name}")
        dec = self.instance.project.analyses.Decompiler(func, cfg=self.instance.cfg, use_cache=True)
        graph = dec.ail_graph
        if graph is None or dec.codegen is None:
            return DiscoveryResult(func.addr, func.name, 0, time.monotonic() - t0)

        # the alignment and every search yield to the GUI now and then, as the CFG does, and
        # notice a Cancel from inside their loops rather than between families only
        checkpoint = Checkpoint(low_priority=True, callback=self._check_cancelled)
        ctx.set_progress(20.0, f"aligning {sum(len(b.statements) for b in graph)} statements")
        finder = self.instance.project.analyses[FuzzyPatternFinder].prep()(
            func,
            graph,
            params=discovery_params(self.min_size, self.min_identity),
            disjoint=False,
            low_priority=True,
            checkpoint=checkpoint,
        )
        stream = finder.stream
        entry = finder.entry
        blocks = {(b.addr, b.idx): b for b in stream.blocks}
        generator = PatternGenerator(dec.codegen, graph)
        result = DiscoveryResult(func.addr, func.name, len(stream), 0.0)

        patterns = sorted(finder.all_patterns, key=lambda p: -len(p.occurrences) * p.size * p.identity)
        for k, family in enumerate(patterns):
            ctx.set_progress(20.0 + 80.0 * k / max(1, len(patterns)), f"family {k + 1} of {len(patterns)}")
            first = min(family.occurrences, key=lambda o: o.interval.start).interval
            start, end = stream.addr_range(first.start, first.end)
            row = DiscoveredFamily(
                copies=len(family.occurrences),
                size=family.size,
                identity=family.identity,
                outlinable=sum(1 for o in family.occurrences if o.outlinable),
                start_addr=start,
                end_addr=end,
                pattern=None,
                copy_addrs=[
                    frozenset().union(
                        *(
                            stmt_ins_addrs(blocks[loc.block_loc].statements[loc.stmt_idx])
                            for loc in stream.locs[occ.interval.start : occ.interval.end]
                        )
                    )
                    for occ in sorted(family.occurrences, key=lambda o: o.interval.start)
                ],
            )
            result.families.append(row)
            stmts = [blocks[loc.block_loc].statements[loc.stmt_idx] for loc in stream.locs[first.start : first.end]]
            try:
                pattern = generator.generate_pattern_from_statements(stmts, f"idiom_{k + 1}")
            except PatternGenerationError:
                continue
            # the copies of a family differ in their constants and deep subexpressions by
            # definition; the pattern starts out as loose as the editor's buttons would make it
            editor = PatternEditor(pattern)
            editor.loosen_constants()
            editor.cut_depth()
            row.pattern = editor.pattern
            try:
                search_stream, matches = find_template_occurrences(
                    row.pattern, graph, entry, kb=self.instance.kb, checkpoint=checkpoint
                )
            except Exception:  # pylint:disable=broad-except
                _l.debug("searching for family %d failed", k, exc_info=True)
                continue
            verified = [m for m in matches if m.verified]
            row.found = len(verified)
            # by statement, not by address range: reverse post-order interleaves blocks, so
            # the address ranges of unrelated spans overlap
            hit = {_stmt_key(search_stream, t) for m in verified for t in range(m.interval.start, m.interval.end)}
            row.covered = sum(
                1
                for occ in family.occurrences
                if any(_stmt_key(stream, t) in hit for t in range(occ.interval.start, occ.interval.end))
            )

        result.seconds = time.monotonic() - t0
        ctx.set_progress(100.0, "done")
        return result
