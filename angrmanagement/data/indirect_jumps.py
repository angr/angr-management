from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr.analyses.full_program_indirect_jump_resolution import FullProgramIndirectJumpResolution
    from angr.knowledge_plugins.cfg import CFGModel

_l = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProvenanceEntry:
    """
    One step of the chain that put a code pointer where an indirect jump could read it, rendered for display.

    :ivar text: What happened, in words.
    :ivar addr: Where it happened, if the step names an address worth navigating to.
    """

    text: str
    addr: int | None = None


@dataclass
class IndirectJumpResolutionResult:
    """
    What a ``FullProgramIndirectJumpResolution`` run found, in a form that outlives the analysis object.

    The analysis holds on to every function's dataflow facts and to the whole descriptor store, which is far more
    than a GUI needs and far too much to keep resident for the rest of a session. This is the distilled version:
    the resolutions themselves, enough about each site to display it and to line it up with ``kb.indirect_jumps``,
    and the provenance chains already rendered.

    :ivar resolutions: Site instruction address to the set of resolved target addresses.
    :ivar sites:       Every indirect site that was seen, resolved or not, to ``(containing function address, kind)``
                       where kind is ``"jump"`` or ``"call"``.
    :ivar block_addrs: Site instruction address to the address of the block that contains it, which is how
                       ``kb.indirect_jumps`` keys the same sites.
    :ivar provenance:  ``(site instruction address, target)`` to the chain of steps that got the pointer there,
                       oldest step first. Missing for a pair whose provenance was not recorded.
    :ivar summary:     One-line summary of the run.
    :ivar aborted:     Whether the run stopped early, making everything above partial.
    """

    resolutions: dict[int, set[int]] = field(default_factory=dict)
    sites: dict[int, tuple[int, str]] = field(default_factory=dict)
    block_addrs: dict[int, int] = field(default_factory=dict)
    provenance: dict[tuple[int, int], list[ProvenanceEntry]] = field(default_factory=dict)
    summary: str = ""
    aborted: bool = False

    @classmethod
    def from_analysis(
        cls, analysis: FullProgramIndirectJumpResolution, cfg_model: CFGModel | None = None
    ) -> IndirectJumpResolutionResult:
        """
        Distill a finished (or aborted) analysis into a result snapshot.

        :param cfg_model: Used to map each site back onto the block that contains it, which is how the same sites are
                          keyed in ``kb.indirect_jumps``. Without it the snapshot simply has no block addresses.
        """
        result = cls(
            resolutions={site: set(targets) for site, targets in analysis.resolved_indirect_jumps.items()},
            sites=dict(analysis.indirect_sites),
            summary=analysis.stats.summary(),
            aborted=analysis.stats.aborted,
        )

        if cfg_model is not None:
            for site in result.sites:
                node = cfg_model.get_any_node(site, anyaddr=True)
                if node is not None:
                    result.block_addrs[site] = node.addr

        for site, targets in result.resolutions.items():
            for target in targets:
                chain = cls._provenance_of(analysis, site, target)
                if chain:
                    result.provenance[site, target] = chain

        return result

    @staticmethod
    def _provenance_of(analysis: FullProgramIndirectJumpResolution, site: int, target: int) -> list[ProvenanceEntry]:
        """
        Render one provenance chain, pairing each rendered line with the address it happened at.
        """
        try:
            steps = analysis.get_provenance(site, target)
            lines = analysis.describe_provenance(site, target)
        except Exception:  # pylint:disable=broad-except
            _l.warning("Failed to render the provenance of %#x -> %#x.", site, target, exc_info=True)
            return []

        entries = []
        for step, line in zip(steps, lines, strict=False):
            entries.append(ProvenanceEntry(line, step.ins_addr if step.ins_addr is not None else step.addr))
        return entries

    #
    # Queries
    #

    def targets_of_block(self, block_addr: int) -> set[int]:
        """
        The targets this run recovered for the site in the given block, which is how ``kb.indirect_jumps`` names it.
        """
        targets: set[int] = set()
        for site in self.sites_in_block(block_addr):
            targets |= self.resolutions.get(site, set())
        return targets

    def sites_in_block(self, block_addr: int) -> list[int]:
        """
        The instruction addresses of the indirect sites this run found in the given block.
        """
        return [site for site, addr in self.block_addrs.items() if addr == block_addr]

    def provenance_of(self, site: int, target: int) -> list[ProvenanceEntry]:
        """
        The provenance chain for one resolved (site, target) pair; empty if none was recorded.
        """
        return self.provenance.get((site, target), [])
