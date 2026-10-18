"""
A stand-in for the analysis gate when CFG recovery on the job thread never stops for the views.

The frontend-neutral tests and the Qt tests both use it, so it imports nothing from Qt.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from angrmanagement.logic.analysis_gate import AnalysisGate


def refuse_gate_reads(gate: AnalysisGate, add_cleanup: Callable[..., Any]) -> list[Callable[[], object]]:
    """
    Make ``gate`` refuse every read, as when the recovery does not stop in time, until ``patch.stopall()`` or the
    cleanup (pass the test's ``addCleanup``) undoes it.

    :returns: The list that collects what the readers put off until the recovery is done.
    """
    deferred: list[Callable[[], object]] = []

    @contextlib.contextmanager
    def refused(timeout: float = 0.0) -> Iterator[bool]:  # pylint:disable=unused-argument
        yield False

    patcher = patch.multiple(gate, access=refused, retry_when_done=deferred.append)
    patcher.start()
    add_cleanup(patcher.stop)
    return deferred
