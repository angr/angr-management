from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.data.search import Searcher

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.data.search import SearchQuery, SearchResult
    from angrmanagement.logic.jobmanager import JobContext


class SearchJob(InstanceJob):
    """Runs a :class:`SearchQuery` in the worker thread."""

    def __init__(self, instance: Instance, query: SearchQuery, on_finish=None) -> None:
        super().__init__("Searching", instance, on_finish=on_finish)
        self.query = query
        self.results: list[SearchResult] = []

    def run(self, ctx: JobContext) -> list[SearchResult]:
        project = self.instance.project.am_obj
        if project is None:
            return []

        cfg = None if self.instance.cfg.am_none else self.instance.cfg.am_obj
        searcher = Searcher(project, kb=self.instance.kb, cfg=cfg)

        results: list[SearchResult] = []
        for result in searcher.iter_results(self.query, progress=ctx.set_progress):
            results.append(result)
            if len(results) >= self.query.max_results:
                break
        self.results = results
        return results
