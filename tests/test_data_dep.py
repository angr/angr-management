"""
The data dependency view, without a toolkit and in the terminal, on fauxware: the DataDep analysis of a state that
ran main's first block (built in memory, as a trace file's pickled state would be), the full graph, the one without
temporaries and a traced node's, tracing ancestors and descendants, the node search, and loading a trace file.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import unittest
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import angr
from angr.analyses.data_dep import RegDepNode, TmpDepNode

from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.present.data_dep import DataDepPresenter, ancestors, graph_has_tmp_nodes, search_nodes
from angrmanagement.present.menus import walk_entries
from angrmanagement.present.shell import show_trace_file
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.views.graphs import DataDepSearchScreen, DataDepTuiView

if TYPE_CHECKING:
    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
MAIN = 0x40071D


def stepped_state(project) -> angr.SimState:
    """A state that ran main's first block with action tracking, as a trace's final state."""
    options = angr.sim_options.refs | {
        angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
    }
    state = project.factory.blank_state(addr=MAIN, add_options=options)
    return project.factory.successors(state).flat_successors[0]


def params(state) -> dict:
    return {"end_state": state, "start_addr": MAIN, "end_addr": None, "block_addrs": None}


def captions(menu) -> list[str]:
    return [entry.text for _path, entry in walk_entries(menu)]


class TestPresenter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = angr.Project(FAUXWARE, auto_load_libs=False)
        cls.project.analyses.CFGFast(normalize=True)
        cls.state = stepped_state(cls.project)

    def setUp(self):
        self.workspace: Any = HeadlessWorkspace(auto_analyze=False)
        self.instance: Any = self.workspace.main_instance
        self.instance.project.am_obj = self.project
        self.instance.project.am_event()

    def tearDown(self):
        self.workspace.job_manager.quit()

    def test_graphs_and_toggles(self):
        presenter = DataDepPresenter(self.workspace, self.instance)
        assert presenter.context_menu(None) is None
        presenter.analysis_params = params(self.state)
        data_dep = presenter._data_dep
        assert presenter.data_dep_graph is data_dep.graph and graph_has_tmp_nodes(presenter.data_dep_graph)
        assert len(presenter.graph.picture.boxes) == data_dep.graph.number_of_nodes()
        menu = presenter.context_menu(None)
        assert menu is not None and captions(menu) == ["Hide temp nodes"]
        presenter.toggle_graph()
        assert presenter.data_dep_graph is data_dep.simplified_graph
        assert not graph_has_tmp_nodes(presenter.data_dep_graph)
        assert presenter.toggle_text() == "Show temp nodes"
        presenter.toggle_graph()
        assert presenter.data_dep_graph is data_dep.graph
        # a node's own graph, then back
        node = next(n for n in data_dep.graph.nodes if isinstance(n, RegDepNode) and str(n) == "rbp")
        node_menu = presenter.context_menu(node)
        assert node_menu is not None and captions(node_menu) == ["Trace backward", "Trace forward"]
        presenter.use_subgraph(node, False)
        assert presenter.data_dep_graph is data_dep.sub_graph and presenter.toggle_text() == "Untrack node"
        presenter.toggle_graph()
        assert presenter.data_dep_graph is data_dep.graph
        # the same parameters do not run the analysis again
        presenter.analysis_params = params(self.state)
        assert presenter._data_dep is data_dep

    def test_tracing(self):
        presenter = DataDepPresenter(self.workspace, self.instance)
        presenter.analysis_params = params(self.state)
        graph = presenter.data_dep_graph
        assert graph is not None
        node = next(n for n in graph.nodes if graph.in_degree(n) and graph.out_degree(n))
        presenter.trace(node)
        assert presenter.traced_ancestors == ancestors(graph, node) and not presenter.traced_descendants
        presenter.edge_styles()
        traced = [e for e in presenter.graph.picture.edges if e.style == "graph.edge.traced"]
        assert traced and all(e.dst.node in presenter.traced_ancestors for e in traced)
        presenter.graph.selected = node
        presenter.toggle_trace_direction()
        assert presenter.traced_descendants and not presenter.traced_ancestors
        presenter.trace(None)
        assert not presenter.traced_ancestors and not presenter.traced_descendants

    def test_search(self):
        presenter = DataDepPresenter(self.workspace, self.instance)
        presenter.analysis_params = params(self.state)
        nodes = list(presenter.data_dep_graph.nodes)  # type: ignore[union-attr]
        found, error = search_nodes(nodes, "rsp", "", "")
        assert found and not error and all("rsp" in str(n) for n in found)
        found, error = search_nodes(nodes, "", "", f"{MAIN:x}")
        assert found and all(n.ins_addr == MAIN for n in found)
        assert search_nodes(nodes, "", "zz", "") == ([], "Input must be in hexadecimal format!")
        assert search_nodes(nodes, "no-such-node", "", "") == ([], "No nodes match the given search criteria.")
        first = presenter.search_next("tmp", "", "")
        second = presenter.search_next("tmp", "", "")
        assert isinstance(first, TmpDepNode) and isinstance(second, TmpDepNode) and first is not second
        assert presenter.graph.selected is second


class TestTraceFile(unittest.TestCase):
    """show_trace_file, which both frontends' File > Load a new trace... call."""

    def setUp(self):
        self.workspace: Any = HeadlessWorkspace(auto_analyze=False)
        self.reported: list[str] = []

    def report(self, title: str, text: str) -> None:
        self.reported.append(title)

    def test_errors(self):
        assert not show_trace_file(self.workspace, "https://example.com/state.trace", self.report)
        assert not show_trace_file(self.workspace, "/nonexistent/state.trace", self.report)
        assert not show_trace_file(self.workspace, FAUXWARE, self.report)  # not a pickle
        assert self.reported == ["Unsupported Action", "File not found", "Unable to load trace file"]

    def test_loaded_state(self):
        state = object()
        with (
            patch("angrmanagement.present.shell.pickle.load", return_value=state),
            patch.object(self.workspace, "view_data_dependency_graph") as view,
        ):
            assert show_trace_file(self.workspace, FAUXWARE, self.report)
        view.assert_called_once_with({"end_state": state, "start_addr": None, "end_addr": None, "block_addrs": None})
        assert not self.reported


class TestTerminal(unittest.TestCase):
    def test_view_trace_search_and_trace_files(self):
        async def main() -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
            async with app.run_test(size=(200, 60)) as pilot:
                await pilot.pause()
                await app.open_binary(FAUXWARE, function="main")
                for _ in range(4):
                    await pilot.pause()
                project = app.workspace.main_instance.project.am_obj
                app.workspace.view_data_dependency_graph(params(stepped_state(project)))
                for _ in range(8):
                    await pilot.pause()
                view = app.view_widget("data_dependency")
                assert isinstance(view, DataDepTuiView)
                presenter = view.presenter
                assert view.graph.canvas is not None
                assert "rbp" in str(view.graph.canvas)
                view.graph.focus()
                await pilot.press("t")
                for _ in range(4):
                    await pilot.pause()
                assert presenter.data_dep_graph is presenter._data_dep.simplified_graph
                await pilot.press("ctrl+f")
                for _ in range(4):
                    await pilot.pause()
                assert isinstance(app.screen, DataDepSearchScreen)
                app.screen.query_one("#name").value = "rsp"  # type: ignore[attr-defined]
                await pilot.press("enter")
                for _ in range(4):
                    await pilot.pause()
                selected = presenter.graph.selected
                assert selected is not None and "rsp" in str(selected)
                assert presenter.traced_ancestors
                await pilot.press("escape")
                for _ in range(2):
                    await pilot.pause()
                # trace files: one that is not there
                services: Any = app.services
                messages: list[str] = []
                with patch.object(services, "message", lambda level, title, text: messages.append(title)):
                    app.load_trace_file("/nonexistent/state.trace")
                assert messages == ["File not found"]

        asyncio.run(main())


async def _data_dep_for_snapshot(pilot: Pilot) -> None:
    app: Any = pilot.app
    await pilot.pause()
    await app.open_binary(FAUXWARE, function="main")
    for _ in range(4):
        await pilot.pause()
    project = app.workspace.main_instance.project.am_obj
    app.workspace.view_data_dependency_graph(params(stepped_state(project)))
    for _ in range(4):
        await pilot.pause()
    view = app.view_widget("data_dependency")
    view.presenter.toggle_graph()
    for _ in range(4):
        await pilot.pause()


def test_snapshot_data_dependency(snap_compare):
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name="Light", interactive=False)
    assert snap_compare(app, terminal_size=(200, 60), run_before=_data_dep_for_snapshot)


if __name__ == "__main__":
    unittest.main()
