# pylint:disable=missing-class-docstring,wrong-import-order,protected-access
from __future__ import annotations

# Import fastmcp (and therefore pydantic) before PySide6 is loaded via `common`. PySide6's
# shiboken __feature__ import hook otherwise collides with pydantic's lazy imports under pytest,
# producing a spurious circular ImportError.
try:
    from fastmcp import Client

    _MCP_IMPORT_OK = True
except ImportError:
    _MCP_IMPORT_OK = False

import asyncio
import os
import re
import shutil
import tempfile
import threading
import time
import unittest

import angr
import pytest
from common import AngrManagementTestCase, test_location
from PySide6.QtWidgets import QApplication

if _MCP_IMPORT_OK:
    from angrmanagement.mcp import MCPServerManager, is_mcp_available
else:
    is_mcp_available = lambda: False  # noqa: E731

pytestmark = pytest.mark.skipif(not is_mcp_available(), reason="fastmcp/uvicorn are not installed")


def _base_port() -> int:
    """A non-default base port, made unique per xdist worker so parallel runs don't clash."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "gw0")
    try:
        offset = int(worker.removeprefix("gw"))
    except ValueError:
        offset = 0
    # reserve two ports per worker (server + auth server), well clear of the default 8642
    return 8731 + offset * 2


_PORT = _base_port()


class MCPTestCase(AngrManagementTestCase):
    """Base case that loads fauxware and starts an MCP server bound to the live instance."""

    binary = os.path.join(test_location, "x86_64", "fauxware")
    auth_token: str | None = None
    port = _PORT
    load_project = True

    def setUp(self) -> None:
        super().setUp()
        if self.load_project:
            instance = self.main.workspace.main_instance
            instance.project.am_obj = angr.Project(self.binary, auto_load_libs=False)
            instance.project.am_event()
            self.main.workspace.job_manager.join_all_jobs()

        self.manager = MCPServerManager(self.main.workspace, port=self.port, auth_token=self.auth_token)
        self.manager.start()

    def tearDown(self) -> None:
        self.manager.stop()
        super().tearDown()

    def run_client(self, coro_factory, timeout: float = 300.0):
        """
        Run an async client coroutine in a background thread while pumping the Qt event loop on
        this (GUI) thread, so tools that marshal work onto the GUI thread can complete.

        :param coro_factory: A callable taking a connected Client and returning a coroutine.
        :returns: Whatever the coroutine returns.
        """
        box: dict[str, object] = {}
        done = threading.Event()

        url = self.manager.url
        auth = self.auth_token

        def worker() -> None:
            async def main():
                async with Client(url, auth=auth) as client:
                    return await coro_factory(client)

            try:
                box["result"] = asyncio.run(main())
            except Exception as e:  # noqa: BLE001  pylint:disable=broad-exception-caught
                box["error"] = e
            finally:
                done.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

        deadline = time.time() + timeout
        while not done.is_set() and time.time() < deadline:
            QApplication.processEvents()
            time.sleep(0.01)

        assert done.is_set(), "MCP client did not finish in time"
        if "error" in box:
            raise box["error"]  # type: ignore[misc]
        return box.get("result")


class TestMCPReadTools(MCPTestCase):
    def test_list_and_inspect_functions(self):
        async def scenario(client):
            info = (await client.call_tool("get_project_info", {})).data
            assert info["cfg_built"] is True
            assert info["function_count"] > 0

            funcs = (await client.call_tool("list_functions", {"name_pattern": "main"})).data
            assert any(f["name"] == "main" for f in funcs["functions"])

            fi = (await client.call_tool("get_function_info", {"name": "main"})).data
            assert fi["name"] == "main"

            # any address inside the function resolves to it
            mid = hex(int(fi["address"], 16) + 4)
            fi2 = (await client.call_tool("get_function_info", {"address": mid})).data
            assert fi2["name"] == "main"

            dis = (await client.call_tool("get_disassembly", {"name": "main"})).data
            assert dis["block_count"] > 0

            return fi["address"]

        main_addr = self.run_client(scenario)
        assert isinstance(main_addr, str)

    def test_get_decompilation_requires_prior_decompilation(self):
        from fastmcp.exceptions import ToolError

        async def scenario(client):
            with pytest.raises(ToolError):
                await client.call_tool("get_decompilation", {"name": "authenticate"})

        self.run_client(scenario)


class TestMCPLoadBinary(MCPTestCase):
    """The server is started with no project; the agent loads one via load_binary."""

    load_project = False

    def test_load_binary_into_empty_gui(self):
        assert self.main.workspace.main_instance.project.am_none

        async def scenario(client):
            status = (await client.call_tool("get_server_status", {})).data
            assert status["project_loaded"] is False

            r = (await client.call_tool("load_binary", {"binary_path": self.binary})).data
            assert r["loaded"] is True
            assert r["cfg_built"] is True
            assert r["function_count"] > 0

            # the loaded binary is now queryable through the live tools
            funcs = (await client.call_tool("list_functions", {"name_pattern": "main"})).data
            assert any(f["name"] == "main" for f in funcs["functions"])

        self.run_client(scenario)

        instance = self.main.workspace.main_instance
        assert not instance.project.am_none
        assert instance.project.am_obj.filename.endswith("fauxware")
        assert not instance.cfg.am_none

    def test_load_binary_missing_path_errors(self):
        from fastmcp.exceptions import ToolError

        async def scenario(client):
            with pytest.raises(ToolError):
                await client.call_tool("load_binary", {"binary_path": "/nonexistent/binary/xyzzy"})

        self.run_client(scenario)

    def test_load_uses_default_analysis_settings_without_prompting(self):
        from unittest.mock import patch

        # force the GUI code path that would normally pop the analysis-options dialog; reset it
        # before teardown so closeEvent does not pop a modal save prompt
        self.main.shown_at_start = True

        async def scenario(client):
            r = (await client.call_tool("load_binary", {"binary_path": self.binary})).data
            assert r["cfg_built"] is True

        try:
            with patch("angrmanagement.ui.workspace.AnalysisOptionsDialog") as dialog:
                self.run_client(scenario)
                # default (show_analysis_options=False): the dialog is never constructed
                assert dialog.call_count == 0
        finally:
            self.main.shown_at_start = False

    def test_load_with_show_analysis_options_prompts(self):
        from unittest.mock import MagicMock, patch

        self.main.shown_at_start = True

        async def scenario(client):
            await client.call_tool("load_binary", {"binary_path": self.binary, "show_analysis_options": True})

        try:
            with patch("angrmanagement.ui.workspace.AnalysisOptionsDialog") as dialog:
                dialog.return_value = MagicMock(**{"exec_.return_value": 1})  # user accepts
                self.run_client(scenario)
                assert dialog.call_count >= 1
        finally:
            self.main.shown_at_start = False


class TestMCPCloseProject(MCPTestCase):
    """close_project unloads the current binary and clears the views without errors."""

    def _open_and_populate_views(self):
        from angrmanagement.ui.views import DisassemblyView

        ws = self.main.workspace
        ws.show_functions_view()
        ws.show_hex_view()
        ws.show_linear_disassembly_view()
        ws.show_graph_disassembly_view()
        func = self.main.workspace.main_instance.kb.functions.function(name="main")
        disasm = ws._get_or_create_view("disassembly", DisassemblyView)
        disasm.display_disasm_graph()
        disasm.display_function(func)
        disasm.decompile_current_function()
        ws.job_manager.join_all_jobs()
        ws.show_pseudocode_view()
        for _ in range(30):
            QApplication.processEvents()
        return disasm

    def test_close_clears_project_and_views(self):
        disasm = self._open_and_populate_views()
        assert disasm._flow_graph.function_graph is not None
        functions_view = self.main.workspace.view_manager.first_view_in_category("functions")
        functions_model = functions_view._function_table._table_view._model
        assert functions_model.rowCount() > 0

        async def scenario(client):
            r = (await client.call_tool("close_project", {})).data
            assert r["closed"] is True
            status = (await client.call_tool("get_server_status", {})).data
            assert status["project_loaded"] is False

        self.run_client(scenario)

        # let any queued repaints run; they must not raise
        for _ in range(50):
            QApplication.processEvents()

        instance = self.main.workspace.main_instance
        assert instance.project.am_none
        assert instance.cfg.am_none
        # the disassembly graph and linear viewer cleared themselves
        assert disasm._flow_graph.function_graph is None
        assert not disasm._linear_viewer.objects
        # the functions view cleared its table
        assert functions_model.rowCount() == 0

    def test_load_binary_refused_while_open(self):
        from fastmcp.exceptions import ToolError

        async def scenario(client):
            with pytest.raises(ToolError):
                await client.call_tool("load_binary", {"binary_path": os.path.join(test_location, "x86_64", "true")})

        self.run_client(scenario)
        # the originally loaded binary is untouched
        instance = self.main.workspace.main_instance
        assert not instance.project.am_none
        assert instance.project.am_obj.filename.endswith("fauxware")

    def test_close_then_load_again(self):
        self._open_and_populate_views()

        async def scenario(client):
            await client.call_tool("close_project", {})
            r = (
                await client.call_tool("load_binary", {"binary_path": os.path.join(test_location, "x86_64", "true")})
            ).data
            assert r["cfg_built"] is True

        self.run_client(scenario)

        instance = self.main.workspace.main_instance
        assert not instance.project.am_none
        assert instance.project.am_obj.filename.endswith("true")

    def test_close_with_no_binary_is_noop(self):
        # close the fauxware loaded by setUp, then a second close is a no-op
        async def scenario(client):
            first = (await client.call_tool("close_project", {})).data
            assert first["closed"] is True
            second = (await client.call_tool("close_project", {})).data
            assert second["closed"] is False

        self.run_client(scenario)
        assert self.main.workspace.main_instance.project.am_none


class TestMCPDatabase(MCPTestCase):
    """save_database / load_database persist and restore the analysis session."""

    def setUp(self) -> None:
        super().setUp()
        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir, ignore_errors=True)
        self.db_path = os.path.join(self._tmpdir, "session.adb")

    def test_save_reload_roundtrip_preserves_edits(self):
        async def scenario(client):
            await client.call_tool("decompile_function", {"name": "authenticate", "focus": True})
            await client.call_tool("rename_function", {"name": "authenticate", "new_name": "check_creds"})

            saved = (await client.call_tool("save_database", {"database_path": self.db_path})).data
            assert saved["saved"] is True
            assert os.path.exists(self.db_path)

            await client.call_tool("close_project", {})

            loaded = (await client.call_tool("load_database", {"database_path": self.db_path})).data
            assert loaded["loaded"] is True
            assert loaded["function_count"] > 0

            # the rename and its decompilation survived the round-trip
            funcs = (await client.call_tool("list_functions", {"name_pattern": "check_creds"})).data
            assert any(f["name"] == "check_creds" for f in funcs["functions"])
            dec = (await client.call_tool("get_decompilation", {"name": "check_creds"})).data
            assert "check_creds" in dec["code"]

        self.run_client(scenario)
        instance = self.main.workspace.main_instance
        assert not instance.project.am_none
        assert instance.kb.functions.function(name="check_creds") is not None

    def test_save_refuses_overwrite_without_flag(self):
        from fastmcp.exceptions import ToolError

        async def scenario(client):
            first = (await client.call_tool("save_database", {"database_path": self.db_path})).data
            assert first["saved"] is True
            with pytest.raises(ToolError):
                await client.call_tool("save_database", {"database_path": self.db_path})
            # overwrite=True succeeds
            again = (await client.call_tool("save_database", {"database_path": self.db_path, "overwrite": True})).data
            assert again["saved"] is True

        self.run_client(scenario)

    def test_load_database_refused_while_open(self):
        from fastmcp.exceptions import ToolError

        async def scenario(client):
            await client.call_tool("save_database", {"database_path": self.db_path})
            with pytest.raises(ToolError):
                await client.call_tool("load_database", {"database_path": self.db_path})

        self.run_client(scenario)


class TestMCPDatabaseEmpty(MCPTestCase):
    """Database tool error paths when no project is loaded."""

    load_project = False

    def test_save_without_project_errors(self):
        from fastmcp.exceptions import ToolError

        with tempfile.TemporaryDirectory() as td:

            async def scenario(client):
                with pytest.raises(ToolError):
                    await client.call_tool("save_database", {"database_path": os.path.join(td, "x.adb")})

            self.run_client(scenario)

    def test_load_missing_database_errors(self):
        from fastmcp.exceptions import ToolError

        async def scenario(client):
            with pytest.raises(ToolError):
                await client.call_tool("load_database", {"database_path": "/nonexistent/session.adb"})

        self.run_client(scenario)


class TestMCPHistory(MCPTestCase):
    """Tool calls are recorded and shown in the MCP History view, docked in the console group."""

    def _history_view(self):
        return self.main.workspace.view_manager.first_view_in_category("mcp_history")

    def _pump(self, n: int = 60) -> None:
        # let the deferred (GUI-thread) history events apply
        for _ in range(n):
            QApplication.processEvents()

    def test_history_view_present_in_bottom_group(self):
        view = self._history_view()
        assert view is not None
        assert view.base_caption == "MCP History"
        assert view.default_docking_position == "bottom"

    def test_calls_recorded_and_reflected_in_table(self):
        from fastmcp.exceptions import ToolError

        view = self._history_view()

        async def scenario(client):
            await client.call_tool("get_server_status", {})
            await client.call_tool("list_functions", {"name_pattern": "main"})
            with pytest.raises(ToolError):
                await client.call_tool("get_function_info", {"name": "no_such_function_xyz"})

        self.run_client(scenario)
        self._pump()

        records = list(self.main.workspace.mcp_history.am_obj)
        tools = [r.tool for r in records]
        assert "get_server_status" in tools
        assert "list_functions" in tools
        # the failing call is recorded with an error status
        assert any(r.tool == "get_function_info" and r.status == "error" for r in records)
        # the table shows one row per record
        assert view._table.rowCount() == len(records)

    def test_clear_empties_history_and_table(self):
        async def scenario(client):
            await client.call_tool("get_server_status", {})

        self.run_client(scenario)
        self._pump()

        view = self._history_view()
        assert len(self.main.workspace.mcp_history.am_obj) >= 1
        assert view._table.rowCount() >= 1

        view._on_clear_clicked()
        QApplication.processEvents()
        assert view._table.rowCount() == 0
        assert len(self.main.workspace.mcp_history.am_obj) == 0

    def test_history_limit_caps_records_and_table(self):
        from angrmanagement.config import Conf

        original = Conf.mcp_server_history_limit
        Conf.mcp_server_history_limit = 3
        try:

            async def scenario(client):
                for _ in range(7):
                    await client.call_tool("get_server_status", {})

            self.run_client(scenario)
            self._pump()

            view = self._history_view()
            # only the most recent 3 calls are retained, in both the container and the table
            assert len(self.main.workspace.mcp_history.am_obj) == 3
            assert view._table.rowCount() == 3
        finally:
            Conf.mcp_server_history_limit = original


class TestMCPDecompileAndVisualize(MCPTestCase):
    def test_focused_decompilation_updates_pseudocode_view(self):
        async def scenario(client):
            r = (await client.call_tool("decompile_function", {"name": "main", "focus": True})).data
            assert "main" in r["code"]
            assert r["shown_to_user"] is True
            return r

        self.run_client(scenario)
        # give the async focus event a moment to be processed on the GUI thread
        for _ in range(200):
            QApplication.processEvents()
            time.sleep(0.005)

        code_view = self.main.workspace.view_manager.first_view_in_category("pseudocode")
        assert code_view is not None
        assert not code_view.function.am_none
        assert code_view.function.am_obj.name == "main"

    def test_background_decompilation_does_not_change_view(self):
        async def scenario(client):
            r = (await client.call_tool("decompile_function", {"name": "authenticate", "focus": False})).data
            assert "authenticate" in r["code"]
            assert r["shown_to_user"] is False

        self.run_client(scenario)
        # the pseudocode view should not have been opened on authenticate
        code_view = self.main.workspace.view_manager.first_view_in_category("pseudocode")
        if code_view is not None and not code_view.function.am_none:
            assert code_view.function.am_obj.name != "authenticate"


class TestMCPMutationTools(MCPTestCase):
    def test_rename_function_reflected_in_kb_and_pseudocode(self):
        async def scenario(client):
            await client.call_tool("decompile_function", {"name": "authenticate", "focus": True})
            r = (await client.call_tool("rename_function", {"name": "authenticate", "new_name": "check_creds"})).data
            assert r["new_name"] == "check_creds"
            dec = (await client.call_tool("get_decompilation", {"name": "check_creds"})).data
            assert "check_creds" in dec["code"]

        self.run_client(scenario)

        instance = self.main.workspace.main_instance
        assert instance.kb.functions.function(name="check_creds") is not None

    def test_rename_variable_reflected_in_pseudocode(self):
        async def scenario(client):
            await client.call_tool("decompile_function", {"name": "authenticate", "focus": True})
            dec = (await client.call_tool("get_decompilation", {"name": "authenticate"})).data
            m = re.search(r"\b(v\d+)\b", dec["code"])
            assert m, dec["code"]
            var = m.group(1)
            await client.call_tool(
                "rename_variable", {"name": "authenticate", "variable_name": var, "new_name": "renamed_var"}
            )
            dec = (await client.call_tool("get_decompilation", {"name": "authenticate"})).data
            assert "renamed_var" in dec["code"]

        self.run_client(scenario)

        code_view = self.main.workspace.view_manager.first_view_in_category("pseudocode")
        assert code_view is not None and not code_view.codegen.am_none
        assert "renamed_var" in code_view.codegen.text

    def test_set_comment_shown_once_as_header(self):
        async def scenario(client):
            await client.call_tool("decompile_function", {"name": "main", "focus": True})
            fi = (await client.call_tool("get_function_info", {"name": "main"})).data
            r = (
                await client.call_tool("set_comment", {"address": fi["address"], "comment": "commented by a test"})
            ).data
            assert r["shown_in_pseudocode"] is True

        self.run_client(scenario)

        code_view = self.main.workspace.view_manager.first_view_in_category("pseudocode")
        assert code_view is not None and not code_view.codegen.am_none
        assert code_view.codegen.text.count("commented by a test") == 1


class TestMCPAuth(unittest.TestCase):
    """Auth is exercised directly against the manager to keep it independent of a loaded project."""

    def setUp(self) -> None:
        from common import create_qapp
        from PySide6.QtCore import QThread

        from angrmanagement.logic import GlobalInfo

        self.app = create_qapp()
        GlobalInfo.gui_thread = QThread.currentThread()
        from angrmanagement.ui.main_window import MainWindow

        self.main = MainWindow(show=False)
        self.token = "unit-test-token"
        self.manager = MCPServerManager(self.main.workspace, port=_PORT + 1, auth_token=self.token)
        self.manager.start()

    def tearDown(self) -> None:
        self.manager.stop()
        self.main.close()

    def _connect(self, auth) -> bool:
        box: dict[str, object] = {}
        done = threading.Event()
        url = self.manager.url

        def worker() -> None:
            async def main():
                async with Client(url, auth=auth) as client:
                    await client.list_tools()

            try:
                asyncio.run(main())
                box["ok"] = True
            except Exception:  # noqa: BLE001  pylint:disable=broad-exception-caught
                box["ok"] = False
            finally:
                done.set()

        threading.Thread(target=worker, daemon=True).start()
        deadline = time.time() + 60
        while not done.is_set() and time.time() < deadline:
            QApplication.processEvents()
            time.sleep(0.01)
        assert done.is_set()
        return bool(box.get("ok"))

    def test_missing_token_rejected(self):
        assert self._connect(auth=None) is False

    def test_wrong_token_rejected(self):
        assert self._connect(auth="not-the-token") is False

    def test_correct_token_accepted(self):
        assert self._connect(auth=self.token) is True


if __name__ == "__main__":
    unittest.main()
