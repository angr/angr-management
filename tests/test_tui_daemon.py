"""
The terminal app as the main window of the daemon client and the MCP server, on fauxware from angr/binaries: angr://
URL actions arriving from the daemon reach the app's workspace and bring the terminal to the front; the MCP server
starts at launch when configured and from the AI menu, and stops.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use

from __future__ import annotations

import asyncio
import os
import socket
import unittest
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from tui_pilot import kb_of, settle, wait_for  # pylint: disable=import-error

from angrmanagement.config import Conf
from angrmanagement.daemon.client import ClientService
from angrmanagement.logic import GlobalInfo
from angrmanagement.mcp import is_mcp_available
from angrmanagement.present.menus import MenuEntry
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.executor import TextualExecutor

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
MAIN = 0x40071D


def run_app(scenario: Callable[[AmApp, Pilot], Awaitable[None]], binary: str | None = FAUXWARE, **kwargs: Any) -> None:
    async def main() -> None:
        app = AmApp(caps=kwargs.pop("caps", TerminalCaps(truecolor=True, forced_tier=2)), interactive=False, **kwargs)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            if binary is not None:
                await app.open_binary(binary)
                await pilot.pause()
            await scenario(app, pilot)

    asyncio.run(main())


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class AppCase(unittest.TestCase):
    def setUp(self) -> None:
        self.saved = (GlobalInfo._executor, GlobalInfo._ui_services, GlobalInfo.main_window)
        self.saved_conf = {name: Conf.entry(name).value for name in ("mcp_server_autostart", "mcp_server_port")}

    def tearDown(self) -> None:
        for name, value in self.saved_conf.items():
            setattr(Conf, name, value)
        assert (GlobalInfo._ui_services, GlobalInfo.main_window) == self.saved[1:]
        assert not isinstance(GlobalInfo._executor, TextualExecutor)
        GlobalInfo._executor = self.saved[0]


class TestDaemonClient(AppCase):
    def test_url_actions_reach_the_app_and_bring_it_to_the_front(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            main_window: Any = GlobalInfo.main_window
            assert main_window is app and main_window.workspace is app.workspace
            fronts: list[bool] = []
            app.bring_to_front = lambda: fronts.append(True)  # type: ignore[method-assign]
            service = ClientService()
            # the daemon calls these from its connection's thread
            await asyncio.to_thread(service.exposed_jumpto, 0x400664, None)
            disasm: Any = app.view_widget("disassembly")
            await wait_for(pilot, lambda: disasm.presenter.function.am_obj.name == "authenticate")
            await asyncio.to_thread(service.exposed_commentat, MAIN, "from a URL")
            await wait_for(pilot, lambda: kb_of(app).comments.get(MAIN) == "from a URL")
            assert len(fronts) == 2

        run_app(scenario)

    def test_bring_to_front_asks_kitty_and_rings_elsewhere(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            bells: list[bool] = []
            app.bell = lambda: bells.append(True)  # type: ignore[method-assign]
            with (
                patch.dict(os.environ, {"KITTY_WINDOW_ID": "7"}),
                patch("angrmanagement.tui.app.shutil.which", return_value="/usr/bin/kitty"),
                patch("angrmanagement.tui.app.subprocess.run") as run,
            ):
                app.bring_to_front()
            assert run.call_args.args[0] == ["kitty", "@", "focus-window", "--match", "id:7"] and not bells
            app.caps.kitty = False
            app.bring_to_front()
            await settle(pilot)
            assert bells == [True]

        run_app(scenario, binary=None, caps=TerminalCaps(truecolor=True, kitty=True, forced_tier=3))

    def test_with_the_daemon_it_connects_at_start(self) -> None:
        async def scenario(_app: AmApp, pilot: Pilot) -> None:
            await settle(pilot)

        with patch("angrmanagement.daemon.client.connect_to_daemon") as connect:
            run_app(scenario, binary=None, use_daemon=True)
        connect.assert_called_once_with()
        with patch("angrmanagement.daemon.client.connect_to_daemon") as connect:
            run_app(scenario, binary=None)
        connect.assert_not_called()


@unittest.skipUnless(is_mcp_available(), "fastmcp/uvicorn are not installed")
class TestMcpServer(AppCase):
    def test_autostart_from_the_configuration_and_stop_from_the_menu(self) -> None:
        Conf.mcp_server_autostart = True
        Conf.mcp_server_port = free_port()

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            await wait_for(pilot, lambda: app.mcp_server_manager is not None and app.mcp_server_manager.running)
            assert app.mcp_server_manager.url.endswith(f":{Conf.mcp_server_port}/mcp")
            ai_menu = next(menu for menu in app.menus if menu.text == "AI")
            stop = next(e for e in ai_menu.items() if isinstance(e, MenuEntry) and e.text == "Stop MCP Server")
            stop.trigger()
            await settle(pilot)
            assert app.mcp_server_manager is None
            start = next(e for e in ai_menu.items() if isinstance(e, MenuEntry) and e.text == "Start MCP Server")
            start.trigger()
            await wait_for(pilot, lambda: app.mcp_server_manager is not None and app.mcp_server_manager.running)
            app.stop_mcp_server()

        run_app(scenario, binary=None)


if __name__ == "__main__":
    unittest.main()
