"""
The Qt and the terminal pseudocode show the same text: for fauxware's main and authenticate, each line the terminal
widget draws (without its line numbers) is the line of ``codegen.text``, and the Qt editor's plain text is
``codegen.text`` itself. The Qt view also highlights the mentions of the node under the cursor as soon as it shows a
decompilation, before any key is pressed.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use

from __future__ import annotations

import asyncio
import os
import unittest
from typing import Any

from common import AngrManagementTestCase, open_analyzed_project, test_location

from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.views.code import CodeTuiView
from angrmanagement.ui.views import CodeView, DisassemblyView

FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
FUNCTIONS = ["main", "authenticate"]


class TestQtCodeText(AngrManagementTestCase):
    def setUp(self):
        super().setUp()
        self.project = open_analyzed_project(self.main, FAUXWARE)
        self.workspace = self.main.workspace

    def show(self, name: str) -> Any:
        func = self.project.kb.functions[name]
        disasm: Any = self.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm.display_function(func)
        disasm.decompile_current_function()
        self.workspace.job_manager.join_all_jobs()
        view = self.workspace.view_manager.first_view_in_category("pseudocode")
        assert isinstance(view, CodeView)
        return view

    def test_the_editor_shows_codegen_text(self):
        for name in FUNCTIONS:
            view = self.show(name)
            assert view.function.am_obj.name == name
            assert view.textedit.toPlainText() == view.codegen.text, name

    def test_the_first_node_is_highlighted_when_shown(self):
        view = self.show("main")
        assert view.textedit.textCursor().position() == 0
        # "int", the return type at position 0: its mentions are the chunks
        chunks = view.document.find_related_text_chunks(view.document.get_node_at_position(0))
        assert chunks
        assert len(view._chunk_selections) == len(chunks)


class TestTerminalCodeText(unittest.TestCase):
    def test_every_line_is_the_text_line(self):
        results: dict[str, tuple[list[str], list[str]]] = {}

        async def main() -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=False)
            async with app.run_test(size=(200, 60)) as pilot:
                await pilot.pause()
                await app.open_binary(FAUXWARE, function="main")
                for name in FUNCTIONS:
                    kb: Any = app.workspace.main_instance.kb
                    func = kb.functions[name]
                    app.workspace.decompile_function(func)
                    await app.wait_for_jobs()
                    for _ in range(200):
                        view: Any = app.view_widget("pseudocode")
                        shown = isinstance(view, CodeTuiView) and view.presenter.function.am_obj is func
                        if shown and view.presenter.doc is not None and not app.workspace.job_manager.jobs:
                            break
                        await pilot.pause()
                    view = app.view_widget("pseudocode")
                    assert isinstance(view, CodeTuiView)
                    results[name] = (view.presenter.codegen.text.split("\n"), view.line_texts())

        asyncio.run(main())
        assert set(results) == set(FUNCTIONS)
        for name, (expected, drawn) in results.items():
            assert len(drawn) > 10, name
            assert drawn == expected, name


if __name__ == "__main__":
    unittest.main()
