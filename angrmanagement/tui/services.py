"""
UI services of the terminal frontend.

:class:`TuiServices` asks the user through modal screens. A worker thread that asks (the load job, say) waits for the
answer; the UI thread cannot wait, so the frontend's own code asks through the ``async`` methods (``await
services.ask_question(...)``) instead, and a synchronous question on the UI thread gets its default answer. With
``interactive`` off, every question gets its default and loads use the default options, as in a headless process.
"""

from __future__ import annotations

import asyncio
import logging
import webbrowser
from typing import TYPE_CHECKING, Any

from angrmanagement.data.load_options import build_load_options, default_selection
from angrmanagement.logic import GlobalInfo

from .executor import Deferred, TextualExecutor
from .screens import ChecklistScreen, FilePickerScreen, InfoScreen, MessageScreen, PromptScreen, QuestionScreen

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    import cle
    from angr.knowledge_plugins.functions import Function
    from textual.app import App
    from textual.screen import Screen

    from angrmanagement.data.analysis_options import AnalysesConfiguration
    from angrmanagement.data.load_options import LoadOptions
    from angrmanagement.logic.ui_services import MessageLevel

_l = logging.getLogger(__name__)

_SEVERITIES = {"info": "information", "warning": "warning", "critical": "error"}


def function_info_rows(function: Function) -> list[tuple[str, str]]:
    """What the function information screen lists."""
    rows = [
        ("Name", function.name),
        ("Address", f"{function.addr:#x}"),
        ("Size", str(function.size)),
        ("Blocks", str(len(function.block_addrs_set))),
        ("Binary", function.binary_name or ""),
        ("Returning", str(function.returning)),
        ("Calling convention", str(function.calling_convention)),
        ("Prototype", str(function.prototype)),
        ("PLT stub", str(function.is_plt)),
        ("SimProcedure", str(function.is_simprocedure)),
        ("Syscall", str(function.is_syscall)),
        ("Alignment", str(function.is_alignment)),
    ]
    if function.tags:
        rows.append(("Tags", ", ".join(function.tags)))
    return rows


class TuiServices:
    """UIServices over Textual modal screens."""

    def __init__(self, app: App | None = None) -> None:
        self.app = app
        self.interactive = True
        self._clipboard = ""

    #
    # Plumbing
    #

    @property
    def _running(self) -> bool:
        return self.app is not None and self.app.is_running

    @staticmethod
    def _executor() -> TextualExecutor | None:
        executor = GlobalInfo.executor
        return executor if isinstance(executor, TextualExecutor) else None

    def _ask_sync(self, make_screen: Callable[[], Screen], default: Any) -> Any:
        """
        Show a screen and return its answer. From a worker thread the thread waits; on the UI thread a call that a
        waiting worker scheduled is answered when the screen is dismissed; any other call on the UI thread gets
        ``default`` at once.
        """
        if not self.interactive or not self._running:
            return default
        executor = self._executor()
        if executor is None:
            return default
        if not executor.is_ui_thread():
            return executor.schedule(self._ask_sync, (make_screen, default))
        if executor.serving_blocking_call:
            # only the call the worker scheduled may wait; questions it asks in turn get their default
            executor.serving_blocking_call = False
            loop = asyncio.get_running_loop()
            future: asyncio.Future = loop.create_future()

            def done(result: Any) -> None:
                if not future.done():
                    future.set_result(default if result is None and default is not None else result)

            assert self.app is not None
            self.app.push_screen(make_screen(), callback=done)
            return Deferred(future, default)
        _l.warning("A question was asked on the UI thread and cannot wait; answering %r", default)
        return default

    async def ask(self, screen: Screen, default: Any = None) -> Any:
        """Show ``screen`` and wait for its answer; for code on the UI loop."""
        if not self.interactive or not self._running:
            return default
        assert self.app is not None
        future: asyncio.Future = asyncio.get_running_loop().create_future()

        def done(result: Any) -> None:
            if not future.done():
                future.set_result(result)

        self.app.push_screen(screen, callback=done)
        return await future

    #
    # UIServices
    #

    def message(self, level: MessageLevel, title: str, text: str) -> None:
        if not self.interactive or not self._running:
            _l.log(
                {"warning": logging.WARNING, "critical": logging.CRITICAL}.get(level, logging.INFO),
                "%s: %s",
                title,
                text,
            )
            return
        executor = self._executor()
        if executor is not None and (not executor.is_ui_thread() or executor.serving_blocking_call):
            self._ask_sync(lambda: MessageScreen(level, title, text), None)
            return
        # on the UI thread nothing can wait for the acknowledgement; the notice stays until dismissed
        self.notify(level, title, text)

    def notify(self, level: MessageLevel, title: str, text: str) -> None:
        if not self._running:
            _l.info("%s: %s", title, text)
            return
        assert self.app is not None
        executor = self._executor()
        if executor is not None and not executor.is_ui_thread():
            executor.schedule_async(self.notify, (level, title, text))
            return
        self.app.push_screen(MessageScreen(level, title, text))

    def toast(self, text: str, level: MessageLevel = "info", timeout: float = 5) -> None:
        """A short notice in the corner that goes away by itself."""
        if self._running:
            assert self.app is not None
            severity: Any = _SEVERITIES.get(level, "information")
            self.app.notify(text, severity=severity, timeout=timeout)

    def question(self, title: str, text: str, buttons: Sequence[str], default: str) -> str:
        return self._ask_sync(lambda: QuestionScreen(title, text, buttons, default), default)

    def question_async(
        self, title: str, text: str, buttons: Sequence[str], default: str, callback: Callable[[str], None]
    ) -> None:
        if not self.interactive or not self._running:
            callback(default)
            return
        assert self.app is not None
        self.app.push_screen(
            QuestionScreen(title, text, buttons, default), callback=lambda r: callback(r if r is not None else default)
        )

    def prompt_text(self, title: str, label: str, default: str = "") -> str | None:
        return self._ask_sync(lambda: PromptScreen(title, label, default), None)

    def _ask_then(self, screen: Screen, default: Any, callback: Callable[[Any], None]) -> None:
        if not self.interactive or not self._running:
            callback(default)
            return
        assert self.app is not None
        executor = self._executor()
        if executor is not None and not executor.is_ui_thread():
            executor.schedule_async(self._ask_then, (screen, default, callback))
            return
        self.app.push_screen(screen, callback=lambda r: callback(default if r is None and default is not None else r))

    def prompt_text_async(self, title: str, label: str, default: str, callback: Callable[[str | None], None]) -> None:
        self._ask_then(PromptScreen(title, label, default), None, callback)

    def pick_open_files_async(
        self, caption: str, directory: str, name_filter: str, multiple: bool, callback: Callable[[list[str]], None]
    ) -> None:
        self._ask_then(FilePickerScreen(caption, directory, name_filter, "open", multiple), [], callback)

    def pick_save_file_async(
        self, caption: str, directory: str, name_filter: str, callback: Callable[[str | None], None]
    ) -> None:
        self._ask_then(FilePickerScreen(caption, directory, name_filter, "save"), None, callback)

    def pick_open_files(self, caption: str, directory: str, name_filter: str, multiple: bool) -> list[str]:
        return self._ask_sync(lambda: FilePickerScreen(caption, directory, name_filter, "open", multiple), []) or []

    def pick_save_file(self, caption: str, directory: str, name_filter: str) -> str | None:
        return self._ask_sync(lambda: FilePickerScreen(caption, directory, name_filter, "save"), None)

    def pick_directory(self, caption: str, directory: str) -> str | None:
        return self._ask_sync(lambda: FilePickerScreen(caption, directory, "", "directory"), None)

    def load_binary_options(
        self,
        partial_ld: cle.Loader,
        suggested_backend: type[cle.Backend] | None = None,
        suggested_os_name: str | None = None,
        suggested_main_opts: dict | None = None,
        suggested_original_backend: type[cle.Backend] | None = None,
        suggested_main_filename: str | None = None,
    ) -> Any:
        """The default load options, after the user confirms them and the two library switches."""
        selection = default_selection(
            partial_ld,
            suggested_backend=suggested_backend,
            suggested_os_name=suggested_os_name,
            suggested_main_opts=suggested_main_opts,
            suggested_original_backend=suggested_original_backend,
        )
        if selection is None:
            self.message("critical", "Load binary", "No architecture matches this binary; it cannot be loaded here.")
            return None

        def build() -> LoadOptions:
            return build_load_options(
                partial_ld,
                selection,
                suggested_main_opts=suggested_main_opts,
                suggested_main_filename=suggested_main_filename,
            )

        if not self.interactive or not self._running:
            return build()
        main = partial_ld.main_object
        text = (
            f"File:    {getattr(main, 'binary', '') or suggested_main_filename or ''}\n"
            f"Backend: {selection.backend}\n"
            f"Arch:    {getattr(selection.arch, 'name', selection.arch)}\n"
            f"OS:      {selection.simos_name}"
        )
        items = [("Load libraries (auto_load_libs)", selection.auto_load_libs), ("Load debug info", True)]

        def make_screen() -> Screen:
            return ChecklistScreen("Load a binary", text, items, ok="Load")

        result = self._ask_sync(make_screen, [selection.auto_load_libs, selection.load_debug_info])
        if isinstance(result, Deferred):
            # scheduled from the load job: finish building once the user answered
            outer = result

            async def finish() -> Any:
                answer = await outer.future
                if answer is None:
                    return None
                selection.auto_load_libs, selection.load_debug_info = answer
                return build()

            return Deferred(asyncio.ensure_future(finish()), None)
        if result is None:
            return None
        selection.auto_load_libs, selection.load_debug_info = result
        return build()

    def encryption_key(self, filename: str, prompt: str = "", initial_text: str = "") -> bytes | None:
        answer = self.prompt_text(
            "Encryption key", prompt or f"The encryption key of {filename}, in hex:", initial_text
        )
        if not answer:
            return None
        try:
            return bytes.fromhex(answer.strip())
        except ValueError:
            return answer.encode()

    def clipboard_text(self) -> str:
        return self._clipboard

    def set_clipboard_text(self, text: str) -> None:
        self._clipboard = text
        if self._running:
            assert self.app is not None
            # OSC 52; the internal buffer above serves pastes inside the app on terminals that ignore it
            self.app.copy_to_clipboard(text)

    def open_url(self, url: str) -> bool:
        if self._running:
            assert self.app is not None
            # a hyperlink (OSC 8) the user can click if the browser does not open
            self.app.notify(f"[link={url}]{url}[/link]", title="Opening", timeout=10)
        try:
            return webbrowser.open(url)
        except webbrowser.Error:
            return False

    def analysis_options(self, workspace, configuration: AnalysesConfiguration) -> AnalysesConfiguration | None:  # pylint:disable=unused-argument
        items = [(a.display_name or a.name, a.enabled) for a in configuration]
        result = self._ask_sync(lambda: analyses_screen(configuration), [enabled for _, enabled in items])
        if result is None:
            return None
        for analysis, enabled in zip(configuration, result, strict=False):
            analysis.enabled = enabled
        return configuration

    async def ask_analysis_options(self, configuration: AnalysesConfiguration) -> AnalysesConfiguration | None:
        """Ask which analyses to run, on the UI loop."""
        result = await self.ask(analyses_screen(configuration), [a.enabled for a in configuration])
        if result is None:
            return None
        for analysis, enabled in zip(configuration, result, strict=False):
            analysis.enabled = enabled
        return configuration

    def function_info(self, function: Function) -> None:
        if self._running:
            assert self.app is not None
            self.app.push_screen(InfoScreen(f"Function {function.name}", function_info_rows(function)))

    #
    # Asking from the UI loop
    #

    async def ask_question(self, title: str, text: str, buttons: Sequence[str], default: str) -> str:
        answer = await self.ask(QuestionScreen(title, text, buttons, default), default)
        return answer if answer is not None else default

    async def ask_text(self, title: str, label: str, default: str = "") -> str | None:
        return await self.ask(PromptScreen(title, label, default), None)

    async def ask_open_file(self, caption: str, directory: str, name_filter: str = "") -> str | None:
        paths = await self.ask(FilePickerScreen(caption, directory, name_filter, "open"), [])
        return paths[0] if paths else None

    async def ask_save_file(self, caption: str, directory: str, name_filter: str = "") -> str | None:
        return await self.ask(FilePickerScreen(caption, directory, name_filter, "save"), None)


def analyses_screen(configuration: AnalysesConfiguration) -> ChecklistScreen:
    return ChecklistScreen(
        "Run analysis",
        "The analyses to run, with their default options.",
        [(a.display_name or a.name, a.enabled) for a in configuration],
        ok="Run",
    )
