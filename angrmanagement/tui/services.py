"""
UI services of the terminal frontend.

:class:`TuiServices` asks the user through modal screens. A worker thread that asks (the load job, say) waits for the
answer; the UI thread cannot wait, so the frontend's own code asks through the ``async`` methods (``await
services.ask_question(...)``) or the ``*_async`` UIServices methods instead, and a synchronous question on the UI
thread gets its default answer and a notice saying so. With ``interactive`` off, every question gets its default and
loads use the default options, as in a headless process.

A question has two answers that nobody chose: the *default*, given when nobody is asked at all, and the *cancel*
answer, given when the user cancels the screen or the app shuts down while it is up. They differ for the load and
analysis options: nobody asked means "use the defaults", a cancel means "do not load" or "do not analyse", as with
the Qt dialogs.
"""

from __future__ import annotations

import asyncio
import logging
import webbrowser
from typing import TYPE_CHECKING, Any

from angrmanagement.data.load_options import (
    LoadOptions,
    LoadSelection,
    build_load_options,
    confirm_symbol_download,
    default_selection,
)
from angrmanagement.logic import GlobalInfo
from angrmanagement.present.dialogs import encryption_key_form, function_actions, function_info_form, key_of_form

from .executor import Deferred, TextualExecutor
from .screens import FilePickerScreen, MessageScreen, PromptScreen, QuestionScreen
from .screens.analysis_options import AnalysisOptionsScreen
from .screens.form import FormScreen
from .screens.load_binary import LoadBinaryScreen

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    import cle
    from angr.knowledge_plugins.functions import Function
    from textual.app import App
    from textual.screen import Screen

    from angrmanagement.data.analysis_options import AnalysesConfiguration
    from angrmanagement.logic.ui_services import MessageLevel
    from angrmanagement.present.forms import Form

_l = logging.getLogger(__name__)

_SEVERITIES = {"info": "information", "warning": "warning", "critical": "error"}

#: ``cancelled`` of :meth:`TuiServices._ask_sync` when a cancel gives the default answer
_DEFAULT: Any = object()


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

    def _ask_sync(
        self,
        make_screen: Callable[[], Screen],
        default: Any,
        cancelled: Any = _DEFAULT,
        then: Callable[[Any], Any] | None = None,
    ) -> Any:
        """
        Show a screen and return its answer. From a worker thread the thread waits; on the UI thread a call that a
        waiting worker scheduled is answered when the screen is dismissed; any other call on the UI thread gets
        ``default`` at once.

        A call that a waiting worker scheduled returns a :class:`Deferred`, not the answer, so a caller that needs to
        do something with the answer passes ``then`` rather than looking at what comes back.

        :param default:     The answer when nobody can be asked.
        :param cancelled:   The answer when the user cancels the screen (it dismisses with None) or the app shuts
                            down while the screen is up; ``default`` unless given.
        :param then:        Turns the answer (any of the three) into what the call returns.
        """
        if cancelled is _DEFAULT:
            cancelled = default
        convert: Callable[[Any], Any] = then if then is not None else (lambda answer: answer)
        if not self.interactive or not self._running:
            return convert(default)
        executor = self._executor()
        if executor is None:
            return convert(default)
        if executor.closed:
            return convert(cancelled)
        if not executor.is_ui_thread():
            answer = executor.schedule(self._ask_sync, (make_screen, default, cancelled))
            # None is what a call gets that the executor could not deliver because the app shut down
            return convert(cancelled if answer is None else answer)
        if executor.serving_blocking_call:
            # only the call the worker scheduled may wait; questions it asks in turn get their default
            executor.serving_blocking_call = False
            loop = asyncio.get_running_loop()
            future: asyncio.Future = loop.create_future()

            def done(result: Any) -> None:
                if not future.done():
                    future.set_result(cancelled if result is None else result)

            assert self.app is not None
            self.app.push_screen(make_screen(), callback=done)
            if then is None:
                return Deferred(future, cancelled)

            async def converted() -> Any:
                return then(await future)

            return Deferred(asyncio.ensure_future(converted()), then(cancelled))
        _l.warning("A question was asked on the UI thread and cannot wait; answering %r", default)
        self.toast(f"A question could not be shown here; answered {default!r}.", "warning")
        return convert(default)

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

    def prompt_password(self, title: str, label: str, default: str = "") -> str | None:
        return self._ask_sync(lambda: PromptScreen(title, label, default, password=True), None)

    def prompt_multiline_text(self, title: str, label: str, default: str = "") -> str | None:
        from angrmanagement.present.forms import Form, FormField  # pylint:disable=import-outside-toplevel

        form = Form(title, [FormField("text", "", "multiline", default)], text=label)
        return self._ask_sync(
            lambda: FormScreen(form), None, then=lambda values: None if values is None else values["text"]
        )

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

    def ask_form_async(self, form: Form, callback: Callable[[dict[str, Any] | None], None]) -> None:
        self._ask_then(FormScreen(form), None, callback)

    def pick_open_files_async(
        self, caption: str, directory: str, name_filter: str, multiple: bool, callback: Callable[[list[str]], None]
    ) -> None:
        self._ask_then(FilePickerScreen(caption, directory, name_filter, "open", multiple), [], callback)

    def pick_save_file_async(
        self, caption: str, directory: str, name_filter: str, callback: Callable[[str | None], None]
    ) -> None:
        self._ask_then(FilePickerScreen(caption, directory, name_filter, "save"), None, callback)

    def pick_directory_async(self, caption: str, directory: str, callback: Callable[[str | None], None]) -> None:
        self._ask_then(FilePickerScreen(caption, directory, "", "directory"), None, callback)

    def popup_menu(self, menu: Any) -> None:
        if not self._running:
            return
        app: Any = self.app
        executor = self._executor()
        if executor is not None and not executor.is_ui_thread():
            executor.schedule_async(self.popup_menu, (menu,))
            return
        # where the mouse last was, or the middle of the screen
        offset = getattr(app, "mouse_position", None) or (app.size.width // 3, app.size.height // 3)
        app.open_context_menu(menu, tuple(offset))

    def pick_open_files(self, caption: str, directory: str, name_filter: str, multiple: bool) -> list[str]:
        return self._ask_sync(
            lambda: FilePickerScreen(caption, directory, name_filter, "open", multiple),
            [],
            then=lambda files: files or [],
        )

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
        """The Load a new binary screen over the partial load; the default options when nobody can be asked."""
        selection = default_selection(
            partial_ld,
            suggested_backend=suggested_backend,
            suggested_os_name=suggested_os_name,
            suggested_main_opts=suggested_main_opts,
            suggested_original_backend=suggested_original_backend,
        )

        def build(chosen: LoadSelection | None) -> LoadOptions | None:
            if chosen is None:
                return None
            return build_load_options(
                partial_ld,
                chosen,
                suggested_main_opts=suggested_main_opts,
                suggested_main_filename=suggested_main_filename,
                confirm_symbol_download=confirm_symbol_download,
            )

        if not self.interactive or not self._running:
            if selection is None:
                self.message(
                    "critical", "Load binary", "No architecture matches this binary; it cannot be loaded here."
                )
            return build(selection)

        def make_screen() -> Screen:
            return LoadBinaryScreen(
                partial_ld,
                suggested_backend=suggested_backend,
                suggested_os_name=suggested_os_name,
                suggested_main_opts=suggested_main_opts,
                suggested_original_backend=suggested_original_backend,
                suggested_main_filename=suggested_main_filename,
            )

        # a cancel is None, and the load job stops, as it does when the Qt load dialog is cancelled
        return self._ask_sync(make_screen, selection, cancelled=None, then=build)

    def encryption_key(self, filename: str, prompt: str = "", initial_text: str = "") -> bytes | None:
        """The Set an encryption key screen: the key in any of the formats the Qt dialog reads."""
        text = prompt or f"Set the encryption key for {filename}."
        # the load job asks for the key from the worker thread, so the answer can come back as a Deferred
        return self._ask_sync(lambda: FormScreen(encryption_key_form(text, initial_text)), None, then=key_of_form)

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
        """The Run Analysis screen; the options change in place, and a cancel runs nothing."""
        return self._ask_sync(
            lambda: AnalysisOptionsScreen(configuration),
            True,
            cancelled=None,
            then=lambda run: configuration if run else None,
        )

    async def ask_analysis_options(self, configuration: AnalysesConfiguration) -> AnalysesConfiguration | None:
        """Ask which analyses to run, on the UI loop."""
        run = await self.ask(AnalysisOptionsScreen(configuration), True)
        return configuration if run else None

    def function_info(self, function: Function) -> None:
        """The Function dialog: the facts the Qt dialog lists, and its four actions."""
        if not self._running:
            return
        app: Any = self.app
        workspace = app.workspace

        def show_xrefs() -> None:
            app.show_xrefs(addr=function.addr, dst_addr=function.addr, xrefs_manager=workspace.main_instance.kb.xrefs)

        app.push_screen(FormScreen(function_info_form(function, function_actions(workspace, function, show_xrefs))))

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
