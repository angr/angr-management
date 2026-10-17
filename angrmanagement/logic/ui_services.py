"""
Asking the user things, without depending on a frontend.

Code outside the frontends reaches the user through ``GlobalInfo.ui_services``, an object implementing
:class:`UIServices`. The Qt frontend installs ``QtServices`` (angrmanagement.ui.qt_services); headless code gets
:class:`HeadlessServices`, which logs messages and answers every question with its default. Call these on the UI
thread, through ``gui_thread_schedule`` when on another thread.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Literal, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    import cle
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.data.analysis_options import AnalysesConfiguration
    from angrmanagement.data.load_options import LoadOptions
    from angrmanagement.present.forms import Form
    from angrmanagement.present.menus import Menu

_l = logging.getLogger(__name__)

MessageLevel = Literal["info", "warning", "critical"]


class UIServices(Protocol):
    """The questions and notices the core can put to the user."""

    def message(self, level: MessageLevel, title: str, text: str) -> None:
        """Tell the user something and wait until they acknowledge it."""
        raise NotImplementedError

    def question(self, title: str, text: str, buttons: Sequence[str], default: str) -> str:
        """Ask the user to pick one of ``buttons``; returns the one picked, or ``default`` when there is no answer."""
        raise NotImplementedError

    def notify(self, level: MessageLevel, title: str, text: str) -> None:
        """Tell the user something without waiting: the caller carries on while the notice is shown."""
        raise NotImplementedError

    def question_async(
        self, title: str, text: str, buttons: Sequence[str], default: str, callback: Callable[[str], None]
    ) -> None:
        """
        Ask like :meth:`question` without waiting; ``callback`` gets the button picked, or ``default``, later, on
        the UI thread.
        """
        raise NotImplementedError

    def prompt_text_async(self, title: str, label: str, default: str, callback: Callable[[str | None], None]) -> None:
        """Ask like :meth:`prompt_text` without waiting; ``callback`` gets the answer later, on the UI thread."""
        raise NotImplementedError

    def pick_open_files_async(
        self, caption: str, directory: str, name_filter: str, multiple: bool, callback: Callable[[list[str]], None]
    ) -> None:
        """Ask like :meth:`pick_open_files` without waiting; ``callback`` gets the files later, on the UI thread."""
        raise NotImplementedError

    def pick_save_file_async(
        self, caption: str, directory: str, name_filter: str, callback: Callable[[str | None], None]
    ) -> None:
        """Ask like :meth:`pick_save_file` without waiting; ``callback`` gets the path later, on the UI thread."""
        raise NotImplementedError

    def ask_form_async(self, form: Form, callback: Callable[[dict[str, Any] | None], None]) -> None:
        """
        Show a form (angrmanagement.present.forms) without waiting; ``callback`` gets its values by key, or None if
        the user cancelled, later, on the UI thread.
        """
        raise NotImplementedError

    def pick_directory_async(self, caption: str, directory: str, callback: Callable[[str | None], None]) -> None:
        """Ask like :meth:`pick_directory` without waiting; ``callback`` gets the directory later, on the UI thread."""
        raise NotImplementedError

    def popup_menu(self, menu: Menu) -> None:
        """Show a context menu (angrmanagement.present.menus.Menu) where the user is; its entries run when picked."""
        raise NotImplementedError

    def analysis_options(self, workspace, configuration: AnalysesConfiguration) -> AnalysesConfiguration | None:
        """
        Let the user choose which analyses to run and with what options, editing ``configuration`` in place.

        :returns: The configuration to run, or None if the user cancelled.
        """
        raise NotImplementedError

    def function_info(self, function: Function) -> None:
        """Show what is known about a function."""
        raise NotImplementedError

    def prompt_text(self, title: str, label: str, default: str = "") -> str | None:
        """Ask for a line of text; None if the user cancelled."""
        raise NotImplementedError

    def prompt_password(self, title: str, label: str, default: str = "") -> str | None:
        """Ask for a line of text that is not shown as it is typed; None if the user cancelled."""
        raise NotImplementedError

    def prompt_multiline_text(self, title: str, label: str, default: str = "") -> str | None:
        """Ask for text of several lines; None if the user cancelled."""
        raise NotImplementedError

    def pick_open_files(self, caption: str, directory: str, name_filter: str, multiple: bool) -> list[str]:
        """
        Ask for existing files to open; an empty list if the user cancelled.

        ``name_filter`` is in Qt's format, such as ``"Object Files (*.a *.o);;All files (*)"``.
        """
        raise NotImplementedError

    def pick_save_file(self, caption: str, directory: str, name_filter: str) -> str | None:
        """Ask for a file to save to; None if the user cancelled. ``directory`` may include a file name."""
        raise NotImplementedError

    def pick_directory(self, caption: str, directory: str) -> str | None:
        """Ask for a directory; None if the user cancelled."""
        raise NotImplementedError

    def load_binary_options(
        self,
        partial_ld: cle.Loader,
        suggested_backend: type[cle.Backend] | None = None,
        suggested_os_name: str | None = None,
        suggested_main_opts: dict | None = None,
        suggested_original_backend: type[cle.Backend] | None = None,
        suggested_main_filename: str | None = None,
    ) -> LoadOptions | None:
        """Ask how to load a binary that ``partial_ld`` has partially loaded; None if the user cancelled."""
        raise NotImplementedError

    def encryption_key(self, filename: str, prompt: str = "", initial_text: str = "") -> bytes | None:
        """
        Ask for the key of the encrypted file ``filename``; None if the user gave none.

        ``prompt`` explains what the key is for, and ``initial_text`` pre-fills the answer (a key in hex).
        """
        raise NotImplementedError

    def clipboard_text(self) -> str:
        """The text on the clipboard."""
        raise NotImplementedError

    def set_clipboard_text(self, text: str) -> None:
        """Put text on the clipboard."""
        raise NotImplementedError

    def open_url(self, url: str) -> bool:
        """Open a URL in the user's browser; whether that worked."""
        raise NotImplementedError


class HeadlessServices:
    """
    The UI services of a process with nobody to ask.

    Messages are logged at their level; questions get their default answer; pickers, prompts and forms return
    nothing; the analyses run with the options they are given;
    binaries load with the options the load dialog would preselect; there is no encryption key. The clipboard is a
    string held in this object.
    """

    _LOG_LEVELS = {"info": logging.INFO, "warning": logging.WARNING, "critical": logging.CRITICAL}

    def __init__(self) -> None:
        self._clipboard = ""

    def message(self, level: MessageLevel, title: str, text: str) -> None:
        _l.log(self._LOG_LEVELS.get(level, logging.INFO), "%s: %s", title, text)

    def question(self, title: str, text: str, buttons: Sequence[str], default: str) -> str:
        _l.info("%s: %s [%s] -> %s", title, text, "/".join(buttons), default)
        return default

    def notify(self, level: MessageLevel, title: str, text: str) -> None:
        self.message(level, title, text)

    def question_async(
        self, title: str, text: str, buttons: Sequence[str], default: str, callback: Callable[[str], None]
    ) -> None:
        callback(self.question(title, text, buttons, default))

    def prompt_text_async(self, title: str, label: str, default: str, callback: Callable[[str | None], None]) -> None:
        callback(self.prompt_text(title, label, default))

    def pick_open_files_async(
        self, caption: str, directory: str, name_filter: str, multiple: bool, callback: Callable[[list[str]], None]
    ) -> None:
        callback(self.pick_open_files(caption, directory, name_filter, multiple))

    def pick_save_file_async(
        self, caption: str, directory: str, name_filter: str, callback: Callable[[str | None], None]
    ) -> None:
        callback(self.pick_save_file(caption, directory, name_filter))

    def ask_form_async(  # pylint:disable=unused-argument
        self, form: Form, callback: Callable[[dict[str, Any] | None], None]
    ) -> None:
        # nobody can confirm the form, so nothing it would do happens
        callback(None)

    def pick_directory_async(self, caption: str, directory: str, callback: Callable[[str | None], None]) -> None:
        callback(self.pick_directory(caption, directory))

    def popup_menu(self, menu: Menu) -> None:  # pylint:disable=unused-argument
        # nobody can pick an entry
        return

    def analysis_options(  # pylint:disable=unused-argument
        self, workspace, configuration: AnalysesConfiguration
    ) -> AnalysesConfiguration | None:
        return configuration

    def function_info(self, function: Function) -> None:
        _l.info("Function %s at %#x", function.name, function.addr)

    def prompt_text(self, title: str, label: str, default: str = "") -> str | None:  # pylint:disable=unused-argument
        return None

    def prompt_password(self, title: str, label: str, default: str = "") -> str | None:  # pylint:disable=unused-argument
        return None

    def prompt_multiline_text(  # pylint:disable=unused-argument
        self, title: str, label: str, default: str = ""
    ) -> str | None:
        return None

    def pick_open_files(  # pylint:disable=unused-argument
        self, caption: str, directory: str, name_filter: str, multiple: bool
    ) -> list[str]:
        return []

    def pick_save_file(  # pylint:disable=unused-argument
        self, caption: str, directory: str, name_filter: str
    ) -> str | None:
        return None

    def pick_directory(self, caption: str, directory: str) -> str | None:  # pylint:disable=unused-argument
        return None

    def load_binary_options(
        self,
        partial_ld: cle.Loader,
        suggested_backend: type[cle.Backend] | None = None,
        suggested_os_name: str | None = None,
        suggested_main_opts: dict | None = None,
        suggested_original_backend: type[cle.Backend] | None = None,
        suggested_main_filename: str | None = None,
    ) -> LoadOptions | None:
        from angrmanagement.data.load_options import default_load_options  # pylint:disable=import-outside-toplevel

        return default_load_options(
            partial_ld,
            suggested_backend=suggested_backend,
            suggested_os_name=suggested_os_name,
            suggested_main_opts=suggested_main_opts,
            suggested_original_backend=suggested_original_backend,
            suggested_main_filename=suggested_main_filename,
        )

    def encryption_key(  # pylint:disable=unused-argument
        self, filename: str, prompt: str = "", initial_text: str = ""
    ) -> bytes | None:
        return None

    def clipboard_text(self) -> str:
        return self._clipboard

    def set_clipboard_text(self, text: str) -> None:
        self._clipboard = text

    def open_url(self, url: str) -> bool:
        _l.info("Not opening %s: there is no browser in a headless process", url)
        return False
