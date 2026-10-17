"""The UI services of the Qt frontend: message boxes, input dialogs, file dialogs, the clipboard and the browser."""

# pylint: disable=no-self-use

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog, QLineEdit, QMessageBox

from angrmanagement.data.load_options import LoadOptions
from angrmanagement.logic import GlobalInfo

from .dialogs.analysis_options import AnalysisOptionsDialog

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    import cle
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.data.analysis_options import AnalysesConfiguration
    from angrmanagement.logic.ui_services import MessageLevel
    from angrmanagement.present.forms import Form
    from angrmanagement.present.menus import Menu

# looked up on QMessageBox when called, so that a test can replace QMessageBox.warning and see the call
_MESSAGE_BOXES = {
    "info": "information",
    "warning": "warning",
    "critical": "critical",
}
_MESSAGE_ICONS = {
    "info": QMessageBox.Icon.Information,
    "warning": QMessageBox.Icon.Warning,
    "critical": QMessageBox.Icon.Critical,
}
_STANDARD_BUTTONS = {
    "Yes": QMessageBox.StandardButton.Yes,
    "No": QMessageBox.StandardButton.No,
    "Ok": QMessageBox.StandardButton.Ok,
    "OK": QMessageBox.StandardButton.Ok,
    "Cancel": QMessageBox.StandardButton.Cancel,
}


def _modal_parent():
    """The dialog the user is in, if any: a message from inside a dialog stays in front of it."""
    return QApplication.activeModalWidget()


def _window_parent():
    return _modal_parent() or GlobalInfo.main_window


class QtServices:
    """
    UIServices for the Qt frontend.

    Call the methods on the GUI thread. message() and the file pickers open their dialogs over the dialog the user is
    in, or with no parent, as the core's own message boxes and file dialogs had none. question(), the prompts and
    forms are parented on that dialog or the main window, so they stay in front of it.
    """

    def message(self, level: MessageLevel, title: str, text: str) -> None:
        getattr(QMessageBox, _MESSAGE_BOXES.get(level, "information"))(_window_parent(), title, text)

    def notify(self, level: MessageLevel, title: str, text: str) -> None:
        box = QMessageBox(GlobalInfo.main_window)
        box.setIcon(_MESSAGE_ICONS.get(level, QMessageBox.Icon.Information))
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        # shown without blocking: whoever reported this carries on, and nothing waits behind the box
        box.show()

    def question_async(
        self, title: str, text: str, buttons: Sequence[str], default: str, callback: Callable[[str], None]
    ) -> None:
        box = QMessageBox(
            QMessageBox.Icon.Question, title, text, QMessageBox.StandardButton.NoButton, GlobalInfo.main_window
        )
        by_result: dict[int, str] = {}
        if all(caption in _STANDARD_BUTTONS for caption in buttons):
            # standard buttons, so that finished() reports which one was pressed
            for caption in buttons:
                standard = _STANDARD_BUTTONS[caption]
                box.addButton(standard)
                by_result[int(standard.value)] = caption
                if caption == default:
                    box.setDefaultButton(standard)
        else:
            for idx, caption in enumerate(buttons):
                button = box.addButton(caption, QMessageBox.ButtonRole.AcceptRole)
                by_result[idx] = caption
                if caption == default:
                    box.setDefaultButton(button)
        box.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        def on_finished(result: int) -> None:
            callback(by_result.get(int(result), default))

        box.finished.connect(on_finished)
        # modeless: a modal box here would block whoever waits on the job queue (e.g., a headless test) forever
        box.open()

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

    def pick_directory_async(self, caption: str, directory: str, callback: Callable[[str | None], None]) -> None:
        callback(self.pick_directory(caption, directory))

    def popup_menu(self, menu: Menu) -> None:
        from PySide6.QtGui import QCursor  # pylint:disable=import-outside-toplevel

        from .menus.menu import to_qmenu  # pylint:disable=import-outside-toplevel

        to_qmenu(menu, _window_parent()).exec_(QCursor.pos())

    def analysis_options(self, workspace, configuration: AnalysesConfiguration) -> AnalysesConfiguration | None:
        dlg = AnalysisOptionsDialog(configuration, workspace, GlobalInfo.main_window)
        dlg.setModal(True)
        if not dlg.exec_():
            return None
        return configuration

    def function_info(self, function: Function) -> None:
        from .dialogs.function import FunctionDialog  # pylint:disable=import-outside-toplevel

        FunctionDialog(function).exec_()

    def question(self, title: str, text: str, buttons: Sequence[str], default: str) -> str:
        if all(caption in _STANDARD_BUTTONS for caption in buttons):
            # the static question box with standard buttons, as the message boxes it replaces were
            flags = QMessageBox.StandardButton.NoButton
            for caption in buttons:
                flags |= _STANDARD_BUTTONS[caption]
            pressed = QMessageBox.question(
                _window_parent(),
                title,
                text,
                flags,
                _STANDARD_BUTTONS.get(default, QMessageBox.StandardButton.NoButton),
            )
            for caption in buttons:
                if _STANDARD_BUTTONS[caption] == pressed:
                    return caption
            return default
        box = QMessageBox(_window_parent())
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle(title)
        box.setText(text)
        by_button = {}
        for caption in buttons:
            button = box.addButton(caption, QMessageBox.ButtonRole.AcceptRole)
            by_button[button] = caption
            if caption == default:
                box.setDefaultButton(button)
        box.exec_()
        return by_button.get(box.clickedButton(), default)

    def prompt_text(self, title: str, label: str, default: str = "") -> str | None:
        text, ok = QInputDialog.getText(_window_parent(), title, label, QLineEdit.EchoMode.Normal, default)
        return text if ok else None

    def prompt_password(self, title: str, label: str, default: str = "") -> str | None:
        text, ok = QInputDialog.getText(_window_parent(), title, label, QLineEdit.EchoMode.Password, default)
        return text if ok else None

    def prompt_multiline_text(self, title: str, label: str, default: str = "") -> str | None:
        text, ok = QInputDialog.getMultiLineText(_window_parent(), title, label, default)
        return text if ok else None

    def ask_form_async(self, form: Form, callback: Callable[[dict[str, Any] | None], None]) -> None:
        from .dialogs.form import FormDialog  # pylint:disable=import-outside-toplevel

        dialog = FormDialog(form, _window_parent())
        dialog.exec_()
        callback(dialog.values)

    def pick_open_files(self, caption: str, directory: str, name_filter: str, multiple: bool) -> list[str]:
        if multiple:
            filenames, _ = QFileDialog.getOpenFileNames(_modal_parent(), caption, directory, name_filter)
            return list(filenames)
        filename, _ = QFileDialog.getOpenFileName(_modal_parent(), caption, directory, name_filter)
        return [filename] if filename else []

    def pick_save_file(self, caption: str, directory: str, name_filter: str) -> str | None:
        filename, _ = QFileDialog.getSaveFileName(_modal_parent(), caption, directory, name_filter)
        return filename or None

    def pick_directory(self, caption: str, directory: str) -> str | None:
        return QFileDialog.getExistingDirectory(_modal_parent(), caption, directory) or None

    def load_binary_options(
        self,
        partial_ld: cle.Loader,
        suggested_backend: type[cle.Backend] | None = None,
        suggested_os_name: str | None = None,
        suggested_main_opts: dict | None = None,
        suggested_original_backend: type[cle.Backend] | None = None,
        suggested_main_filename: str | None = None,
    ) -> LoadOptions | None:
        from .dialogs.load_binary import LoadBinary  # pylint:disable=import-outside-toplevel

        load_options, simos = LoadBinary.run(
            partial_ld,
            suggested_backend=suggested_backend,
            suggested_os_name=suggested_os_name,
            suggested_main_opts=suggested_main_opts,
            suggested_original_backend=suggested_original_backend,
            suggested_main_filename=suggested_main_filename,
        )
        if load_options is None:
            return None
        return LoadOptions(load_options, simos)

    def encryption_key(self, filename: str, prompt: str = "", initial_text: str = "") -> bytes | None:
        from .dialogs.set_encryption_key import SetEncryptionKeyDialog  # pylint:disable=import-outside-toplevel

        dialog = SetEncryptionKeyDialog(
            prompt_msg=prompt or f"Set the encryption key for {filename}.", initial_text=initial_text
        )
        dialog.exec_()
        return dialog.result

    def clipboard_text(self) -> str:
        return QGuiApplication.clipboard().text()

    def set_clipboard_text(self, text: str) -> None:
        QGuiApplication.clipboard().setText(text)

    def open_url(self, url: str) -> bool:
        return QDesktopServices.openUrl(QUrl(url))
