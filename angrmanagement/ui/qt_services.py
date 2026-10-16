"""The UI services of the Qt frontend: message boxes, input dialogs, file dialogs, the clipboard and the browser."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox

from angrmanagement.data.load_options import LoadOptions
from angrmanagement.logic import GlobalInfo

if TYPE_CHECKING:
    from collections.abc import Sequence

    import cle

    from angrmanagement.logic.ui_services import MessageLevel

_MESSAGE_BOXES = {
    "info": QMessageBox.information,
    "warning": QMessageBox.warning,
    "critical": QMessageBox.critical,
}


class QtServices:
    """
    UIServices for the Qt frontend.

    Dialogs have no parent, as the core's own message boxes had none; call the methods on the GUI thread.
    """

    def message(self, level: MessageLevel, title: str, text: str) -> None:
        _MESSAGE_BOXES.get(level, QMessageBox.information)(None, title, text)

    def question(self, title: str, text: str, buttons: Sequence[str], default: str) -> str:
        box = QMessageBox(GlobalInfo.main_window)
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
        text, ok = QInputDialog.getText(GlobalInfo.main_window, title, label, QLineEdit.EchoMode.Normal, default)
        return text if ok else None

    def pick_open_files(self, caption: str, directory: str, name_filter: str, multiple: bool) -> list[str]:
        if multiple:
            filenames, _ = QFileDialog.getOpenFileNames(None, caption, directory, name_filter)
            return list(filenames)
        filename, _ = QFileDialog.getOpenFileName(None, caption, directory, name_filter)
        return [filename] if filename else []

    def pick_save_file(self, caption: str, directory: str, name_filter: str) -> str | None:
        filename, _ = QFileDialog.getSaveFileName(None, caption, directory, name_filter)
        return filename or None

    def pick_directory(self, caption: str, directory: str) -> str | None:
        return QFileDialog.getExistingDirectory(None, caption, directory) or None

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
