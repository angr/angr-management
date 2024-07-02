from __future__ import annotations

import base64
from enum import IntEnum

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
)


class EncKeyFormat(IntEnum):
    BASE64 = 0
    BYTESTRING = 1
    ASCII = 2


class SetEncryptionKeyDialog(QDialog):
    """
    A generic dialog box for loading an encryption key from the user.
    """

    def __init__(
        self,
        window_title: str = "Set an encryption key",
        prompt_msg: str = "",
        initial_text: str = "",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._prompt_msg: str = prompt_msg
        self._initial_text: str = initial_text
        self._enckey_box: QLineEdit = None
        self._status_label: QLabel = None
        self._key_preview: QLabel = None
        self._key_preview_bytes: QLabel = None
        self._auto_radio: QRadioButton = None
        self._base64_radio: QRadioButton = None
        self._bytestring_radio: QRadioButton = None
        self._ascii_radio: QRadioButton = None
        self._ok_button: QPushButton = None
        self.main_layout: QVBoxLayout = QVBoxLayout()
        self.result: bytes | None = None
        self._init_widgets()
        self.setLayout(self.main_layout)
        self.setWindowTitle(window_title)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        prompt_label = QLabel(self)
        prompt_label.setText(self._prompt_msg)
        self.main_layout.addWidget(prompt_label)

        secondary_prompt_label = QLabel(self)
        secondary_prompt_label.setText(
            "Please provide an encryption key (in the form of a Base64-encoed string, a Python byte string, or an "
            "ASCII string):"
        )
        self.main_layout.addWidget(secondary_prompt_label)

        # key format
        format_groupbox = QGroupBox("Key format")
        self._auto_radio = QRadioButton("Auto-detect")
        self._auto_radio.clicked.connect(self._on_enckey_changed)
        self._base64_radio = QRadioButton("Base64")
        self._base64_radio.clicked.connect(self._on_enckey_changed)
        self._bytestring_radio = QRadioButton("Python byte string")
        self._bytestring_radio.clicked.connect(self._on_enckey_changed)
        self._ascii_radio = QRadioButton("ASCII")
        self._ascii_radio.clicked.connect(self._on_enckey_changed)
        format_layout = QHBoxLayout()
        format_layout.addWidget(self._auto_radio)
        self._auto_radio.setChecked(True)
        format_layout.addWidget(self._base64_radio)
        format_layout.addWidget(self._bytestring_radio)
        format_layout.addWidget(self._ascii_radio)
        format_groupbox.setLayout(format_layout)
        self.main_layout.addWidget(format_groupbox)

        enckey_label = QLabel(self)
        enckey_label.setText("Encryption key")
        key_box = QLineEdit(self)
        if self._initial_text:
            key_box.setText(self._initial_text)
            key_box.selectAll()
        key_box.textChanged.connect(self._on_enckey_changed)
        self._enckey_box = key_box

        label_layout = QHBoxLayout()
        label_layout.addWidget(enckey_label)
        label_layout.addWidget(key_box)
        self.main_layout.addLayout(label_layout)

        status_label = QLabel()
        self.main_layout.addWidget(status_label)
        self._status_label = status_label

        self._key_preview = QLabel()
        self.main_layout.addWidget(self._key_preview)
        self._key_preview_bytes = QLabel()
        self.main_layout.addWidget(self._key_preview_bytes)

        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self.close)
        self._ok_button = buttons.button(QDialogButtonBox.Ok)
        self._ok_button.setEnabled(False)
        self.main_layout.addWidget(buttons)

    def _get_enckey(self, txt: str) -> bytes | None:
        if not txt:
            return None

        format = None
        if self._base64_radio.isChecked():
            format = EncKeyFormat.BASE64
        elif self._bytestring_radio.isChecked():
            format = EncKeyFormat.BYTESTRING
        elif self._ascii_radio.isChecked():
            format = EncKeyFormat.ASCII

        # parse it as a base64 string
        if format is None or format == EncKeyFormat.BASE64:
            try:
                key = base64.b64decode(txt, validate=True)
                # it works!
                return key
            except (ValueError, TypeError):
                # can't be parsed as a base64 string
                pass
            if format == EncKeyFormat.BASE64:
                return None

        # parse it as a Python byte string
        if format is None or format == EncKeyFormat.BYTESTRING:
            if (txt.startswith('b"') or txt.startswith("b'")) and (txt.endswith('"') or txt.endswith("'")):
                trimmed_txt = txt[2:-1]
            else:
                trimmed_txt = txt
            try:
                key = eval(f'b"{trimmed_txt}"')
                if isinstance(key, bytes):
                    return key
            except Exception:
                pass

            if format == EncKeyFormat.BYTESTRING:
                return None

        # encode it as a normal string
        if format is None or format == EncKeyFormat.ASCII:
            try:
                return txt.encode("ascii")
            except Exception:
                pass
            if format == EncKeyFormat.ASCII:
                return None

        # everything has failed
        return None

    #
    # Event handlers
    #

    def _on_enckey_changed(self, new_text) -> None:  # pylint:disable=unused-argument
        if self._enckey_box is None:
            # initialization is not done yet
            return

        enc_key = self._get_enckey(self._enckey_box.text())

        if enc_key is None:
            # the variable name is invalid
            self._status_label.setText("Invalid")
            self._status_label.setProperty("class", "status_invalid")
            self._ok_button.setEnabled(False)

            self._key_preview.setText("Key in byte string: ")
            self._key_preview_bytes.setText("Key in bytes: ")
        else:
            self._status_label.setText("Valid")
            self._status_label.setProperty("class", "status_valid")
            self._ok_button.setEnabled(True)

            self._key_preview.setText("Key in byte string: " + str(repr(enc_key)))
            self._key_preview_bytes.setText("Key in bytes: " + " ".join(f"{x:02x}" for x in enc_key))

        self._status_label.style().unpolish(self._status_label)
        self._status_label.style().polish(self._status_label)

    def _on_ok_clicked(self) -> None:
        enc_key = self._get_enckey(self._enckey_box.text())
        if enc_key is not None:
            self.result = enc_key
            self.close()
