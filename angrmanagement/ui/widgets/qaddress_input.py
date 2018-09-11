from PySide2.QtWidgets import QLineEdit


class QAddressInput(QLineEdit):
    def __init__(self, textchanged_callback, parent=None, default=None):
        super(QAddressInput, self).__init__(parent)

        if default is not None:
            self.setText(str(default))

        if textchanged_callback is not None:
            self.textChanged.connect(textchanged_callback)

    @property
    def target(self):
        text = self.text()
        if self._is_valid_addr_or_label(text):
            return self._convert_to_addr(text)
        return None

    @property
    def raw_target(self):
        text = self.text()
        return self._convert_to_addr(text)

    def _is_valid_addr_or_label(self, input):
        r = self._convert_to_addr(input)
        return r is not None

    def _convert_to_addr(self, input):
        # TODO: take care of labels

        try:
            addr = int(input, 16)
            return addr
        except ValueError:
            return None
