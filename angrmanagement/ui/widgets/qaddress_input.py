from typing import Callable, Optional

from PySide6.QtWidgets import QLineEdit


class QAddressInput(QLineEdit):
    def __init__(self, textchanged_callback: Optional[Callable], instance, parent=None, default: Optional[str] = None):
        super().__init__(parent)

        self.instance = instance

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

    def _convert_to_addr(self, input_):
        # TODO: take care of labels
        # TODO: take care of decimal integers

        # is it a hex?
        try:
            addr = int(input_, 16)
            return addr
        except ValueError:
            pass

        # is it a function name?
        functions = self.instance.project.kb.functions
        func = functions.function(name=input_, create=False)
        if func is not None:
            return func.addr

        return None
