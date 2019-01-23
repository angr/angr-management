
from PySide2.QtGui import QFont, QFontMetricsF

from .config_entry import ConfigurationEntry as CE


ENTRIES = [
    CE('disasm_font', QFont, None),
    CE('disasm_font_height', int, None),
    CE('disasm_font_width', int, None),
    CE('disasm_font_ascent', int, None),
    CE('symexec_font', QFont, None),
    CE('symexec_font_height', int, None),
    CE('symexec_font_width', int, None),
    CE('symexec_font_ascent', int, None),
    CE('code_font', QFont, None),
    CE('code_font_height', int, None),
    CE('code_font_width', int, None),
    CE('code_font_ascent', int, None),
]


class ConfigurationManager(object):

    __slots__ = ['_entries']

    def __init__(self):

        self._entries = { }

        for entry in ENTRIES:
            self._entries[entry.name] = entry.copy()

    def init_font_config(self):
        self.disasm_font = QFont("DejaVu Sans Mono", 10)
        font_metrics = QFontMetricsF(self.disasm_font)
        self.disasm_font_height = font_metrics.height()
        self.disasm_font_width = font_metrics.width('A')
        self.disasm_font_ascent = font_metrics.ascent()

        self.symexec_font = QFont("DejaVu Sans Mono", 10)
        font_metrics = QFontMetricsF(self.symexec_font)
        self.symexec_font_height = font_metrics.height()
        self.symexec_font_width = font_metrics.width('A')
        self.symexec_font_ascent = font_metrics.ascent()

        self.code_font = QFont("Source Code Pro", 10)
        font_metrics = QFontMetricsF(self.code_font)
        self.code_font_height = font_metrics.height()
        self.code_font_width = font_metrics.width('A')
        self.code_font_ascent = font_metrics.ascent()

    def __getattr__(self, item):

        if item in self.__slots__:
            raise AttributeError()

        if item in self._entries:
            return self._entries[item].value

        raise AttributeError()

    def __setattr__(self, key, value):

        if key in self.__slots__:
            super(ConfigurationManager, self).__setattr__(key, value)
            return

        if key in self._entries:
            self._entries[key].value = value
            return

        raise KeyError()
