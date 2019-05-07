
from PySide2.QtGui import QFont, QFontMetricsF, QColor

from .config_entry import ConfigurationEntry as CE
import yaml
import logging

_l = logging.getLogger(__name__)

def color_constructor(loader, node):
    value = loader.construct_scalar(node)
    r, g, b = map(lambda s: int(s, 0), value.split(','))
    return QColor(r, g, b)

yaml.add_constructor(u'!color', color_constructor)


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
    CE('disasm_view_operand_highlight_color', QColor, QColor(0x7f, 0xf5, 0)),
    CE('disasm_view_operand_select_color', QColor, QColor(0xc0, 0xbf, 0x40)),
    CE('disasm_view_target_addr_color', QColor, QColor(0, 0xff, 0)),
    CE('disasm_view_antitarget_addr_color', QColor, QColor(0xff, 0, 0)),
    CE('disasm_view_node_background_color', QColor, QColor(0xfa, 0xfa, 0xfa)),
    CE('disasm_view_node_border_color', QColor, QColor(0xf0, 0xf0, 0xf0)),
]


class ConfigurationManager(object):

    __slots__ = ['_entries']

    def __init__(self, entries=None):

        if entries is None:
            self._entries = { }

            for entry in ENTRIES:
                self._entries[entry.name] = entry.copy()
        else:
            self._entries = entries

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

    @classmethod
    def parse(cls, f):
        loaded = yaml.load(f, Loader=yaml.Loader)
        entry_map = {}
        for entry in ENTRIES:
            entry_map[entry.name] = entry.copy()
        for k, v in loaded.items():
            if k not in entry_map:
                _l.warning('Unknown configuration option \'%s\'. Ignoring...', k)
                continue
            entry = entry_map[k]
            if type(v) is not entry.type_:
                _l.warning('Value \'%s\' for configuration option \'%s\' has type \'%s\', expected type \'%s\'. Ignoring...',
                         v, k, type(v), entry.type_)
                continue
            entry.value = v
        return cls(entry_map)
