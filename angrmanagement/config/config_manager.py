
import logging

import toml
from PySide2.QtGui import QFont, QFontMetricsF, QColor
from PySide2.QtWidgets import QApplication

from .config_entry import ConfigurationEntry as CE

_l = logging.getLogger(__name__)

def color_constructor(config_option, value):
    if isinstance(value, str):
        value = int(value, 0)

    if type(value) is int:
        return QColor(value)
    elif isinstance(value, dict):
        keys = set(value.keys())
        expected_keys = {'r', 'g', 'b'}
        if keys != expected_keys:
            _l.warning('Found color type with keys %s for option %s, expecting %s. Skipping...',
                    config_option, keys, expected_keys)
        return QColor(value['r'], value['g'], value['b'])
    else:
        _l.error('Failed to parse value %s for option %s', value, config_option)

data_constructors = {
    QColor : color_constructor,
}


ENTRIES = [
    CE('ui_default_font', QFont, None),
    CE('tabular_view_font', QFont, None),
    CE('disasm_font', QFont, None),
    CE('disasm_font_metrics', QFontMetricsF, None),
    CE('disasm_font_height', int, None),
    CE('disasm_font_width', int, None),
    CE('disasm_font_ascent', int, None),
    CE('symexec_font', QFont, None),
    CE('symexec_font_metrics', QFontMetricsF, None),
    CE('symexec_font_height', int, None),
    CE('symexec_font_width', int, None),
    CE('symexec_font_ascent', int, None),
    CE('code_font_metrics', QFontMetricsF, None),
    CE('code_font', QFont, None),
    CE('code_font_height', int, None),
    CE('code_font_width', int, None),
    CE('code_font_ascent', int, None),
    CE('disasm_view_operand_highlight_color', QColor, QColor(0xfc, 0xef, 0)),
    CE('disasm_view_operand_select_color', QColor, QColor(0xff, 0xff, 0)),
    CE('disasm_view_label_highlight_color', QColor, QColor(0xf0, 0xf0, 0xbf)),
    CE('disasm_view_target_addr_color', QColor, QColor(0, 0, 0xff)),
    CE('disasm_view_antitarget_addr_color', QColor, QColor(0xff, 0, 0)),
    CE('disasm_view_node_background_color', QColor, QColor(0xfa, 0xfa, 0xfa)),
    CE('disasm_view_node_border_color', QColor, QColor(0xf0, 0xf0, 0xf0)),
    CE('disasm_view_selected_node_border_color', QColor, QColor(0x6b, 0x71, 0x7c)),
    CE('disasm_view_printable_byte_color', QColor, QColor(0, 0x80, 0x40)),
    CE('disasm_view_printable_character_color', QColor, QColor(0, 0x80, 0x40)),
    CE('disasm_view_unprintable_byte_color', QColor, QColor(0x80, 0x40, 0)),
    CE('disasm_view_unprintable_character_color', QColor, QColor(0x80, 0x40, 0)),
    CE('disasm_view_unknown_byte_color', QColor, QColor(0xf0, 0, 0)),
    CE('disasm_view_unknown_character_color', QColor, QColor(0xf0, 0, 0)),
    # feature map
    CE('feature_map_color_regular_function', QColor, QColor(0, 0xa0, 0xe8)),
    CE('feature_map_color_unknown', QColor, QColor(0xa, 0xa, 0xa)),
    CE('feature_map_color_delimiter', QColor, QColor(0, 0, 0)),
    CE('feature_map_color_data', QColor, QColor(0xc0, 0xc0, 0xc0)),
    # plugins
    CE('plugin_search_path', str, '$AM_BUILTIN_PLUGINS:~/.local/share/angr-management/plugins'),
    CE('plugin_blacklist', str, 'sample_plugin'),
]


class ConfigurationManager:

    __slots__ = ['_entries']

    def __init__(self, entries=None):

        if entries is None:
            self._entries = { }

            for entry in ENTRIES:
                self._entries[entry.name] = entry.copy()
        else:
            self._entries = entries

    def init_font_config(self):
        self.ui_default_font = QApplication.font("QMenu")
        self.tabular_view_font = QApplication.font("QMenu")

        self.disasm_font = QFont("DejaVu Sans Mono", 10)
        self.disasm_font_metrics = QFontMetricsF(self.disasm_font)
        self.disasm_font_height = self.disasm_font_metrics.height()
        self.disasm_font_width = self.disasm_font_metrics.width('A')
        self.disasm_font_ascent = self.disasm_font_metrics.ascent()

        self.symexec_font = QFont("DejaVu Sans Mono", 10)
        self.symexec_font_metrics = QFontMetricsF(self.symexec_font)
        self.symexec_font_height = self.symexec_font_metrics.height()
        self.symexec_font_width = self.symexec_font_metrics.width('A')
        self.symexec_font_ascent = self.symexec_font_metrics.ascent()

        self.code_font = QFont("Source Code Pro", 10)
        self.code_font_metrics = QFontMetricsF(self.code_font)
        self.code_font_height = self.code_font_metrics.height()
        self.code_font_width = self.code_font_metrics.width('A')
        self.code_font_ascent = self.code_font_metrics.ascent()

    def __getattr__(self, item):

        if item in self.__slots__:
            raise AttributeError()

        if item in self._entries:
            return self._entries[item].value

        raise AttributeError(item)

    def __setattr__(self, key, value):

        if key in self.__slots__:
            super(ConfigurationManager, self).__setattr__(key, value)
            return

        if key in self._entries:
            self._entries[key].value = value
            return

        raise AttributeError(key)

    def __dir__(self):
        return list(super().__dir__()) + list(self._entries)

    @classmethod
    def parse(cls, f):
        entry_map = {}
        for entry in ENTRIES:
            entry_map[entry.name] = entry.copy()

        try:
            loaded = toml.load(f)

            for k, v in loaded.items():
                if entry.type_ in data_constructors:
                    v = data_constructors[entry.type_](k, v)
                if k not in entry_map:
                    _l.warning('Unknown configuration option \'%s\'. Ignoring...', k)
                    continue
                entry = entry_map[k]
                if type(v) is not entry.type_:
                    _l.warning('Value \'%s\' for configuration option \'%s\' has type \'%s\', expected type \'%s\'. Ignoring...',
                             v, k, type(v), entry.type_)
                    continue
                entry.value = v
        except toml.TomlDecodeError as e:
            _l.error('Failed to parse configuration file: \'%s\'. Continuing with default options...', e.msg)

        return cls(entry_map)
