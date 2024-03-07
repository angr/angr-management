import contextlib
import enum
import logging
import os
import re
from typing import Any, Callable, List, Optional, Tuple, Type

import tomlkit
import tomlkit.exceptions
import tomlkit.items
from PySide6.QtGui import QColor, QFont, QFontMetricsF
from PySide6.QtWidgets import QApplication, QMessageBox

from angrmanagement.utils.env import app_root

from .config_entry import ConfigurationEntry as CE

_l = logging.getLogger(__name__)
color_re = re.compile("[0-9a-fA-F]+")


class UninterpretedCE(CE):
    """
    A config entry which has not been parsed because no type was available for it.
    """

    def __init__(self, name, value, default_value=None):
        super().__init__(name, UninterpretedCE, value, default_value=default_value)


def tomltype2pytype(v, ty: Optional[Type]) -> Any:
    if ty is str:
        if not isinstance(v, tomlkit.items.String):
            raise TypeError
        return str(v)
    elif ty is int:
        if not isinstance(v, tomlkit.items.Integer):
            raise TypeError
        return v.unwrap()
    elif ty is list:
        if not isinstance(v, tomlkit.items.Array):
            raise TypeError
        return [tomltype2pytype(v_, None) for v_ in v.value]
    return str(v) if isinstance(v, tomlkit.items.String) else v.unwrap()


def color_parser(config_option, value) -> Optional[QColor]:
    if not isinstance(value, str) or not color_re.match(value) or len(value) not in (3, 6, 8, 12):
        _l.error("Failed to parse value %r as rgb color for option %s", value, config_option)
        return None

    return QColor("#" + value)


def color_serializer(config_option, value: QColor) -> str:
    if not isinstance(value, QColor):
        _l.error("Failed to serialize value %r as rgb color for option %s", value, config_option)
        return None

    return f"{value.alpha():02x}{value.red():02x}{value.green():02x}{value.blue():02x}"


def font_parser(config_option, value) -> Optional[QFont]:
    if not isinstance(value, str) or "px " not in value:
        _l.error("Failed to parse value %r as font for option %s", value, config_option)
        return None

    parts = value.split("px ", 1)
    try:
        size = int(parts[0])
    except ValueError:
        _l.error("Failed to parse value %r as font for option %s", value, config_option)
        return None

    return QFont(parts[1], size)


def font_serializer(config_option, value: QFont) -> str:
    if not isinstance(value, QFont):
        _l.error("Failed to serialize value %r as font for option %s", value, config_option)
        return None

    return f"{value.pointSize()}px {value.family()}"


def enum_parser_serializer_generator(
    the_enum: enum.Enum, default
) -> Tuple[Callable[[str, str], enum.Enum], Callable[[str, enum.Enum], str]]:
    def parser(config_option: str, value: str) -> enum.Enum:
        try:
            return the_enum[value]
        except KeyError:
            _l.error(
                "Failed to parse value %r as %s for option %s. Default to %s.",
                value,
                type(the_enum),
                config_option,
                default,
            )
        return default

    def serializer(config_option: str, value: enum.Enum) -> str:
        if not isinstance(value, the_enum):
            _l.error(
                "Failed to serialize value %r as %s for option %s. Default to %s.",
                value,
                type(the_enum),
                config_option,
                default,
            )
            return default
        return value.name

    return parser, serializer


def bool_parser(config_option, value) -> bool:
    if not value:
        return False
    if value.lower() in {"true", "1", "yes"}:
        return True
    if value.lower() in {"false", "0", "no"}:
        return False
    _l.error("Failed to parse value %r as bool for option %s. Default to False.", value, config_option)
    return False


def bool_serializer(config_option, value: bool) -> str:
    if not isinstance(value, bool):
        _l.error("Failed to serialize value %r as bool for option %s. Default to False.", value, config_option)
        return "false"
    return "true" if value else "false"


data_serializers = {
    QColor: (color_parser, color_serializer),
    QFont: (font_parser, font_serializer),
    bool: (bool_parser, bool_serializer),
    QFont.Weight: enum_parser_serializer_generator(QFont.Weight, QFont.Weight.Normal),
    QFont.Style: enum_parser_serializer_generator(QFont.Style, QFont.Style.StyleNormal),
}


# CE(name, type, default_value)
ENTRIES = [
    CE("ui_default_font", QFont, None),
    CE("tabular_view_font", QFont, None),
    CE("disasm_font", QFont, QFont("DejaVu Sans Mono", 10)),
    CE("symexec_font", QFont, QFont("DejaVu Sans Mono", 10)),
    CE("code_font", QFont, QFont("Source Code Pro", 10)),
    CE("theme_name", str, "Light"),
    CE("disasm_view_minimap_viewport_color", QColor, QColor(0xFF, 0x00, 0x00)),
    CE("disasm_view_minimap_background_color", QColor, QColor(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("disasm_view_minimap_outline_color", QColor, QColor(0xB8, 0xB8, 0xB8, 0xFF)),
    CE("disasm_view_background_color", QColor, QColor(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("disasm_view_operand_color", QColor, QColor(0x00, 0x00, 0x80)),
    CE("disasm_view_operand_constant_color", QColor, QColor(0x00, 0x00, 0x80)),
    CE("disasm_view_variable_label_color", QColor, QColor(0x00, 0x80, 0x00)),
    CE("disasm_view_operand_highlight_color", QColor, QColor(0xFC, 0xEF, 0x00)),
    CE("disasm_view_operand_select_color", QColor, QColor(0xFF, 0xFF, 0x00)),
    CE("disasm_view_function_color", QColor, QColor(0x00, 0x00, 0xFF)),
    CE("disasm_view_string_color", QColor, QColor(0xA0, 0xA0, 0xA4)),
    CE("disasm_view_variable_ident_color", QColor, QColor(0xAA, 0x25, 0xDA)),
    CE("disasm_view_variable_offset_color", QColor, QColor(0x80, 0x80, 0x00)),
    CE("disasm_view_branch_target_text_color", QColor, QColor(0x80, 0x80, 0x00)),
    CE("disasm_view_comment_color", QColor, QColor(0x37, 0x3D, 0x3F, 0xFF)),
    CE("disasm_view_ir_default_color", QColor, QColor(0x80, 0x80, 0x80)),
    CE("disasm_view_label_color", QColor, QColor(0x00, 0x00, 0xFF)),
    CE("disasm_view_label_highlight_color", QColor, QColor(0xF0, 0xF0, 0xBF)),
    CE("disasm_view_target_addr_color", QColor, QColor(0x00, 0x00, 0xFF)),
    CE("disasm_view_antitarget_addr_color", QColor, QColor(0xFF, 0x00, 0x00)),
    CE("disasm_view_node_shadow_color", QColor, QColor(0x00, 0x00, 0x00, 0x00)),
    CE("disasm_view_node_background_color", QColor, QColor(0xFA, 0xFA, 0xFA)),
    CE("disasm_view_node_zoomed_out_background_color", QColor, QColor(0xDA, 0xDA, 0xDA)),
    CE("disasm_view_node_border_color", QColor, QColor(0xF0, 0xF0, 0xF0)),
    CE("disasm_view_node_instruction_selected_background_color", QColor, QColor(0xB8, 0xC3, 0xD6)),
    CE("disasm_view_node_address_color", QColor, QColor(0x00, 0x00, 0x00)),
    CE("disasm_view_node_mnemonic_color", QColor, QColor(0x00, 0x00, 0x80)),
    CE("disasm_view_node_rounding", int, 0),
    CE("disasm_view_selected_node_border_color", QColor, QColor(0x6B, 0x71, 0x7C)),
    CE("disasm_view_printable_byte_color", QColor, QColor(0x00, 0x80, 0x40)),
    CE("disasm_view_printable_character_color", QColor, QColor(0x00, 0x80, 0x40)),
    CE("disasm_view_unprintable_byte_color", QColor, QColor(0x80, 0x40, 0x00)),
    CE("disasm_view_unprintable_character_color", QColor, QColor(0x80, 0x40, 0x00)),
    CE("disasm_view_unknown_byte_color", QColor, QColor(0xF0, 0x00, 0x00)),
    CE("disasm_view_unknown_character_color", QColor, QColor(0xF0, 0x00, 0x00)),
    CE("disasm_view_back_edge_color", QColor, QColor(0xF9, 0xD5, 0x77)),
    CE("disasm_view_true_edge_color", QColor, QColor(0x79, 0xCC, 0xCD)),
    CE("disasm_view_false_edge_color", QColor, QColor(0xF1, 0x66, 0x64)),
    CE("disasm_view_direct_jump_edge_color", QColor, QColor(0x56, 0x5A, 0x5C)),
    CE("disasm_view_exception_edge_color", QColor, QColor(0xF9, 0x91, 0x0A)),
    CE("hex_view_selection_color", QColor, QColor(0xFF, 0x00, 0x00)),
    CE("hex_view_selection_alt_color", QColor, QColor(0xA0, 0xA0, 0xA4)),
    CE("hex_view_data_color", QColor, QColor(0x00, 0x00, 0xFF)),
    CE("hex_view_string_color", QColor, QColor(0x00, 0xFF, 0xFF)),
    CE("hex_view_instruction_color", QColor, QColor(0xFF, 0x00, 0xFF)),
    CE("function_table_color", QColor, QColor(0x00, 0x00, 0x00)),
    CE("function_table_syscall_color", QColor, QColor(0x00, 0x00, 0x80)),
    CE("function_table_plt_color", QColor, QColor(0x00, 0x80, 0x00)),
    CE("function_table_simprocedure_color", QColor, QColor(0x80, 0x00, 0x00)),
    CE("function_table_alignment_color", QColor, QColor(0x80, 0x00, 0x80)),
    CE("function_table_signature_bg_color", QColor, QColor(0xAA, 0xFF, 0xFF)),
    CE("palette_window", QColor, QColor(0xEF, 0xEF, 0xEF, 0xFF)),
    CE("palette_windowtext", QColor, QColor(0x00, 0x00, 0x00, 0xFF)),
    CE("palette_base", QColor, QColor(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("palette_alternatebase", QColor, QColor(0xF7, 0xF7, 0xF7, 0xFF)),
    CE("palette_tooltipbase", QColor, QColor(0xFF, 0xFF, 0xDC, 0xFF)),
    CE("palette_tooltiptext", QColor, QColor(0x00, 0x00, 0x00, 0xFF)),
    CE("palette_placeholdertext", QColor, QColor(0x00, 0x00, 0x00, 0xAF)),
    CE("palette_text", QColor, QColor(0x00, 0x00, 0x00, 0xFF)),
    CE("palette_button", QColor, QColor(0xEF, 0xEF, 0xEF, 0xFF)),
    CE("palette_buttontext", QColor, QColor(0x00, 0x00, 0x00, 0xFF)),
    CE("palette_brighttext", QColor, QColor(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("palette_highlight", QColor, QColor(0x30, 0x8C, 0xC6, 0xFF)),
    CE("palette_highlightedtext", QColor, QColor(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("palette_disabled_text", QColor, QColor(0xBE, 0xBE, 0xBE, 0xFF)),
    CE("palette_disabled_buttontext", QColor, QColor(0xBE, 0xBE, 0xBE, 0xFF)),
    CE("palette_disabled_windowtext", QColor, QColor(0xBE, 0xBE, 0xBE, 0xFF)),
    CE("palette_light", QColor, QColor(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("palette_midlight", QColor, QColor(0xCA, 0xCA, 0xCA, 0xFF)),
    CE("palette_dark", QColor, QColor(0x9F, 0x9F, 0x9F, 0xFF)),
    CE("palette_mid", QColor, QColor(0xB8, 0xB8, 0xB8, 0xFF)),
    CE("palette_shadow", QColor, QColor(0x76, 0x76, 0x76, 0xFF)),
    CE("palette_link", QColor, QColor(0x00, 0x00, 0xFF, 0xFF)),
    CE("palette_linkvisited", QColor, QColor(0xFF, 0x00, 0xFF, 0xFF)),
    CE("pseudocode_comment_color", QColor, QColor(0x00, 0x80, 0x00, 0xFF)),
    CE("pseudocode_comment_weight", QFont.Weight, QFont.Weight.Bold),
    CE("pseudocode_comment_style", QFont.Style, QFont.Style.StyleNormal),
    CE("pseudocode_function_color", QColor, QColor(0x00, 0x00, 0xFF, 0xFF)),
    CE("pseudocode_library_function_color", QColor, QColor(0xFF, 0x00, 0xFF)),
    CE("pseudocode_function_weight", QFont.Weight, QFont.Weight.Bold),
    CE("pseudocode_function_style", QFont.Style, QFont.Style.StyleNormal),
    CE("pseudocode_quotation_color", QColor, QColor(0x00, 0x80, 0x00, 0xFF)),
    CE("pseudocode_quotation_weight", QFont.Weight, QFont.Weight.Normal),
    CE("pseudocode_quotation_style", QFont.Style, QFont.Style.StyleNormal),
    CE("pseudocode_keyword_color", QColor, QColor(0x00, 0x00, 0x80, 0xFF)),
    CE("pseudocode_keyword_weight", QFont.Weight, QFont.Weight.Bold),
    CE("pseudocode_keyword_style", QFont.Style, QFont.Style.StyleNormal),
    CE("pseudocode_types_color", QColor, QColor(0x00, 0x00, 0x80, 0xFF)),
    CE("pseudocode_types_weight", QFont.Weight, QFont.Weight.Normal),
    CE("pseudocode_types_style", QFont.Style, QFont.Style.StyleNormal),
    CE("pseudocode_variable_color", QColor, QColor(0x00, 0x00, 0x00, 0xFF)),
    CE("pseudocode_variable_weight", QFont.Weight, QFont.Weight.Normal),
    CE("pseudocode_variable_style", QFont.Style, QFont.Style.StyleNormal),
    CE("pseudocode_label_color", QColor, QColor(0x00, 0x00, 0xFF)),
    CE("pseudocode_label_weight", QFont.Weight, QFont.Weight.Normal),
    CE("pseudocode_label_style", QFont.Style, QFont.Style.StyleNormal),
    CE("pseudocode_highlight_color", QColor, QColor(0xFF, 0xFF, 0x00, 0xFF)),
    CE("proximity_node_background_color", QColor, QColor(0xFA, 0xFA, 0xFA)),
    CE("proximity_node_selected_background_color", QColor, QColor(0xCC, 0xCC, 0xCC)),
    CE("proximity_node_border_color", QColor, QColor(0xF0, 0xF0, 0xF0)),
    CE("proximity_function_node_text_color", QColor, QColor(0xFF, 0x00, 0x00)),
    CE("proximity_string_node_text_color", QColor, QColor(0x00, 0x80, 0x00)),
    CE("proximity_integer_node_text_color", QColor, QColor(0x00, 0x00, 0x80)),
    CE("proximity_variable_node_text_color", QColor, QColor(0x00, 0x00, 0x80)),
    CE("proximity_unknown_node_text_color", QColor, QColor(0x00, 0x00, 0x80)),
    CE("proximity_call_node_text_color", QColor, QColor(0x00, 0x00, 0xFF)),
    CE("proximity_call_node_text_color_plt", QColor, QColor(0x8B, 0x00, 0x8B)),
    CE("proximity_call_node_text_color_simproc", QColor, QColor(0x8B, 0x00, 0x8B)),
    CE("log_timestamp_format", str, "%X"),
    # FLIRT signatures
    CE("flirt_signatures_root", str, "./flirt_signatures/"),
    # Library documentation
    CE("library_docs_root", str, "./library_docs/"),
    # feature map
    CE("feature_map_regular_function_color", QColor, QColor(0x00, 0xA0, 0xE8)),
    CE("feature_map_unknown_color", QColor, QColor(0x0A, 0x0A, 0x0A)),
    CE("feature_map_delimiter_color", QColor, QColor(0x00, 0x00, 0x00)),
    CE("feature_map_data_color", QColor, QColor(0xC0, 0xC0, 0xC0)),
    CE("feature_map_string_color", QColor, QColor(0x00, 0xF0, 0x80)),
    # networking
    CE("http_proxy", str, ""),
    CE("https_proxy", str, ""),
    # plugins
    CE("plugin_search_path", str, "$AM_BUILTIN_PLUGINS:~/.local/share/angr-management/plugins"),
    CE("enabled_plugins", str, ""),
    # configurations for individual plugins
    # TOOD: Move them to separate locations
    CE("plugin_ComponentsPlugin_enabled", bool, False),
    # VARec
    CE("varec_endpoint", str, "http://192.168.32.129:5000/varec_joint_small"),
    # Daemon
    CE("use_daemon", bool, False),
    # Tabs
    CE("enabled_tabs", str, ""),
    # Recent
    CE("recent_files", list, []),
    CE("prompted_for_url_scheme_registration", bool, False),
]


class ConfigurationManager:  # pylint: disable=assigning-non-slot
    """
    Globe Configuration Manager for UI configuration with save/load function
    """

    __slots__ = (
        "_entries",
        "_disasm_font",
        "_disasm_font_metrics",
        "_disasm_font_height",
        "_disasm_font_width",
        "_disasm_font_ascent",
        "_symexec_font",
        "_symexec_font_metrics",
        "_symexec_font_height",
        "_symexec_font_width",
        "_symexec_font_ascent",
        "_code_font",
        "_code_font_metrics",
        "_code_font_height",
        "_code_font_width",
        "_code_font_ascent",
    )

    def __init__(self, entries=None):
        self._disasm_font = self._disasm_font_metrics = self._disasm_font_height = None
        self._disasm_font_width = self._disasm_font_ascent = None
        self._symexec_font = self._symexec_font_metrics = self._symexec_font_height = None
        self._symexec_font_width = self._symexec_font_ascent = None
        self._code_font = self._code_font_metrics = self._code_font_height = None
        self._code_font_width = self._code_font_ascent = None

        if entries is None:
            self._entries = {}
            self.load_initial_entries(reset=True)
        else:
            self._entries = entries

    def load_initial_entries(self, reset: bool = True):
        """
        Load configuration entries into self._entries.

        :param reset:   Reset all configuration items to their default values.
        :return:        None
        """
        for entry in ENTRIES:
            if entry.name not in self._entries:
                self._entries[entry.name] = entry.copy()
            else:
                if reset:
                    self._entries[entry.name] = entry.copy()

    @staticmethod
    def _manage_font_cache(real_font, font, metrics, height, width, ascent):
        if real_font == font:
            return font, metrics, height, width, ascent

        metrics = QFontMetricsF(real_font)
        height = metrics.height()
        width = metrics.width("A")
        ascent = metrics.ascent()
        return real_font, metrics, height, width, ascent

    def _disasm_manage_font_cache(self):
        (
            self._disasm_font,
            self._disasm_font_metrics,
            self._disasm_font_height,
            self._disasm_font_width,
            self._disasm_font_ascent,
        ) = ConfigurationManager._manage_font_cache(
            self.disasm_font,
            self._disasm_font,
            self._disasm_font_metrics,
            self._disasm_font_height,
            self._disasm_font_width,
            self._disasm_font_ascent,
        )

    def _symexec_manage_font_cache(self):
        (
            self._symexec_font,
            self._symexec_font_metrics,
            self._symexec_font_height,
            self._symexec_font_width,
            self._symexec_font_ascent,
        ) = ConfigurationManager._manage_font_cache(
            self.symexec_font,
            self._symexec_font,
            self._symexec_font_metrics,
            self._symexec_font_height,
            self._symexec_font_width,
            self._symexec_font_ascent,
        )

    def _code_manage_font_cache(self):
        (
            self._code_font,
            self._code_font_metrics,
            self._code_font_height,
            self._code_font_width,
            self._code_font_ascent,
        ) = ConfigurationManager._manage_font_cache(
            self.code_font,
            self._code_font,
            self._code_font_metrics,
            self._code_font_height,
            self._code_font_width,
            self._code_font_ascent,
        )

    disasm_font: QFont
    symexec_font: QFont
    code_font: QFont

    @property
    def disasm_font_metrics(self):
        self._disasm_manage_font_cache()
        return self._disasm_font_metrics

    @property
    def disasm_font_height(self):
        self._disasm_manage_font_cache()
        return self._disasm_font_height

    @property
    def disasm_font_width(self):
        self._disasm_manage_font_cache()
        return self._disasm_font_width

    @property
    def disasm_font_ascent(self):
        self._disasm_manage_font_cache()
        return self._disasm_font_ascent

    @property
    def symexec_font_metrics(self):
        self._symexec_manage_font_cache()
        return self._symexec_font_metrics

    @property
    def symexec_font_height(self):
        self._symexec_manage_font_cache()
        return self._symexec_font_height

    @property
    def symexec_font_width(self):
        self._symexec_manage_font_cache()
        return self._symexec_font_width

    @property
    def symexec_font_ascent(self):
        self._symexec_manage_font_cache()
        return self._symexec_font_ascent

    @property
    def code_font_metrics(self):
        self._code_manage_font_cache()
        return self._code_font_metrics

    @property
    def code_font_height(self):
        self._code_manage_font_cache()
        return self._code_font_height

    @property
    def code_font_width(self):
        self._code_manage_font_cache()
        return self._code_font_width

    @property
    def code_font_ascent(self):
        self._code_manage_font_cache()
        return self._code_font_ascent

    def init_font_config(self):
        if self.ui_default_font is None:
            self.ui_default_font = QApplication.font("QMenu")
        if self.tabular_view_font is None:
            self.tabular_view_font = QApplication.font("QMenu")

    recent_files: List[str]

    def recent_file(self, file_path: str):
        with contextlib.suppress(ValueError):
            self.recent_files.remove(file_path)
        self.recent_files = self.recent_files[:9]
        self.recent_files.append(file_path)

    def __getattr__(self, item):
        if item in self.__slots__ or item in type(self).__dict__:
            return super().__getattribute__(item)

        if item in self._entries:
            return self._entries[item].value

        raise AttributeError(item)

    def __setattr__(self, key, value):
        if key in self.__slots__ or key in type(self).__dict__:
            super().__setattr__(key, value)
            return

        if key in self._entries:
            self._entries[key].value = value
            return

        raise AttributeError(key)

    def connect(self, key: str, func: Callable[[Any], None], init: bool) -> None:
        """
        Connect func to the QT signal emitted when the key changes
        If init, calls func on the value associated with key after connecting
        """
        self._entries[key].changed.connect(func)
        if init:
            func(getattr(self, key))

    def disconnect(self, key: str, func: Callable[[Any], None]) -> None:
        """
        Disconnect func from the QT signal emitted when the key changes
        """
        self._entries[key].changed.disconnect(func)

    def __dir__(self):
        return list(super().__dir__()) + list(self._entries)

    @classmethod
    def parse(cls, f, ignore_unknown_entries: bool = False):
        entry_map = {}
        for entry in ENTRIES:
            entry_map[entry.name] = entry.copy()

        try:
            loaded = tomlkit.load(f)

            for k, v in loaded.items():
                if k not in entry_map:
                    if ignore_unknown_entries:
                        _l.warning("Unknown configuration option '%s'. Ignoring...", k)
                    else:
                        entry_map[k] = UninterpretedCE(k, v)
                    continue
                    # default to a string

                entry = entry_map[k]
                entry.value = cls.deserialize(entry.type_, k, v)
                if entry.value is None:
                    entry_map[k] = UninterpretedCE(k, v)
        except tomlkit.exceptions.ParseError:
            _l.error("Failed to parse configuration file: '%s'. Continuing with default options...", exc_info=True)

        return cls(entry_map)

    @staticmethod
    def deserialize(ty, k, v):
        if ty in data_serializers:
            v = data_serializers[ty][0](k, v)
            if v is None:
                return None
        else:
            try:
                v = tomltype2pytype(v, ty)
            except TypeError:
                _l.warning(
                    "Value '%s' for configuration option '%s' has type '%s', expected type '%s'. Ignoring...",
                    v,
                    k,
                    type(v),
                    ty,
                )
                return None

        return v

    def reinterpet(self):
        """
        Walks the ENTRIES list, trying to update self's entries with respect to anything that may have been added to
        the global list. Tries to fix up UninterpretedCEs. Should be called e.g. after loading plugins.
        """
        for entry in ENTRIES:
            my_entry = self._entries.get(entry.name, None)
            if my_entry is None:
                self._entries[entry.name] = my_entry
                continue

            if type(my_entry) is UninterpretedCE:
                entry.value = self.deserialize(entry.type_, entry.name, my_entry.value)
                if entry.value is not None:
                    self._entries[entry.name] = entry

    @classmethod
    def parse_file(cls, path: str, ignore_unknown_entries: bool = False):
        with open(path, encoding="utf-8") as f:
            return cls.parse(f, ignore_unknown_entries=ignore_unknown_entries)

    def save(self, f):
        out = {}
        for k, v in self._entries.items():
            v = v.value
            while type(v) in data_serializers:
                v = data_serializers[type(v)][1](k, v)
            out[k] = v

        tomlkit.dump(out, f)

    def save_file(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            self.save(f)

    def attempt_importing_initial_config(self) -> bool:
        """
        Look for am_initial_config inside the last four levels of directories. Import the first one found. Then remove
        the file. Prompt user to manually remove the file if file removing fails.

        :return: True if successfully imports the initial configuration. False otherwise.
        """

        loaded = False

        base = app_root()
        for _ in range(4):
            initial_config_path = os.path.join(base, "am_initial_config")
            if os.path.isfile(initial_config_path):
                from . import save_config  # delayed import # pylint: disable=import-outside-toplevel

                # we found it!
                new_conf = self.__class__.parse_file(initial_config_path, ignore_unknown_entries=False)
                # copy entries over
                self._entries = new_conf._entries
                # save it!
                save_config()
                loaded = True

                # remove the file
                try:
                    os.remove(initial_config_path)
                except (IsADirectoryError, FileNotFoundError):
                    pass
                except Exception:  # pylint: disable=broad-except
                    QMessageBox.warning(
                        None,
                        "Failed to remove the initial configuration file",
                        f"angr management imported the initial configuration but failed to remove the"
                        f"initial configuration file at {initial_config_path}. Please remove it "
                        f"manually. Otherwise your settings will be overwritten next time angr "
                        f"management starts.",
                    )

                break

            last_dirname = base
            base = os.path.dirname(last_dirname)

            if base == last_dirname:
                # we reached the end of the directory hierarchy
                break

        return loaded

    @property
    def has_operation_mango(self) -> bool:
        try:
            import argument_resolver  # noqa

            return True
        except ImportError:
            return False
