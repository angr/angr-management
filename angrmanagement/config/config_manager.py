from __future__ import annotations

import contextlib
import logging
import os
import re
from typing import TYPE_CHECKING, Any, Protocol

import tomlkit
import tomlkit.exceptions
import tomlkit.items

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.signal import max_positional_args
from angrmanagement.utils.env import app_root

from .color import Color
from .color_schemes import BASE_SCHEME, COLOR_SCHEMES
from .config_entry import ConfigurationEntry as CE
from .font import FontSpec, FontStyle, FontWeight

if TYPE_CHECKING:
    import enum
    from collections.abc import Callable

_l = logging.getLogger(__name__)
#: kept for code outside angr management; Color.from_hex is what parses colours now
color_re = re.compile("[0-9a-fA-F]+")


class FrontendAdapter(Protocol):
    """
    Converts configuration values between their stored, frontend-neutral form and a frontend's own types.

    Stored values are always neutral (Color, FontSpec, FontWeight, FontStyle and plain Python values). Reading
    ``Conf.<name>`` returns ``to_frontend(name, value)``, and assigning ``Conf.<name>`` stores
    ``from_frontend(name, value)``, so Qt code keeps reading and assigning QColor and QFont objects.
    """

    def to_frontend(self, entry_name: str, value: Any) -> Any:
        """Convert a stored value to the frontend's type. Values the frontend has no type for are returned as is."""
        raise NotImplementedError

    def from_frontend(self, entry_name: str, value: Any) -> Any:
        """Convert a frontend value to the stored type. Values that are already neutral are returned as is."""
        raise NotImplementedError

    def font_metrics(self, font: FontSpec) -> tuple[float, float, float]:
        """The (height, width of "A", ascent) of a font, in the frontend's units."""
        raise NotImplementedError

    def font_metrics_object(self, font: FontSpec) -> Any:
        """
        What ``Conf.<font>_metrics`` returns: the frontend's own font metrics object, such as Qt's QFontMetricsF.

        A frontend without one returns the ``font_metrics`` tuple.
        """
        raise NotImplementedError

    def default_fonts(self) -> dict[str, FontSpec]:
        """The fonts to use for ``ui_default_font`` and ``tabular_view_font`` when the configuration sets none."""
        raise NotImplementedError


#: the fonts a frontend without fonts of its own uses
HEADLESS_DEFAULT_FONT = FontSpec("DejaVu Sans Mono", 10)


class HeadlessFrontendAdapter:  # pylint:disable=no-self-use
    """The adapter of a frontend that uses the neutral values directly: a character cell is 1 by 1."""

    def to_frontend(self, entry_name: str, value: Any) -> Any:  # pylint:disable=unused-argument
        return value

    def from_frontend(self, entry_name: str, value: Any) -> Any:  # pylint:disable=unused-argument
        return value

    def font_metrics(self, font: FontSpec) -> tuple[float, float, float]:  # pylint:disable=unused-argument
        return 1, 1, 1

    def font_metrics_object(self, font: FontSpec) -> tuple[float, float, float]:
        return self.font_metrics(font)

    def default_fonts(self) -> dict[str, FontSpec]:
        return {"ui_default_font": HEADLESS_DEFAULT_FONT, "tabular_view_font": HEADLESS_DEFAULT_FONT}


class UninterpretedCE(CE):
    """
    A config entry which has not been parsed because no type was available for it.
    """

    def __init__(self, name: str, value, default_value=None) -> None:
        super().__init__(name, UninterpretedCE, value, default_value=default_value)


def tomltype2pytype(v, ty: type | None) -> Any:
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


def color_parser(config_option, value) -> Color | None:
    try:
        if not isinstance(value, str):
            raise ValueError
        return Color.from_hex(str(value))
    except ValueError:
        _l.error("Failed to parse value %r as rgb color for option %s", value, config_option)
        return None


def color_serializer(config_option, value: Color) -> str:
    if not isinstance(value, Color):
        _l.error("Failed to serialize value %r as rgb color for option %s", value, config_option)
        return None

    return value.hex


def font_parser(config_option, value) -> FontSpec | None:
    try:
        if not isinstance(value, str):
            raise ValueError
        return FontSpec.from_legacy_string(str(value))
    except ValueError:
        _l.error("Failed to parse value %r as font for option %s", value, config_option)
        return None


def font_serializer(config_option, value: FontSpec) -> str:
    if not isinstance(value, FontSpec):
        _l.error("Failed to serialize value %r as font for option %s", value, config_option)
        return None

    return value.to_legacy_string()


_DEFAULT_WEIGHT = FontWeight(500)


def font_weight_parser(config_option, value) -> FontWeight:
    try:
        if isinstance(value, bool):
            raise ValueError
        if isinstance(value, int):
            return FontWeight(int(value))
        return FontWeight.from_name(str(value))
    except ValueError:
        _l.error(
            "Failed to parse value %r as a font weight for option %s. Default to %s.",
            value,
            config_option,
            _DEFAULT_WEIGHT.name,
        )
    return _DEFAULT_WEIGHT


def font_weight_serializer(config_option, value: FontWeight) -> str:
    if not isinstance(value, int) or isinstance(value, bool):
        _l.error(
            "Failed to serialize value %r as a font weight for option %s. Default to %s.",
            value,
            config_option,
            _DEFAULT_WEIGHT.name,
        )
        return _DEFAULT_WEIGHT.name
    return FontWeight(value).name


def font_style_parser(config_option, value) -> FontStyle:
    try:
        return FontStyle.from_qt_name(str(value))
    except ValueError:
        _l.error(
            "Failed to parse value %r as a font style for option %s. Default to %s.",
            value,
            config_option,
            FontStyle.NORMAL.qt_name,
        )
    return FontStyle.NORMAL


def font_style_serializer(config_option, value: FontStyle) -> str:
    if not isinstance(value, FontStyle):
        _l.error(
            "Failed to serialize value %r as a font style for option %s. Default to %s.",
            value,
            config_option,
            FontStyle.NORMAL.qt_name,
        )
        return FontStyle.NORMAL.qt_name
    return value.qt_name


# not used for the built-in entries any more; a plugin may use it to register an Enum type in data_serializers
def enum_parser_serializer_generator(
    the_enum: type[enum.Enum], default
) -> tuple[Callable[[str, str], enum.Enum], Callable[[str, enum.Enum], str]]:
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
    Color: (color_parser, color_serializer),
    FontSpec: (font_parser, font_serializer),
    bool: (bool_parser, bool_serializer),
    FontWeight: (font_weight_parser, font_weight_serializer),
    FontStyle: (font_style_parser, font_style_serializer),
}


_FONT_UNSET = "UNSET"


# CE(name, type, default_value)
ENTRIES = [
    CE("ui_default_font", FontSpec, _FONT_UNSET),
    CE("tabular_view_font", FontSpec, _FONT_UNSET),
    CE("disasm_font", FontSpec, FontSpec("DejaVu Sans Mono", 11)),
    CE("symexec_font", FontSpec, FontSpec("DejaVu Sans Mono", 11)),
    CE("code_font", FontSpec, FontSpec("Source Code Pro", 11)),
    CE("base_theme_name", str, "Light"),
    CE("theme_name", str, "Light"),
    CE("disasm_view_minimap_viewport_color", Color, Color(0xFF, 0x00, 0x00)),
    CE("disasm_view_minimap_background_color", Color, Color(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("disasm_view_minimap_shadow_color", Color, Color(0x00, 0x00, 0x00, 0x28)),
    CE("disasm_view_minimap_outline_color", Color, Color(0xB8, 0xB8, 0xB8, 0xFF)),
    CE("disasm_view_background_color", Color, Color(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("disasm_view_operand_color", Color, Color(0x00, 0x00, 0x80)),
    CE("disasm_view_operand_constant_color", Color, Color(0x00, 0x00, 0x80)),
    CE("disasm_view_variable_label_color", Color, Color(0x00, 0x80, 0x00)),
    CE("disasm_view_operand_highlight_color", Color, Color(0xFC, 0xEF, 0x00)),
    CE("disasm_view_operand_select_color", Color, Color(0xFF, 0xFF, 0x00)),
    CE("disasm_view_function_color", Color, Color(0x00, 0x00, 0xFF)),
    CE("disasm_view_function_arg_name_color", Color, Color(0x00, 0x00, 0x00)),
    CE("disasm_view_function_arg_type_color", Color, Color(0x00, 0x00, 0x80)),
    CE("disasm_view_string_color", Color, Color(0xA0, 0xA0, 0xA4)),
    CE("disasm_view_variable_ident_color", Color, Color(0xAA, 0x25, 0xDA)),
    CE("disasm_view_variable_offset_color", Color, Color(0x80, 0x80, 0x00)),
    CE("disasm_view_branch_target_text_color", Color, Color(0x80, 0x80, 0x00)),
    CE("disasm_view_comment_color", Color, Color(0x37, 0x3D, 0x3F, 0xFF)),
    CE("disasm_view_bookmark_color", Color, Color(0xFF, 0xD5, 0x4F, 0x60)),
    CE("disasm_view_pattern_highlight_color", Color, Color(0x64, 0xB5, 0xF6, 0x50)),
    CE("disasm_view_ir_default_color", Color, Color(0x80, 0x80, 0x80)),
    CE("disasm_view_alignment_color", Color, Color(0x00, 0x60, 0x60)),
    CE("disasm_view_label_color", Color, Color(0x00, 0x00, 0x80)),
    CE("disasm_view_label_highlight_color", Color, Color(0xF0, 0xF0, 0xBF)),
    CE("disasm_view_target_addr_color", Color, Color(0x00, 0x00, 0xFF)),
    CE("disasm_view_antitarget_addr_color", Color, Color(0xFF, 0x00, 0x00)),
    CE("disasm_view_node_shadow_color", Color, Color(0x00, 0x00, 0x00, 0x00)),
    CE("disasm_view_node_background_color", Color, Color(0xFA, 0xFA, 0xFA)),
    CE("disasm_view_node_zoomed_out_background_color", Color, Color(0xDA, 0xDA, 0xDA)),
    CE("disasm_view_node_border_color", Color, Color(0xF0, 0xF0, 0xF0)),
    CE("disasm_view_node_instruction_selected_background_color", Color, Color(0xB8, 0xC3, 0xD6)),
    CE("disasm_view_node_address_color", Color, Color(0x00, 0x00, 0x00)),
    CE("disasm_view_node_mnemonic_color", Color, Color(0x00, 0x00, 0x80)),
    CE("disasm_view_node_rounding", int, 0),
    CE("disasm_view_selected_node_border_color", Color, Color(0x6B, 0x71, 0x7C)),
    CE("disasm_view_printable_byte_color", Color, Color(0x00, 0x80, 0x40)),
    CE("disasm_view_printable_character_color", Color, Color(0x00, 0x80, 0x40)),
    CE("disasm_view_unprintable_byte_color", Color, Color(0x80, 0x40, 0x00)),
    CE("disasm_view_unprintable_character_color", Color, Color(0x80, 0x40, 0x00)),
    CE("disasm_view_unknown_byte_color", Color, Color(0xF0, 0x00, 0x00)),
    CE("disasm_view_unknown_character_color", Color, Color(0xF0, 0x00, 0x00)),
    CE("disasm_view_back_edge_color", Color, Color(0xF9, 0xD5, 0x77)),
    CE("disasm_view_true_edge_color", Color, Color(0x79, 0xCC, 0xCD)),
    CE("disasm_view_false_edge_color", Color, Color(0xF1, 0x66, 0x64)),
    CE("disasm_view_direct_jump_edge_color", Color, Color(0x56, 0x5A, 0x5C)),
    CE("disasm_view_exception_edge_color", Color, Color(0xF9, 0x91, 0x0A)),
    CE("hex_view_selection_color", Color, Color(0xFF, 0x00, 0x00)),
    CE("hex_view_selection_alt_color", Color, Color(0xA0, 0xA0, 0xA4)),
    CE("hex_view_data_color", Color, Color(0x00, 0x00, 0xFF)),
    CE("hex_view_string_color", Color, Color(0x00, 0xFF, 0xFF)),
    CE("hex_view_instruction_color", Color, Color(0xFF, 0x00, 0xFF)),
    CE("function_table_color", Color, Color(0x00, 0x00, 0x00)),
    CE("function_table_syscall_color", Color, Color(0x00, 0x00, 0x80)),
    CE("function_table_plt_color", Color, Color(0x00, 0x80, 0x00)),
    CE("function_table_simprocedure_color", Color, Color(0x80, 0x00, 0x00)),
    CE("function_table_alignment_color", Color, Color(0x80, 0x00, 0x80)),
    CE("function_table_signature_bg_color", Color, Color(0xAA, 0xFF, 0xFF)),
    CE("ast_viewer_concrete_color", Color, Color(0x00, 0x00, 0xFF)),
    CE("ast_viewer_symbolic_color", Color, Color(0x00, 0x80, 0x00)),
    CE("memory_viewer_address_color", Color, Color(0x00, 0x00, 0x00)),
    CE("memory_viewer_data_color", Color, Color(0x00, 0x00, 0x00)),
    CE("palette_window", Color, Color(0xEF, 0xEF, 0xEF, 0xFF)),
    CE("palette_windowtext", Color, Color(0x00, 0x00, 0x00, 0xFF)),
    CE("palette_base", Color, Color(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("palette_alternatebase", Color, Color(0xF7, 0xF7, 0xF7, 0xFF)),
    CE("palette_tooltipbase", Color, Color(0xFF, 0xFF, 0xDC, 0xFF)),
    CE("palette_tooltiptext", Color, Color(0x00, 0x00, 0x00, 0xFF)),
    CE("palette_placeholdertext", Color, Color(0x00, 0x00, 0x00, 0xAF)),
    CE("palette_text", Color, Color(0x00, 0x00, 0x00, 0xFF)),
    CE("palette_button", Color, Color(0xEF, 0xEF, 0xEF, 0xFF)),
    CE("palette_buttontext", Color, Color(0x00, 0x00, 0x00, 0xFF)),
    CE("palette_brighttext", Color, Color(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("palette_highlight", Color, Color(0x30, 0x8C, 0xC6, 0xFF)),
    CE("palette_highlightedtext", Color, Color(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("palette_disabled_text", Color, Color(0xBE, 0xBE, 0xBE, 0xFF)),
    CE("palette_disabled_buttontext", Color, Color(0xBE, 0xBE, 0xBE, 0xFF)),
    CE("palette_disabled_windowtext", Color, Color(0xBE, 0xBE, 0xBE, 0xFF)),
    CE("palette_light", Color, Color(0xFF, 0xFF, 0xFF, 0xFF)),
    CE("palette_midlight", Color, Color(0xCA, 0xCA, 0xCA, 0xFF)),
    CE("palette_dark", Color, Color(0x9F, 0x9F, 0x9F, 0xFF)),
    CE("palette_mid", Color, Color(0xB8, 0xB8, 0xB8, 0xFF)),
    CE("palette_shadow", Color, Color(0x76, 0x76, 0x76, 0xFF)),
    CE("palette_link", Color, Color(0x00, 0x00, 0xFF, 0xFF)),
    CE("palette_linkvisited", Color, Color(0xFF, 0x00, 0xFF, 0xFF)),
    CE("pseudocode_bookmark_color", Color, Color(0xFF, 0xD5, 0x4F, 0x60)),
    CE("pseudocode_comment_color", Color, Color(0x00, 0x80, 0x00, 0xFF)),
    CE("pseudocode_comment_weight", FontWeight, FontWeight(500)),
    CE("pseudocode_comment_style", FontStyle, FontStyle.NORMAL),
    CE("pseudocode_function_color", Color, Color(0x00, 0x00, 0xFF, 0xFF)),
    CE("pseudocode_function_weight", FontWeight, FontWeight(500)),
    CE("pseudocode_function_style", FontStyle, FontStyle.NORMAL),
    CE("pseudocode_library_function_color", Color, Color(0xFF, 0x00, 0xFF)),
    CE("pseudocode_quotation_color", Color, Color(0x00, 0x80, 0x00, 0xFF)),
    CE("pseudocode_quotation_weight", FontWeight, FontWeight(500)),
    CE("pseudocode_quotation_style", FontStyle, FontStyle.NORMAL),
    CE("pseudocode_keyword_color", Color, Color(0x00, 0x00, 0x80, 0xFF)),
    CE("pseudocode_keyword_weight", FontWeight, FontWeight(500)),
    CE("pseudocode_keyword_style", FontStyle, FontStyle.NORMAL),
    CE("pseudocode_types_color", Color, Color(0x00, 0x00, 0x80, 0xFF)),
    CE("pseudocode_types_weight", FontWeight, FontWeight(500)),
    CE("pseudocode_types_style", FontStyle, FontStyle.NORMAL),
    CE("pseudocode_variable_color", Color, Color(0x00, 0x00, 0x00, 0xFF)),
    CE("pseudocode_variable_weight", FontWeight, FontWeight(500)),
    CE("pseudocode_variable_style", FontStyle, FontStyle.NORMAL),
    CE("pseudocode_global_variable_color", Color, Color(0x00, 0x00, 0xFF)),
    CE("pseudocode_global_variable_weight", FontWeight, FontWeight(500)),
    CE("pseudocode_global_variable_style", FontStyle, FontStyle.NORMAL),
    CE("pseudocode_label_color", Color, Color(0x00, 0x00, 0xFF)),
    CE("pseudocode_label_weight", FontWeight, FontWeight(500)),
    CE("pseudocode_label_style", FontStyle, FontStyle.NORMAL),
    CE("pseudocode_highlight_color", Color, Color(0xFF, 0xFF, 0x00, 0xFF)),
    # lines of a discovered pattern family, shown after double-clicking it in the Discover table
    CE("pseudocode_pattern_highlight_color", Color, Color(0x64, 0xB5, 0xF6, 0x50)),
    CE("proximity_node_background_color", Color, Color(0xFA, 0xFA, 0xFA)),
    CE("proximity_node_selected_background_color", Color, Color(0xCC, 0xCC, 0xCC)),
    CE("proximity_node_border_color", Color, Color(0xF0, 0xF0, 0xF0)),
    CE("proximity_function_node_text_color", Color, Color(0xFF, 0x00, 0x00)),
    CE("proximity_string_node_text_color", Color, Color(0x00, 0x80, 0x00)),
    CE("proximity_integer_node_text_color", Color, Color(0x00, 0x00, 0x80)),
    CE("proximity_variable_node_text_color", Color, Color(0x00, 0x00, 0x80)),
    CE("proximity_unknown_node_text_color", Color, Color(0x00, 0x00, 0x80)),
    CE("proximity_call_node_text_color", Color, Color(0x00, 0x00, 0xFF)),
    CE("proximity_call_node_text_color_plt", Color, Color(0x8B, 0x00, 0x8B)),
    CE("proximity_call_node_text_color_simproc", Color, Color(0x8B, 0x00, 0x8B)),
    CE("log_timestamp_format", str, "%X"),
    # maximum number of matches an incremental find bar collects before reporting "N+"
    CE("find_match_limit", int, 10000),
    # FLIRT signatures
    CE("flirt_signatures_root", str, "./angrmanagement/resources/flirt_signatures/flirt_signatures/"),
    # Library documentation
    CE("library_docs_root", str, "./angrmanagement/resources/library_docs/"),
    # feature map
    CE("feature_map_regular_function_color", Color, Color(0x00, 0xA0, 0xE8)),
    CE("feature_map_unknown_color", Color, Color(0x0A, 0x0A, 0x0A)),
    CE("feature_map_delimiter_color", Color, Color(0x00, 0x00, 0x00)),
    CE("feature_map_data_color", Color, Color(0xC0, 0xC0, 0xC0)),
    CE("feature_map_string_color", Color, Color(0x00, 0xF0, 0x80)),
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
    CE("last_used_directory", str, ""),
    CE("prompted_for_url_scheme_registration", bool, False),
    # LLM settings
    CE("llm_model", str, ""),
    CE("llm_api_key", str, ""),
    CE("llm_api_base", str, ""),
    CE("llm_preload_callees", bool, False),
    CE("llm_auto_rename_variables", bool, False),
    CE("llm_auto_rename_function", bool, False),
    CE("llm_auto_retype_variables", bool, False),
    CE("llm_auto_summarize", bool, False),
    # MCP server
    CE("mcp_server_port", int, 8642),
    CE("mcp_server_autostart", bool, False),
    CE("mcp_server_auth_enabled", bool, False),
    CE("mcp_server_auth_token", str, ""),
    # Maximum number of MCP tool calls retained in the MCP History view (0 or less = unlimited).
    CE("mcp_server_history_limit", int, 2000),
    # Terminal frontend: area sizes and whether the bottom area is hidden, as JSON
    CE("tui_layout", str, ""),
]


class _FrontendListener:
    """
    Calls a ``Conf.connect`` listener with the value converted for the frontend.

    A listener that takes no arguments is called with none, as a Qt slot that takes fewer arguments than its signal
    is.
    """

    __slots__ = ("_key", "_manager", "_takes_value", "func")

    def __init__(self, manager: ConfigurationManager, key: str, func: Callable[..., None]) -> None:
        self._manager = manager
        self._key = key
        self.func = func
        self._takes_value = max_positional_args(func) != 0

    def __call__(self, value) -> None:
        self.deliver(self._manager.frontend_value(self._key, value))

    def deliver(self, frontend_value) -> None:
        """Call the listener with ``frontend_value``, already converted for the frontend, or with nothing."""
        if self._takes_value:
            self.func(frontend_value)
        else:
            self.func()

    def __eq__(self, other) -> bool:
        return isinstance(other, _FrontendListener) and other._key == self._key and other.func == self.func

    def __hash__(self) -> int:
        return hash((self._key, self.func))


class ConfigurationManager:  # pylint: disable=assigning-non-slot
    """
    Globe Configuration Manager for UI configuration with save/load function

    Values are stored in a frontend-neutral form. A frontend installs a FrontendAdapter with set_frontend_adapter();
    attribute reads and writes go through it, so the Qt frontend reads and assigns QColor and QFont objects.
    """

    __slots__ = (
        "_entries",
        "_adapter",
        "_frontend_cache",
        "_metrics_cache",
    )

    def __init__(self, entries=None) -> None:
        self._adapter: FrontendAdapter = HeadlessFrontendAdapter()
        # entry name -> (stored value, frontend value); the stored value is compared by identity
        self._frontend_cache: dict[str, tuple[Any, Any]] = {}
        # font entry name -> (stored FontSpec, (height, width, ascent))
        self._metrics_cache: dict[str, tuple[Any, tuple[float, float, float]]] = {}

        if entries is None:
            self._entries = {}
            self.load_initial_entries(reset=True)
        else:
            self._entries = entries

    def load_initial_entries(self, reset: bool = True) -> None:
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

    #
    # Frontend adapter
    #

    def set_frontend_adapter(self, adapter: FrontendAdapter | None) -> None:
        """Install the adapter of the running frontend; None goes back to the headless one."""
        self._adapter = HeadlessFrontendAdapter() if adapter is None else adapter
        self._frontend_cache.clear()
        self._metrics_cache.clear()

    @property
    def frontend_adapter(self) -> FrontendAdapter:
        return self._adapter

    def frontend_value(self, name: str, value: Any) -> Any:
        """Convert a stored value of entry ``name`` (it need not be the current one) for the frontend."""
        return self._adapter.to_frontend(name, value)

    def entry(self, name: str) -> CE:
        """
        The configuration entry ``name``. Its ``changed`` signal and ``value`` carry stored, neutral values.

        :raises KeyError: If there is no such entry.
        """
        return self._entries[name]

    def _font_metrics(self, name: str) -> tuple[float, float, float]:
        font = self._entries[name].value
        cached = self._metrics_cache.get(name)
        if cached is not None and cached[0] is font:
            return cached[1]
        metrics = self._adapter.font_metrics(font)
        self._metrics_cache[name] = (font, metrics)
        return metrics

    def _font_metrics_object(self, name: str):
        return self._adapter.font_metrics_object(self._entries[name].value)

    disasm_font: Any
    symexec_font: Any
    code_font: Any

    @property
    def disasm_font_metrics(self):
        return self._font_metrics_object("disasm_font")

    @property
    def disasm_font_height(self):
        return self._font_metrics("disasm_font")[0]

    @property
    def disasm_font_width(self):
        return self._font_metrics("disasm_font")[1]

    @property
    def disasm_font_ascent(self):
        return self._font_metrics("disasm_font")[2]

    @property
    def symexec_font_metrics(self):
        return self._font_metrics_object("symexec_font")

    @property
    def symexec_font_height(self):
        return self._font_metrics("symexec_font")[0]

    @property
    def symexec_font_width(self):
        return self._font_metrics("symexec_font")[1]

    @property
    def symexec_font_ascent(self):
        return self._font_metrics("symexec_font")[2]

    @property
    def code_font_metrics(self):
        return self._font_metrics_object("code_font")

    @property
    def code_font_height(self):
        return self._font_metrics("code_font")[0]

    @property
    def code_font_width(self):
        return self._font_metrics("code_font")[1]

    @property
    def code_font_ascent(self):
        return self._font_metrics("code_font")[2]

    def init_font_config(self) -> None:
        defaults = self._adapter.default_fonts()
        if self._entries["ui_default_font"].value == _FONT_UNSET:
            self.ui_default_font = defaults["ui_default_font"]
        if self._entries["tabular_view_font"].value == _FONT_UNSET:
            self.tabular_view_font = defaults["tabular_view_font"]

    recent_files: list[str]

    def recent_file(self, file_path: str) -> None:
        with contextlib.suppress(ValueError):
            self.recent_files.remove(file_path)
        self.recent_files = self.recent_files[:9]
        self.recent_files.append(file_path)

    def __getattr__(self, item):
        if item in self.__slots__ or item in type(self).__dict__:
            return super().__getattribute__(item)

        if item in self._entries:
            value = self._entries[item].value
            cached = self._frontend_cache.get(item)
            if cached is not None and cached[0] is value:
                return cached[1]
            converted = self._adapter.to_frontend(item, value)
            self._frontend_cache[item] = (value, converted)
            return converted

        raise AttributeError(item)

    def __setattr__(self, key, value) -> None:
        if key in self.__slots__ or key in type(self).__dict__:
            super().__setattr__(key, value)
            return

        if key in self._entries:
            entry = self._entries[key]
            value = self._adapter.from_frontend(key, value)
            if entry.type_ is FontWeight and isinstance(value, int) and not isinstance(value, FontWeight | bool):
                value = FontWeight(value)
            entry.value = value
            return

        raise AttributeError(key)

    def connect(self, key: str, func: Callable[..., None], init: bool) -> None:
        """
        Connect func to the signal emitted when the key changes; func receives the value as the frontend sees it,
        or nothing if it takes no arguments. If init, calls func the same way on the current value after connecting.
        """
        listener = _FrontendListener(self, key, func)
        self._entries[key].changed.connect(listener)
        if init:
            listener.deliver(getattr(self, key))

    def disconnect(self, key: str, func: Callable[..., None]) -> None:
        """
        Disconnect func from the signal emitted when the key changes
        """
        self._entries[key].changed.disconnect(_FrontendListener(self, key, func))

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
                    if entry.default_value is None:
                        entry_map[k] = UninterpretedCE(k, v)
                    else:
                        entry_map[k].value = entry.default_value
        except tomlkit.exceptions.ParseError:
            _l.error("Failed to parse configuration file: '%s'. Continuing with default options...", exc_info=True)

        # load color scheme configuration
        if (
            "theme_name" in entry_map
            and "base_theme_name" in entry_map
            and entry_map["theme_name"].value == entry_map["base_theme_name"].value
        ):
            cls.load_default_theme_entries(entry_map["theme_name"].value, entry_map)

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

    def reinterpet(self) -> None:
        """
        Walks the ENTRIES list, trying to update self's entries with respect to anything that may have been added to
        the global list. Tries to fix up UninterpretedCEs. Should be called e.g. after loading plugins.
        """
        for entry in ENTRIES:
            my_entry = self._entries.get(entry.name, None)
            if my_entry is None:
                # an entry the loaded file did not mention starts at its default
                self._entries[entry.name] = entry.copy()
                continue

            if type(my_entry) is UninterpretedCE:
                value = self.deserialize(entry.type_, entry.name, my_entry.value)
                if value is not None:
                    new_entry = entry.copy()
                    new_entry.value = value
                    self._entries[entry.name] = new_entry

    @classmethod
    def parse_file(cls, path: str, ignore_unknown_entries: bool = False):
        with open(path, encoding="utf-8") as f:
            return cls.parse(f, ignore_unknown_entries=ignore_unknown_entries)

    def save(self, f) -> None:
        out = {}

        entries_to_save = self._entries.copy()
        if (
            "theme_name" not in entries_to_save
            or "base_theme_name" in entries_to_save
            or entries_to_save["theme_name"].value == entries_to_save["base_theme_name"].value
        ):
            # we do not save theme-related entries if the theme is one of the default themes
            self.remove_default_theme_entries(entries_to_save)

        for k, v in entries_to_save.items():
            v = v.value
            while type(v) in data_serializers:
                v = data_serializers[type(v)][1](k, v)
            out[k] = v

        tomlkit.dump(out, f)

    def save_file(self, path: str) -> None:
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
                    GlobalInfo.ui_services.message(
                        "warning",
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

    @staticmethod
    def load_default_theme_entries(theme_name: str, entries: dict[str, Any]) -> None:
        """
        Load theme-related entries from the configuration dictionary if the theme is one of the default themes.

        :param theme_name:  The name of the theme.
        :param entries:     The configuration dictionary.
        :return: None
        """
        if not COLOR_SCHEMES or theme_name not in COLOR_SCHEMES:
            return

        theme = (
            COLOR_SCHEMES[theme_name]
            if theme_name == BASE_SCHEME
            else {**COLOR_SCHEMES[BASE_SCHEME], **COLOR_SCHEMES[theme_name]}
        )
        for k, v in theme.items():
            entries[k] = CE(k, type(v), v)

    @staticmethod
    def remove_default_theme_entries(entries: dict[str, Any]) -> None:
        """
        Remove theme-related entries from the configuration dictionary if the theme is one of the default themes.

        :param entries:     The configuration dictionary.
        :return: None
        """
        if not COLOR_SCHEMES:
            return
        all_theme_keys = set()
        for theme in COLOR_SCHEMES.values():
            all_theme_keys.update(theme.keys())

        for entry_name in list(entries):
            if entry_name in all_theme_keys:
                del entries[entry_name]

    @property
    def has_operation_mango(self) -> bool:
        try:
            import argument_resolver  # noqa

            return True
        except ImportError:
            return False
