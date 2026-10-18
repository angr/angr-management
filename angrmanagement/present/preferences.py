"""
The Preferences dialog without a toolkit: what each page shows and what saving it writes to the configuration.

The pages are the Qt dialog's: OS Integration (the angr:// URL scheme and the daemon), Theme and Colors (a scheme and
every colour entry of ``ENTRIES``), Style (the log's timestamp format and the fonts), LLM and MCP Server. Both
frontends' pages read their starting values and save through the functions here, so they write the same entries.
"""

from __future__ import annotations

import enum
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, get_args

from bidict import bidict

from angrmanagement.config import Conf
from angrmanagement.config.color import Color
from angrmanagement.config.config_manager import ENTRIES
from angrmanagement.config.font import FontWeight
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.url_scheme import AngrUrlScheme

from .theme import CUSTOM_SCHEME_NAME, scheme_colors, scheme_names

if TYPE_CHECKING:
    from collections.abc import Mapping

_l = logging.getLogger(__name__)

#: The pages, in the dialog's order.
PAGE_NAMES = ("OS Integration", "Theme and Colors", "Style", "LLM", "MCP Server")

#: The font entries the Style page edits: caption and entry name.
FONT_ENTRIES = (
    ("Application Font", "ui_default_font"),
    ("Tabular View Font", "tabular_view_font"),
    ("Disassembly Font", "disasm_font"),
    ("SymExc Font", "symexec_font"),
    ("Code Font", "code_font"),
)

#: The LLM page's switches: entry name and caption.
LLM_SWITCHES = (
    ("llm_preload_callees", "Auto-refine callees after decompilation"),
    ("llm_auto_rename_variables", "Auto-rename variables after decompilation"),
    ("llm_auto_rename_function", "Auto-rename function after decompilation"),
    ("llm_auto_retype_variables", "Auto-retype variables after decompilation"),
    ("llm_auto_summarize", "Auto-summarize function after decompilation"),
)

MCP_TEXT = (
    "The MCP server lets an AI agent analyze the loaded binary and show results "
    "(such as updated decompilation) live in angr management.\n"
    "Start and stop it from the AI menu. It listens on localhost only."
)

#
# OS integration
#


def url_scheme_state() -> tuple[bool, bool, str]:
    """Whether this OS can register the angr:// scheme, whether it is registered, and to what."""
    try:
        registered, register_as = AngrUrlScheme().is_url_scheme_registered()
    except NotImplementedError:
        return False, False, ""
    return True, registered, str(register_as) if registered else ""


def save_integration(register_url_scheme: bool, use_daemon: bool) -> None:
    """Register or unregister the URL scheme if that changed, and turn the daemon on or off."""
    scheme = AngrUrlScheme()
    try:
        registered, _ = scheme.is_url_scheme_registered()
        if registered != register_url_scheme:
            if register_url_scheme:
                scheme.register_url_scheme()
            else:
                scheme.unregister_url_scheme()
    except NotImplementedError:
        # the current OS is not supported
        pass
    Conf.use_daemon = use_daemon
    main_window: Any = GlobalInfo.main_window
    if Conf.use_daemon and not GlobalInfo.client_id and hasattr(main_window, "_run_daemon"):
        main_window._run_daemon()  # pylint:disable=protected-access


#
# Theme and colours
#


def color_entry_names() -> list[str]:
    """The colour entries, in the order of ENTRIES: the rows of the colour sheet."""
    return [ce.name for ce in ENTRIES if ce.type_ is Color]


def styled_entry_names() -> list[str]:
    """The font weight and other enum entries a colour scheme may set besides colours."""
    return [ce.name for ce in ENTRIES if ce.type_ is not Color and (ce.type_ is FontWeight or _is_enum(ce.type_))]


def _is_enum(type_: Any) -> bool:
    return isinstance(type_, type) and issubclass(type_, enum.Enum)


def theme_choices() -> list[str]:
    """The schemes the Load Theme box offers: the built-in ones, sorted, then Custom."""
    return scheme_names()


def scheme_entry_values(name: str) -> dict[str, Any]:
    """The entries picking the scheme ``name`` sets (the base scheme under it); nothing for Custom."""
    if name == CUSTOM_SCHEME_NAME:
        return {}
    try:
        return scheme_colors(name)
    except KeyError:
        return {}


def current_theme_values() -> tuple[dict[str, Color], dict[str, Any]]:
    """The colour entries now, and the other entries a scheme sets, as the Theme and Colors page starts with them."""
    colors = {name: getattr(Conf, name) for name in color_entry_names()}
    others = {name: Conf.entry(name).value for name in styled_entry_names()}
    return colors, others


def save_theme(theme_name: str, base_theme_name: str, colors: Mapping[str, Color], others: Mapping[str, Any]) -> None:
    """Write the Theme and Colors page: the scheme, its base, every colour and the scheme's other entries."""
    Conf.theme_name = theme_name
    Conf.base_theme_name = base_theme_name
    for name, value in colors.items():
        setattr(Conf, name, value)
    for name, value in others.items():
        setattr(Conf, name, value)


def parse_color(text: str) -> Color | None:
    """A colour the user typed in the sheet (``#rrggbb``, ``#aarrggbb``, ...); None if it is not one."""
    try:
        return Color.from_hex(text.strip())
    except ValueError:
        return None


def color_text(color: Color) -> str:
    """How the colour sheet shows a colour: ``#rrggbb``, or ``#aarrggbb`` when it is not opaque."""
    return f"#{color.rgb_hex}" if color.a == 255 else f"#{color.hex}"


#
# Style
#


def log_format_choices(fmt: str | None = None) -> tuple[bidict, str]:
    """
    The log timestamp formats offered, as (a timestamp shown in the format -> the format), and the one shown now:
    the current format, the locale's time and the locale's date and time.
    """
    fmt = str(Conf.log_timestamp_format) if fmt is None else fmt
    ts = datetime.now()
    fmt_map = bidict({ts.strftime(i): i for i in [fmt, "%X", "%c"]})
    inverse = {name: shown for shown, name in fmt_map.items()}
    if fmt not in inverse:
        fmt = fmt_map[ts.strftime(fmt)]
    return fmt_map, inverse[fmt]


def save_log_format(text: str, fmt_map: Mapping[str, str]) -> None:
    """Save what the format box holds: a shown timestamp stands for its format, anything else is a format."""
    if text:
        Conf.log_timestamp_format = fmt_map.get(text, text)


def font_texts() -> list[tuple[str, str]]:
    """Each font entry's caption and its value, as the Style page lists them."""
    return [(caption, str(getattr(Conf, key))) for caption, key in FONT_ENTRIES]


#
# LLM
#

_known_model_names: list[str] | None = None


def known_model_names() -> list[str]:
    """A sorted list of model names that pydantic-ai supports, or none when it is not installed."""
    global _known_model_names  # pylint:disable=global-statement
    if _known_model_names is not None:
        return _known_model_names
    try:
        from pydantic_ai.models import KnownModelName  # pylint: disable=import-outside-toplevel

        value = getattr(KnownModelName, "__value__", KnownModelName)
        names = get_args(value)
        _known_model_names = sorted(str(n) for n in names) if names else []
    except (ImportError, AttributeError):
        _l.debug("Failed to load pydantic-ai model names", exc_info=True)
        _known_model_names = []
    return _known_model_names


def llm_values() -> dict[str, Any]:
    """The LLM page's values: the model, the key, the base URL and the switches."""
    values: dict[str, Any] = {
        "llm_model": Conf.llm_model,
        "llm_api_key": Conf.llm_api_key,
        "llm_api_base": Conf.llm_api_base,
    }
    for name, _caption in LLM_SWITCHES:
        values[name] = getattr(Conf, name)
    return values


def save_llm(values: Mapping[str, Any], workspace: Any = None) -> None:
    """Write the LLM page, and give the loaded project a client for the model (none without one)."""
    for name in ("llm_model", "llm_api_key", "llm_api_base"):
        setattr(Conf, name, str(values[name]).strip())
    for name, _caption in LLM_SWITCHES:
        setattr(Conf, name, bool(values[name]))
    sync_llm_client(workspace)


def sync_llm_client(workspace: Any) -> None:
    """Give the loaded project an LLM client for the configured model, or take it away when there is no model."""
    if workspace is None:
        return
    instance = workspace.main_instance
    if instance is None or instance.project.am_none:
        return
    model = Conf.llm_model
    if model:
        try:
            from angr.llm_client import LLMClient  # pylint: disable=import-outside-toplevel

            instance.project.am_obj.llm_client = LLMClient(
                model=model,
                api_key=Conf.llm_api_key or None,
                api_base=Conf.llm_api_base or None,
            )
        except ImportError:
            pass
    else:
        instance.project.am_obj.llm_client = None


#
# MCP
#


def mcp_values() -> dict[str, Any]:
    return {
        "mcp_server_port": Conf.mcp_server_port,
        "mcp_server_autostart": Conf.mcp_server_autostart,
        "mcp_server_history_limit": max(0, Conf.mcp_server_history_limit),
        "mcp_server_auth_enabled": Conf.mcp_server_auth_enabled,
        "mcp_server_auth_token": Conf.mcp_server_auth_token,
    }


def save_mcp(values: Mapping[str, Any]) -> None:
    Conf.mcp_server_port = int(values["mcp_server_port"])
    Conf.mcp_server_autostart = bool(values["mcp_server_autostart"])
    Conf.mcp_server_history_limit = int(values["mcp_server_history_limit"])
    Conf.mcp_server_auth_enabled = bool(values["mcp_server_auth_enabled"])
    Conf.mcp_server_auth_token = str(values["mcp_server_auth_token"]).strip()


def generate_auth_token() -> str:
    from angrmanagement.mcp import MCPServerManager  # pylint: disable=import-outside-toplevel

    return MCPServerManager.generate_auth_token()


__all__ = [
    "FONT_ENTRIES",
    "LLM_SWITCHES",
    "MCP_TEXT",
    "PAGE_NAMES",
    "color_entry_names",
    "color_text",
    "current_theme_values",
    "font_texts",
    "generate_auth_token",
    "known_model_names",
    "llm_values",
    "log_format_choices",
    "mcp_values",
    "parse_color",
    "save_integration",
    "save_llm",
    "save_log_format",
    "save_mcp",
    "save_theme",
    "scheme_entry_values",
    "styled_entry_names",
    "sync_llm_client",
    "theme_choices",
    "url_scheme_state",
]
