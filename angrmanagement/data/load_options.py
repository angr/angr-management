"""
Load options for a new binary, computed without widgets.

The Load Binary dialog (angrmanagement.ui.dialogs.load_binary) fills its widgets from the suggestions here and turns
what the user picked into load options with :func:`build_load_options`. :func:`default_load_options` makes the same
options from the dialog's preselected values, which is what a frontend with nobody to ask uses.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import archinfo
import cle
from angr.calling_conventions import unify_arch_name
from angr.simos import os_mapping
from cle.backends.pe.symbolserver import SymbolPathParser

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule

try:
    import pypcode
except ImportError:
    pypcode = None

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

# cart is the only outer backend that takes an encryption key, and this is the load option it takes it in
CART_BACKEND_NAME = "cart"
CART_ENCKEY_ARGNAME = "arc4_key"

#: the outer backend choice that means "none"
NO_OUTER_BACKEND = "<None>"
#: the operating system choice that means "unknown"
UNKNOWN_SIMOS = "Unknown"


def key_to_hex(key: bytes) -> str:
    """
    Render a key the way the encryption key dialog expects it to be typed back in.
    """
    return " ".join(f"{x:02x}" for x in key)


@dataclass
class LoadOptions:
    """
    What loading a binary needs: the keyword arguments for angr.Project's ``load_options`` and the SimOS class.

    It unpacks like the ``(load_options, simos)`` tuple that LoadBinary.run returns.
    """

    load_options: dict[str, Any]
    simos: type | None

    def __iter__(self) -> Iterator[Any]:
        yield self.load_options
        yield self.simos


@dataclass
class LoadSelection:
    """The choices the Load Binary dialog offers, as plain values."""

    backend: str
    simos_name: str
    arch: Any
    outer_backend: str | None = None
    auto_load_libs: bool = False
    load_debug_info: bool = True
    force_load_libs: list[str] = field(default_factory=list)
    skip_libs: set[str] = field(default_factory=set)
    base_addr: int | None = None
    entry_addr: int | None = None
    offset: int | None = None
    # PE only: whether debug symbols may be downloaded, and the symbol path entries as (type, cache, path) rows
    allow_symbol_download: bool = True
    symbol_path_rows: list[tuple[str, str, str]] = field(default_factory=list)
    enckey: bytes | None = None


def available_backends() -> dict[str, type[cle.Backend]]:
    return cle.ALL_BACKENDS


def available_simos() -> dict[str, type | None]:
    """SimOS classes by class name, plus ``Unknown`` for None."""
    simos_by_name: dict[str, type | None] = {}
    for simos in os_mapping.values():
        simos_by_name[simos.__name__] = simos
    simos_by_name[UNKNOWN_SIMOS] = None
    return simos_by_name


def available_archs() -> list[Any]:
    """The archinfo architectures, then the P-code languages when pypcode is installed."""
    archs: list[Any] = archinfo.all_arches[::]
    if pypcode:
        for arch in pypcode.Arch.enumerate():
            archs.extend(sorted(arch.languages, key=lambda lang: lang.id))
    return archs


def requested_dependencies(partial_ld: cle.Loader) -> list[str]:
    return sorted(partial_ld.requested_names)


def loaded_addresses(partial_ld: cle.Loader) -> tuple[int | None, int | None, int]:
    """The (base address, entry point, file offset) the partial load found for the main object."""
    base_addr: int | None = None
    entry_addr: int | None = None
    offset = 0
    main_object = partial_ld.main_object
    if main_object is not None:
        if isinstance(main_object, cle.MetaELF | cle.PE | cle.MachO | cle.CGC):
            base_addr = main_object.mapped_base
            entry_addr = main_object.entry
            offset = getattr(main_object, "offset", 0)
        else:
            if hasattr(main_object, "mapped_base"):
                base_addr = main_object.mapped_base
            if hasattr(main_object, "entry"):
                entry_addr = main_object.entry
            offset = getattr(main_object, "offset", offset)
    return base_addr, entry_addr, offset


def split_arches(partial_ld: cle.Loader, all_arches: list[Any]) -> tuple[Any, list, list]:
    """
    Split a list of architectures into three categories: The (probably) ideal architecture, recommended
    architectures, and other architectures.
    """
    the_arch = None
    recommended_arches = []
    other_arches = []
    self_arch = partial_ld.main_object.arch
    self_arch_str = str(self_arch)
    arch_names = partial_ld.main_object.available_arches if partial_ld.main_object is not None else []

    for arch in all_arches:
        if isinstance(arch, archinfo.Arch):
            if str(arch) == self_arch_str:
                the_arch = arch
            elif arch.name in arch_names:
                recommended_arches.append(arch)
            else:
                other_arches.append(arch)
        elif pypcode and isinstance(arch, pypcode.ArchLanguage):
            if self_arch is not None:
                if self_arch.name == arch.id:
                    the_arch = arch
                elif self_arch.name.lower() in arch.id.lower() or self_arch.name == unify_arch_name(arch.id):
                    recommended_arches.append(arch)
                else:
                    other_arches.append(arch)
        else:
            raise TypeError(f"Unknown architecture type {type(arch)}")

    return the_arch, recommended_arches, other_arches


def suggested_outer_backend_name(suggested_original_backend: type[cle.Backend] | None) -> str | None:
    """The name of the outer backend to preselect, or None for none. Of several names for it, the last one."""
    name = None
    for backend_name, backend in available_backends().items():
        if getattr(backend, "is_outer", False) is True and backend is suggested_original_backend:
            name = backend_name
    return name


def inner_backend_names() -> list[str]:
    return [name for name, backend in available_backends().items() if getattr(backend, "is_outer", False) is False]


def suggested_backend_name(suggested_backend: type[cle.Backend] | None) -> str | None:
    """The name of the backend that matches ``suggested_backend``, or None. Of several names for it, the last one."""
    name = None
    for backend_name, backend in available_backends().items():
        if getattr(backend, "is_outer", False) is False and backend is suggested_backend:
            name = backend_name
    return name


def suggested_simos_name(suggested_os_name: str | None, simos_by_name: dict[str, type | None]) -> str:
    """The SimOS to preselect: the one for ``suggested_os_name`` if there is one, else ``Unknown``."""
    name = UNKNOWN_SIMOS
    if suggested_os_name is not None:
        suggested_os = os_mapping[suggested_os_name].__name__
        if suggested_os in simos_by_name:
            name = suggested_os
    return name


def symbol_path_rows(text: str) -> list[tuple[str, str, str]]:
    """Parse a symbol path string such as ``_NT_SYMBOL_PATH`` into (type, cache, path or server) rows."""
    rows = []
    for entry in SymbolPathParser.parse(text):
        match entry.entry_type:
            case "local":
                cache = ""
                path = entry.local_path
            case "srv" | "symsrv":
                cache = entry.cache_path
                path = entry.server_url
            case "cache":
                cache = entry.cache_path
                path = ""
            case _:
                cache = path = ""
        rows.append((entry.entry_type, cache, path))
    return rows


def symbol_paths_from_rows(rows: list[tuple[str, str, str]]) -> list[str]:
    """Turn (type, cache, path or server) rows back into symbol path entries."""
    symbol_paths = []
    for entry_type, cache, path in rows:
        match entry_type:
            case "local":
                symbol_paths.append(path)
            case "srv" | "symsrv":
                if path:
                    if cache:
                        symbol_paths.append(f"srv*{cache}*{path}")
                    else:
                        symbol_paths.append(f"srv*{path}")
            case "cache":
                if cache:
                    symbol_paths.append(f"cache*{cache}")
    return symbol_paths


def build_load_options(
    partial_ld: cle.Loader,
    selection: LoadSelection,
    suggested_main_opts: dict | None = None,
    suggested_main_filename: str | None = None,
    confirm_symbol_download: Callable[[str], bool] | None = None,
    symbol_download_progress: Callable[[int, int | None], bool] | None = None,
) -> LoadOptions:
    """Turn the choices of a Load Binary dialog into load options."""
    suggested_main_opts = suggested_main_opts or {}
    load_options: dict[str, Any] = {}
    load_options["auto_load_libs"] = selection.auto_load_libs
    load_options["load_debug_info"] = selection.load_debug_info

    arch = selection.arch
    if pypcode and isinstance(arch, pypcode.ArchLanguage):
        arch = archinfo.ArchPcode(arch.id)
    load_options["arch"] = arch

    # options for the object the user picked a backend for. it ends up in either main_opts or, when an outer
    # backend unpacks it, lib_opts.
    main_opts: dict[str, Any] = {
        "backend": selection.backend,
    }
    if selection.base_addr is not None:
        main_opts["base_addr"] = selection.base_addr
    if selection.entry_addr is not None:
        main_opts["entry_point"] = selection.entry_addr
    if selection.offset is not None:
        main_opts["offset"] = selection.offset

    if selection.force_load_libs:
        load_options["force_load_libs"] = selection.force_load_libs
    if selection.skip_libs:
        load_options["skip_libs"] = selection.skip_libs

    # symbol search options for PE files
    if isinstance(partial_ld.main_object, cle.PE):
        main_opts["download_debug_symbols"] = selection.allow_symbol_download
        symbol_paths = symbol_paths_from_rows(selection.symbol_path_rows)
        if symbol_paths:
            main_opts["symbol_paths"] = ";".join(symbol_paths)
        if confirm_symbol_download is not None:
            main_opts["download_debug_symbol_confirm"] = confirm_symbol_download
        if symbol_download_progress is not None:
            main_opts["download_debug_symbol_progress"] = symbol_download_progress

    if selection.outer_backend is not None:
        # the outer backend is the real main object; the options above apply to the object it unpacks
        outer_main_opts = {
            "backend": selection.outer_backend,
        } | suggested_main_opts
        if selection.outer_backend == CART_BACKEND_NAME and selection.enckey is not None:
            # the key the user picked wins over the one the partial load used
            outer_main_opts[CART_ENCKEY_ARGNAME] = selection.enckey
        load_options["main_opts"] = outer_main_opts
        if suggested_main_filename is not None:
            load_options["lib_opts"] = {
                suggested_main_filename: main_opts,
            }
    else:
        load_options["main_opts"] = main_opts | suggested_main_opts

    return LoadOptions(load_options, available_simos()[selection.simos_name])


def default_selection(
    partial_ld: cle.Loader,
    suggested_backend: type[cle.Backend] | None = None,
    suggested_os_name: str | None = None,
    suggested_main_opts: dict | None = None,
    suggested_original_backend: type[cle.Backend] | None = None,
) -> LoadSelection | None:
    """
    The choices the Load Binary dialog preselects, or None when it preselects no architecture (the user must pick
    one before the dialog accepts).
    """
    ideal_arch, _, _ = split_arches(partial_ld, available_archs())
    if ideal_arch is None:
        return None
    backend = suggested_backend_name(suggested_backend)
    if backend is None:
        # the dialog's backend list shows its first entry when nothing matches
        inner = inner_backend_names()
        if not inner:
            return None
        backend = inner[0]
    rows = []
    if isinstance(partial_ld.main_object, cle.PE):
        nt_symbol_path = os.environ.get("_NT_SYMBOL_PATH", "")
        if nt_symbol_path:
            rows = symbol_path_rows(nt_symbol_path)
    return LoadSelection(
        backend=backend,
        simos_name=suggested_simos_name(suggested_os_name, available_simos()),
        arch=ideal_arch,
        outer_backend=suggested_outer_backend_name(suggested_original_backend),
        # every dependency starts unchecked
        skip_libs=set(requested_dependencies(partial_ld)),
        symbol_path_rows=rows,
        enckey=(suggested_main_opts or {}).get(CART_ENCKEY_ARGNAME),
    )


def _confirm_symbol_download(url: str) -> bool:
    # cle calls this on the loading thread, so the question goes to the UI thread
    answer = gui_thread_schedule(
        GlobalInfo.ui_services.question,
        ("Confirm Symbol Download", f"Download debug symbols from:\n{url}", ("Yes", "No"), "Yes"),
    )
    return answer == "Yes"


def default_load_options(
    partial_ld: cle.Loader,
    suggested_backend: type[cle.Backend] | None = None,
    suggested_os_name: str | None = None,
    suggested_main_opts: dict | None = None,
    suggested_original_backend: type[cle.Backend] | None = None,
    suggested_main_filename: str | None = None,
) -> LoadOptions | None:
    """
    The load options the Load Binary dialog produces when the user accepts what it preselects.

    None when the dialog would not accept without a choice from the user, which happens when no architecture matches
    the partial load.
    """
    selection = default_selection(
        partial_ld,
        suggested_backend=suggested_backend,
        suggested_os_name=suggested_os_name,
        suggested_main_opts=suggested_main_opts,
        suggested_original_backend=suggested_original_backend,
    )
    if selection is None:
        return None
    return build_load_options(
        partial_ld,
        selection,
        suggested_main_opts=suggested_main_opts,
        suggested_main_filename=suggested_main_filename,
        confirm_symbol_download=_confirm_symbol_download,
    )
