"""The function signatures view without a toolkit: the loaded signatures, and trying and applying them."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from angrmanagement.data.jobs.bindiff_matching import BindiffMatchingJob
from angrmanagement.logic import GlobalInfo

from .base import InstancePresenter
from .keymap import table_keymap
from .menus import Menu, MenuEntry, MenuSeparator
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from angrmanagement.data.instance import Instance
    from angrmanagement.data.signatures import Signature, SignatureManager

    from .keymap import Keymap


class SignaturesTableModel(ListTableModel["Signature"]):
    """The signatures of a signature manager and how many functions each matched."""

    COL_TYPE = 0
    COL_NAME = 1
    COL_ARCH = 2
    COL_PLATFORM = 3
    COL_COMPILER = 4
    COL_OS_NAME = 5
    COL_MATCHES = 6

    COLUMNS: ClassVar[list[Column]] = [
        Column("Type", 8),
        Column("Name", 30),
        Column("Architecture", 14),
        Column("Platform", 10),
        Column("Compiler", 10),
        Column("OS Name", 10),
        Column("Matches", stretch=True),
    ]
    Headers: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, signature_mgr: SignatureManager, presenter: SignaturesPresenter | None = None) -> None:
        super().__init__()
        self.signature_mgr = signature_mgr
        self.presenter = presenter
        self.signature_mgr.signatures.am_subscribe(self._on_signatures_updated)
        self.reload()

    def shutdown(self) -> None:
        self.signature_mgr.signatures.am_unsubscribe(self._on_signatures_updated)

    def reload(self) -> None:
        self.set_rows(list(self.signature_mgr.signatures))

    def _on_signatures_updated(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.reload()

    def column_text(self, obj: Signature, col: int) -> str:
        if col == self.COL_TYPE:
            return obj.type_name
        if col == self.COL_NAME:
            return obj.sig_name
        if col == self.COL_ARCH:
            return obj.arch
        if col == self.COL_PLATFORM:
            return obj.platform
        if col == self.COL_COMPILER:
            return obj.compiler
        if col == self.COL_OS_NAME:
            return obj.os_name
        if col == self.COL_MATCHES:
            m = self.signature_mgr.get_match_count(obj)
            return str(m) if m is not None else "N/A"
        return ""

    def on_activate(self, obj: Signature) -> None:
        if self.presenter is not None:
            self.presenter.open_signature(obj)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        if self.presenter is None:
            return None
        return self.presenter.signatures_menu(self.objects(rows))


class SignaturesPresenter(InstancePresenter):
    """The function signatures view."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "signatures", instance, default_docking_position)
        self.base_caption = "Function Signatures"
        self.signature_mgr = instance.signature_mgr
        self.model = SignaturesTableModel(self.signature_mgr, self)

    def close(self) -> None:
        self.model.shutdown()

    @property
    def keymap(self) -> Keymap:
        return table_keymap()

    def reload(self) -> None:
        self.signature_mgr.sync_from_angr()

    def try_signatures(self, sigs: Sequence[Signature]) -> None:
        self.signature_mgr.apply_signatures(list(sigs), dry_run=True)

    def apply_signatures(self, sigs: Sequence[Signature]) -> None:
        self.signature_mgr.apply_signatures(list(sigs), dry_run=False)
        self.workspace.on_flirt_signatures_applied()

    def try_all_signatures(self) -> None:
        all_sigs = list(self.signature_mgr.signatures)
        if all_sigs:
            self.signature_mgr.apply_signatures(all_sigs, dry_run=True)

    def load_signatures(self) -> None:
        self.signature_mgr.load_signatures()

    def show_matches(self, sig: Signature, matches: dict[int, str]) -> None:  # pylint:disable=no-self-use
        """List the functions ``sig`` matched; a frontend with a matches dialog overrides this."""
        lines = [f"{addr:#x}  {name}" for addr, name in sorted(matches.items())]
        GlobalInfo.ui_services.message("info", f"Matches of {sig.sig_name}", "\n".join(lines) or "No matches.")

    def open_signature(self, sig: Signature, show_matches: Callable | None = None) -> None:
        """Double-click: try applying the signature if it has no matches yet, otherwise show its matches."""
        matches = self.signature_mgr.get_matches(sig)
        if matches:
            (show_matches or self.show_matches)(sig, matches)
        else:
            self.signature_mgr.apply_signatures([sig], dry_run=True)

    def find_matches_via_bindiff(self) -> None:
        """Ask for binaries, then match their functions against this one with BinDiff in a job."""

        filenames = self.signature_mgr.select_bindiff_base_files()
        if filenames:
            job = BindiffMatchingJob(self.instance, filenames, on_results=self._on_bindiff_matches_finished)
            self.workspace.job_manager.add_job(job)

    def _on_bindiff_matches_finished(self, matches_per_file: dict[str, dict[int, str]]) -> None:
        for filename, matches in matches_per_file.items():
            self.signature_mgr.add_precomputed_signature("Bindif", filename, matches)

    def signatures_menu(self, sigs: Sequence[Signature], show_matches: Callable | None = None) -> Menu:
        """Try, apply or show the matches of the selected signatures, or load more."""
        sigs = list(sigs)
        menu = Menu("")
        if sigs:
            menu.add(MenuEntry("&Try applying signature(s)", lambda: self.try_signatures(sigs)))
            menu.add(MenuEntry("&Apply signature(s)", lambda: self.apply_signatures(sigs)))
            # "View Matches" when exactly one signature with matches is selected
            if len(sigs) == 1:
                sig = sigs[0]
                matches = self.signature_mgr.get_matches(sig)
                if matches:
                    shower = show_matches or self.show_matches
                    menu.add(MenuEntry("&View Matches...", lambda: shower(sig, matches)))
            menu.add(MenuSeparator())
        menu.add(MenuEntry("&Load signature files...", self.load_signatures))
        return menu
