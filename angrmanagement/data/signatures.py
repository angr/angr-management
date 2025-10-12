from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import angr
import angr.flirt
from angr.flirt import FLIRT_SIGNATURES_BY_ARCH, FlirtSignature
from PySide6.QtWidgets import QFileDialog

from angrmanagement.config import Conf
from angrmanagement.utils.env import app_root, is_pyinstaller

from .object_container import ObjectContainer

if TYPE_CHECKING:
    from .instance import Instance

_l = logging.getLogger(__name__)

#
# FLIRT Signatures
#


def init_flirt_signatures() -> None:
    if Conf.flirt_signatures_root:
        # if it's a relative path, it's relative to the angr-management package
        if os.path.isabs(Conf.flirt_signatures_root):
            flirt_signatures_root = Conf.flirt_signatures_root
        else:
            if is_pyinstaller():
                flirt_signatures_root = os.path.join(app_root(), Conf.flirt_signatures_root)
            else:
                # when running as a Python package, we should use the git submodule, which is on the same level
                # with (instead of inside) the angrmanagement module directory.
                flirt_signatures_root = os.path.join(app_root(), "..", Conf.flirt_signatures_root)
        flirt_signatures_root = os.path.normpath(flirt_signatures_root)
        _l.info("Loading FLIRT signatures from %s.", flirt_signatures_root)
        angr.flirt.load_signatures(flirt_signatures_root)


class SignatureManager:
    """
    Manager of function signatures.
    """

    def __init__(self, instance: Instance) -> None:
        self.signatures: ObjectContainer = ObjectContainer([], "List of function signatures")
        self.dryrun_results: dict[str, dict[int, str]] = {}
        self.instance = instance

    def sync_from_angr(self):
        for _arch, sigs in FLIRT_SIGNATURES_BY_ARCH.items():
            for sig in sigs:
                self.add_signature(sig)

    def clear(self) -> None:
        self.signatures.clear()
        self.signatures.am_event()

    def add_signature(self, sig: FlirtSignature) -> None:
        self.signatures.append(sig)
        self.signatures.am_event(added=sig)

    def remove_signature(self, sig: FlirtSignature) -> None:
        self.signatures.remove(sig)
        self.signatures.am_event(removed=sig)

    def apply_signatures(self, sigs: list[FlirtSignature], dry_run: bool = True):
        for sig in sigs:
            fl = self.instance.project.analyses.Flirt(sig.sig_path, dry_run=dry_run)
            if dry_run:
                self.dryrun_results[sig.sig_path] = next(iter(fl.matched_suggestions.values()))[1]

    def load_signatures(self) -> None:
        # open a dialog to select signatures files
        filenames, _ = QFileDialog.getOpenFileNames(
            None,
            "Load FLIRT signature files",
            "",
            "FLIRT signature files (*.sig);;All files (*)",
        )
        for filename in filenames:
            basename = os.path.basename(filename)
            meta_path = filename[: filename.rindex(".")] + ".meta" if "." in basename else None
            r = angr.flirt.load_signature(filename, meta_path=meta_path)
            if r is not None:
                arch, sig = r
                self.add_signature(sig)
            else:
                _l.error("Failed to load signature file %s.", filename)

    def get_match_count(self, sig: FlirtSignature) -> int | None:
        if sig.sig_path in self.dryrun_results:
            return len(self.dryrun_results[sig.sig_path])
        return None

    def get_matches(self, sig: FlirtSignature) -> dict[int, str] | None:
        """Get the matched functions for a signature as a dict of {address: name}."""
        if sig.sig_path in self.dryrun_results:
            return self.dryrun_results[sig.sig_path]
        return None
