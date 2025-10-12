from __future__ import annotations

import logging
import os
import abc
from typing import TYPE_CHECKING, Union
from pathlib import Path

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

class Signature(abc.ABC):
    def __init__(self, type_name: str, filename: str, name: str=None):
        self.type_name = type_name
        self.sig_path = filename
        if not name:
            name = Path(self.sig_path).stem
        self.sig_name = name
        self.arch = ''
        self.platform = ''
        self.compiler = ''
        self.os_name = ''

    @abc.abstractmethod
    def apply_signature(self, mgr: SignatureManager, dry_run: bool = True, ignore_addresses: set[int] = set()) -> None:
        pass

class PrecomputedSignature(Signature):
    def __init__(self, type_name: str, filename: str, matches: dict[int, str], name: str=None):
        super().__init__(type_name, filename=filename, name=name)
        self.matches = matches

    def apply_signature(self, mgr: SignatureManager, dry_run: bool = True, ignore_addresses: set[int] = set()) -> None:
        if dry_run:
            mgr.dryrun_results[self.sig_path] = self.matches
            return

        for func_addr, name in self.matches.items():
            if ignore_addresses and func_addr in ignore_addresses:
                continue
            func = mgr.instance.project.kb.functions.get_by_addr(func_addr)
            if not func:
                continue
            func.name = name 
            func.is_default_name = False
            func.from_signature = "bindiff"

class WrappedFlirtSignature(Signature):
    def __init__(self, flirt: FlirtSignature):
        super().__init__('FLIRT', flirt.sig_path, name=flirt.sig_name)
        self.arch = flirt.arch
        self.platform = flirt.platform
        self.compiler = flirt.compiler
        self.os_name = flirt.os_name
        self.flirt = flirt

    def apply_signature(self, mgr: SignatureManager, dry_run: bool = True, ignore_addresses: set[int] = set()) -> None:
        fl = mgr.instance.project.analyses.Flirt(self.sig_path, dry_run=dry_run or len(ignore_addresses) > 0)
        if not dry_run and not len(ignore_addresses) > 0:
            return

        sig_name, dryrun_results = next(iter(fl.matched_suggestions.values()))
        if dry_run:
            mgr.dryrun_results[self.sig_path] = dryrun_results
            return

        # Manually apply the changes with a reduced set of addresses
        matched_with_ignore = {
            addr: v for addr, v in dryrun_results.items()
            if addr not in ignore_addresses
        }
        _l.info("Applying %s/%s signatures", len(matched_with_ignore), len(dryrun_results))
        fl._apply_changes(
            sig_name if not fl._temporary_sig else None,
            matched_with_ignore,
        )


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
                self.add_signature(WrappedFlirtSignature(sig))

    def clear(self) -> None:
        self.signatures.clear()
        self.signatures.am_event()

    def add_signature(self, sig: Signature) -> None:
        self.signatures.append(sig)
        self.signatures.am_event(added=sig)

    def add_precomputed_signature(self, type_name: str, filename: str, matches: dict[int, str]) -> None:
        sig = PrecomputedSignature(type_name, filename, matches)
        self.dryrun_results[filename] = matches
        self.add_signature(sig)
        return sig

    def remove_signature(self, sig: Signature) -> None:
        self.signatures.remove(sig)
        self.signatures.am_event(removed=sig)

    def apply_signatures(self, sigs: list[Signature], dry_run: bool = True, ignore_addresses: set[int] = set()):
        for sig in sigs:
            sig.apply_signature(self, dry_run, ignore_addresses)

    def select_bindiff_base_files(self) -> list[str] | None:
        """
        Open a dialog to select binaries for bindiff analysis.
        Returns the list of selected filenames, or None if cancelled.
        """
        filenames, _ = QFileDialog.getOpenFileNames(
            None,
            "Load binaries to bindiff from",
            "",
            "Object Files (*.a *.o);;All files (*)",
        )
        return filenames if filenames else None

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
                self.add_signature(WrappedFlirtSignature(sig))
            else:
                _l.error("Failed to load signature file %s.", filename)

    def get_match_count(self, sig: Signature) -> int | None:
        if sig.sig_path in self.dryrun_results:
            return len(self.dryrun_results[sig.sig_path])
        return None

    def get_matches(self, sig: Signature) -> dict[int, str] | None:
        """Get the matched functions for a signature as a dict of {address: name}."""
        if sig.sig_path in self.dryrun_results:
            return self.dryrun_results[sig.sig_path]
        return None
