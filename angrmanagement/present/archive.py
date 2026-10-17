"""
Picking a file out of an archive to load, without a toolkit: the tree of the archive's entries and one attempt at
extracting the chosen one. The Qt archive dialog and the terminal's archive screen show the tree and ask for a
password the same way; they differ only in how they draw it and wait for the answer.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field

from angrmanagement.utils.archive import (
    Archive,
    ArchiveError,
    ArchiveInvalidPassword,
    ArchiveMember,
    ArchivePasswordRequired,
)


def format_size(size: int) -> str:
    """A size as the archive dialog shows it: bytes, then KB, MB, GB and TB with one decimal."""
    s: float = size
    for unit in ("B", "KB", "MB", "GB"):
        if s < 1024:
            return f"{s:.0f} {unit}" if unit == "B" else f"{s:.1f} {unit}"
        s /= 1024
    return f"{s:.1f} TB"


@dataclass
class ArchiveNode:
    """A directory or a file of the archive's tree; ``member`` is set for files."""

    name: str
    member: ArchiveMember | None = None
    children: list[ArchiveNode] = field(default_factory=list)

    @property
    def size_text(self) -> str:
        return format_size(self.member.size) if self.member is not None else ""


def archive_tree(members: list[ArchiveMember]) -> list[ArchiveNode]:
    """The top-level nodes of the tree the members' paths make, sorted by name as the dialog sorts them."""
    roots: list[ArchiveNode] = []
    nodes: dict[str, ArchiveNode] = {}
    for member in sorted(members, key=lambda m: m.name):
        parts = member.name.split("/")
        for i, part in enumerate(parts):
            key = "/".join(parts[: i + 1])
            if key in nodes:
                continue
            node = ArchiveNode(part, member if i == len(parts) - 1 else None)
            if i == 0:
                roots.append(node)
            else:
                nodes["/".join(parts[:i])].children.append(node)
            nodes[key] = node
    return roots


@dataclass
class Extraction:
    """
    What one attempt at extracting a member gave.

    :ivar outcome:  ``"ok"`` (``path`` is the file), ``"password"`` (the member needs a password), ``"wrong"`` (the
                    password was refused; ``message`` says so) or ``"error"`` (``message`` says why).
    """

    outcome: str
    path: str | None = None
    temp_dir: str | None = None
    message: str = ""


def extract_member(archive: Archive, member: ArchiveMember, password: str | None) -> Extraction:
    """Extract ``member`` into a new temporary directory; a failed attempt leaves no directory behind."""
    temp_dir = tempfile.mkdtemp(prefix="angr_management_archive_")
    try:
        path = archive.extract(member.name, temp_dir, password=password)
        if not os.path.isfile(path):
            raise ArchiveError("Extracted path is not a file")
    except ArchivePasswordRequired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return Extraction("password")
    except ArchiveInvalidPassword as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return Extraction("wrong", message=str(e))
    except ArchiveError as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return Extraction("error", message=f"Failed to extract file: {e}")
    return Extraction("ok", path, temp_dir)


__all__ = ["ArchiveNode", "Extraction", "archive_tree", "extract_member", "format_size"]
