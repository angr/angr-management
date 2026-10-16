"""The patches view without a toolkit: every patch, with editable comments, and reverting them."""

from __future__ import annotations

import binascii
from typing import TYPE_CHECKING, Any, ClassVar

from angrmanagement.logic import GlobalInfo

from .base import InstancePresenter, container, project_of
from .keymap import table_keymap
from .menus import Menu, MenuEntry
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angr.knowledge_plugins.patches import Patch

    from angrmanagement.data.instance import Instance

    from .keymap import Keymap


class PatchRow:
    """A patch and the bytes it replaced."""

    __slots__ = ("old_bytes", "patch")

    def __init__(self, patch: Patch, old_bytes: bytes | None) -> None:
        self.patch = patch
        self.old_bytes = old_bytes

    @property
    def cells(self) -> list[str]:
        patch = self.patch
        return [
            f"{patch.addr:x}",
            f"{len(patch)} bytes",
            binascii.hexlify(self.old_bytes).decode("ascii") if self.old_bytes else "<unknown>",
            binascii.hexlify(patch.new_bytes).decode("ascii"),
            patch.comment or "",
        ]


class PatchesTableModel(ListTableModel[PatchRow]):
    """The patches of the instance's project; the comment column is editable."""

    ADDRESS_COL = 0
    SIZE_COL = 1
    OLD_BYTES_COL = 2
    NEW_BYTES_COL = 3
    COMMENT_COL = 4

    COLUMNS: ClassVar[list[Column]] = [
        Column("Address", 10),
        Column("Size", 10),
        Column("Old Bytes", 20),
        Column("New Bytes", 20),
        Column("Comment", stretch=True, editable=True),
    ]
    HEADER: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, instance: Instance, presenter: PatchesPresenter | None = None) -> None:
        super().__init__()
        self.instance = instance
        self.presenter = presenter

    @staticmethod
    def _get_bytes(proj, addr: int, size: int) -> bytes | None:
        try:
            return proj.loader.memory.load(addr, size)
        except KeyError:
            return None

    def reload(self) -> None:
        project = project_of(self.instance)
        if project is None:
            self.set_rows([])
            return
        self.set_rows(
            PatchRow(patch, self._get_bytes(project, patch.addr, len(patch))) for patch in project.kb.patches.values()
        )

    def column_text(self, obj: PatchRow, col: int) -> str:
        cells = obj.cells
        return cells[col] if 0 <= col < len(cells) else ""

    def column_value(self, obj: PatchRow, col: int) -> Any:
        if col == self.ADDRESS_COL:
            return obj.patch.addr
        if col == self.SIZE_COL:
            return len(obj.patch)
        return self.column_text(obj, col)

    def set_text(self, row: int, col: int, text: str) -> bool:
        obj = self.row(row)
        if obj is None or col != self.COMMENT_COL:
            return False
        obj.patch.comment = text
        container(self.instance.patches).am_event()
        return True

    def patches(self, rows: Sequence[int]) -> set[Patch]:
        return {obj.patch for obj in self.objects(rows)}

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        if self.presenter is None:
            return None
        return self.presenter.patches_menu(self.patches(rows))


class PatchesPresenter(InstancePresenter):
    """The patches view: it follows patch changes and reverts patches."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "patches", instance, default_docking_position)
        self.base_caption = "Patches"
        self.model = PatchesTableModel(instance, self)
        container(self.instance.patches).am_subscribe(self._watch_patches)

    def close(self) -> None:
        container(self.instance.patches).am_unsubscribe(self._watch_patches)

    @property
    def keymap(self) -> Keymap:
        return table_keymap()

    def reload(self) -> None:
        self.model.reload()

    def revert(self, patches: set[Patch]) -> None:
        """Ask, then remove ``patches``."""
        if not patches:
            return
        answer = GlobalInfo.ui_services.question(
            "Revert patches", "Are you sure you want to revert selected patches?", ["Yes", "Cancel"], "Cancel"
        )
        if answer != "Yes":
            return
        patch_mgr = container(self.instance.patches)
        for patch in patches:
            patch_mgr.remove_patch(patch.addr)
        patch_mgr.am_event(removed=patches)

    def patches_menu(self, patches: set[Patch]) -> Menu:
        menu = Menu("")
        if patches:
            menu.add(MenuEntry("Revert selected patches", lambda: self.revert(patches)))
        return menu

    def _watch_patches(self, **kwargs) -> None:  # pylint: disable=unused-argument
        if not container(self.instance.patches).am_none:
            self.reload()
