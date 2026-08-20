from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from angr.knowledge_plugins import Function
from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTreeView,
    QVBoxLayout,
)

from angrmanagement.ui.widgets.qfunction_combobox import QFunctionComboBox

from .view import InstanceView

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace

_l = logging.getLogger(__name__)

# roles used to hang the raw values off the items, so sorting and navigation do not have to parse the display text
ADDRESS_ROLE = Qt.ItemDataRole.UserRole + 1
SORT_ROLE = Qt.ItemDataRole.UserRole + 2
SITE_ROLE = Qt.ItemDataRole.UserRole + 3
TARGET_ROLE = Qt.ItemDataRole.UserRole + 4


@dataclass
class IndirectJumpSite:
    """
    One indirect jump or call site, as the view shows it: what the knowledge base knows about the site, merged with
    whatever the whole-binary resolution analysis found for it.

    :ivar block_addr:       Address of the block the site ends, which is how ``kb.indirect_jumps`` keys it.
    :ivar ins_addr:         Address of the indirect jump or call instruction itself.
    :ivar func_addr:        Address of the function the site sits in.
    :ivar kind:             ``"call"`` or ``"jump"``.
    :ivar jumptable:        Whether control-flow recovery resolved this site as a jump table.
    :ivar cfg_targets:      Targets attributed to control-flow recovery.
    :ivar analysis_targets: Targets the whole-binary resolution analysis recovered.
    :ivar analysis_sites:   Instruction addresses the analysis used for this site, for looking up provenance.
    """

    block_addr: int | None = None
    ins_addr: int | None = None
    func_addr: int | None = None
    kind: str = "jump"
    jumptable: bool = False
    cfg_targets: set[int] = field(default_factory=set)
    analysis_targets: set[int] = field(default_factory=set)
    analysis_sites: list[int] = field(default_factory=list)

    @property
    def targets(self) -> set[int]:
        return self.cfg_targets | self.analysis_targets

    @property
    def resolved(self) -> bool:
        return bool(self.targets)

    @property
    def address(self) -> int:
        """
        The address this site is displayed and navigated by.
        """
        if self.ins_addr is not None:
            return self.ins_addr
        assert self.block_addr is not None
        return self.block_addr

    def source_of(self, target: int) -> str:
        """
        Where the given target came from.
        """
        if target in self.cfg_targets:
            return "CFG"
        return "Indirect jump analysis"

    @property
    def source(self) -> str:
        """
        Where this site's targets came from, taken together.
        """
        sources = []
        if self.cfg_targets:
            sources.append("CFG")
        if self.analysis_targets - self.cfg_targets:
            sources.append("Indirect jump analysis")
        return ", ".join(sources)


class QIndirectJumpTreeItem(QStandardItem):
    """
    A tree item that sorts on the value behind it rather than on its display text, so that addresses and counts sort
    as numbers.
    """

    def __lt__(self, other: QStandardItem) -> bool:
        mine = self.data(SORT_ROLE)
        theirs = other.data(SORT_ROLE)
        if mine is None or theirs is None:
            return super().__lt__(other)
        return mine < theirs


class IndirectJumpsView(InstanceView):
    """
    Lists the indirect jumps and calls in the binary, resolved and unresolved, as recorded in ``kb.indirect_jumps``
    and as recovered by the whole-binary indirect jump resolution analysis.
    """

    HEADERS = ["Address", "Function", "Kind", "Status", "Targets", "Resolved by"]
    COL_ADDRESS = 0
    COL_FUNCTION = 1
    COL_KIND = 2
    COL_STATUS = 3
    COL_TARGETS = 4
    COL_SOURCE = 5

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("indirect_jumps", workspace, default_docking_position, instance)
        self.base_caption = "Indirect Jumps"

        self._sites: list[IndirectJumpSite] = []
        self._selected_function: Function | None = None
        self._kind_cache: dict[int, str] = {}

        self._init_widgets()

        self.instance.cfg.am_subscribe(self._on_data_updated)
        self.instance.indirect_jump_resolution.am_subscribe(self._on_data_updated)

        self.reload()

    def sizeHint(self):  # pylint:disable=no-self-use
        return QSize(700, 400)

    def closeEvent(self, event) -> None:
        self.instance.cfg.am_unsubscribe(self._on_data_updated)
        self.instance.indirect_jump_resolution.am_unsubscribe(self._on_data_updated)
        super().closeEvent(event)

    #
    # Public methods
    #

    def reload(self) -> None:
        self._kind_cache.clear()
        if not self.instance.project.am_none:
            self._function_list.functions = self.instance.kb.functions
        self._sites = self._collect_sites()
        self._update_status()
        self._rebuild_model()

    def select_function(self, func: Function | None) -> None:
        """
        Show only the sites inside the given function, or all of them when given None.
        """
        self._function_list.select_function(func if func is not None else "all")

    def run_analysis(self) -> None:
        """
        Kick off a whole-binary indirect jump resolution run.
        """
        self.workspace.analysis_manager.resolve_indirect_jumps()

    #
    # Data collection
    #

    def _collect_sites(self) -> list[IndirectJumpSite]:
        """
        Merge what the knowledge base records about each indirect site with what the resolution analysis found.
        """
        if self.instance.project.am_none or self.instance.kb is None:
            return []

        indirect_jumps = self.instance.kb.indirect_jumps
        cfg_model = None if self.instance.cfg.am_none else self.instance.cfg.am_obj
        result = self.instance.indirect_jump_resolution.am_obj

        sites: dict[tuple[str, int], IndirectJumpSite] = {}

        def site_for_block(block_addr: int) -> IndirectJumpSite:
            key = ("block", block_addr)
            site = sites.get(key)
            if site is None:
                site = IndirectJumpSite(block_addr=block_addr)
                sites[key] = site
            return site

        # the records control-flow recovery published: these carry the instruction address, the owning function, and
        # whether the site is a call or a jump
        for block_addr, record in indirect_jumps.items():
            site = site_for_block(block_addr)
            site.ins_addr = record.ins_addr
            site.func_addr = record.func_addr
            site.kind = "call" if record.jumpkind == "Ijk_Call" else "jump"
            site.jumptable = bool(record.jumptable)
            site.cfg_targets |= set(record.resolved_targets)

        # sites resolved by a timeless resolver never get a record of their own, and only show up here
        for block_addr, targets in indirect_jumps.resolved.items():
            site_for_block(block_addr).cfg_targets |= set(targets)
        for block_addr in indirect_jumps.unresolved:
            site_for_block(block_addr)

        # a site with no record of its own - one a timeless resolver handled - has to be filled in from the CFG,
        # which is also the only way to tell whether it is a call or a jump
        for site in sites.values():
            if site.func_addr is None:
                self._fill_in_from_cfg(site, cfg_model)

        # overlay the whole-binary analysis. Its targets are attributed to it only where the CFG did not already have
        # them: publishing merges the two in the knowledge base, so this is the honest split.
        if result is not None:
            for ins_addr, (func_addr, kind) in result.sites.items():
                block_addr = result.block_addrs.get(ins_addr)
                site = site_for_block(block_addr) if block_addr is not None else None
                if site is None:
                    key = ("ins", ins_addr)
                    site = sites.setdefault(key, IndirectJumpSite(ins_addr=ins_addr))
                if site.ins_addr is None:
                    site.ins_addr = ins_addr
                if site.func_addr is None:
                    site.func_addr = func_addr
                site.kind = kind
                site.analysis_sites.append(ins_addr)
                site.analysis_targets |= result.resolutions.get(ins_addr, set())

        return sorted(sites.values(), key=lambda s: s.address)

    def _fill_in_from_cfg(self, site: IndirectJumpSite, cfg_model: CFGModel | None) -> None:
        """
        Fill in what the CFG can tell us about a site we only know the block address of.
        """
        if cfg_model is None or site.block_addr is None:
            return
        node = cfg_model.get_any_node(site.block_addr)
        if node is None:
            return
        site.func_addr = node.function_address
        site.ins_addr = node.instruction_addrs[-1] if node.instruction_addrs else site.block_addr
        site.kind = self._kind_of_block(site.block_addr, node.size)

    def _kind_of_block(self, block_addr: int, size: int | None) -> str:
        """
        Whether the block ends in an indirect call or an indirect jump, by lifting it.
        """
        kind = self._kind_cache.get(block_addr)
        if kind is None:
            kind = "jump"
            try:
                block = self.instance.project.factory.block(block_addr, size=size)
                kind = "call" if block.vex_nostmt.jumpkind == "Ijk_Call" else "jump"
            except Exception:  # pylint:disable=broad-except
                _l.debug("Cannot determine the kind of the indirect site at %#x.", block_addr, exc_info=True)
            self._kind_cache[block_addr] = kind
        return kind

    #
    # Model
    #

    def _visible_sites(self) -> list[IndirectJumpSite]:
        sites = self._sites
        if self._selected_function is not None:
            func_addr = self._selected_function.addr
            sites = [s for s in sites if s.func_addr == func_addr]

        status = self._status_filter.currentData()
        if status == "resolved":
            sites = [s for s in sites if s.resolved]
        elif status == "unresolved":
            sites = [s for s in sites if not s.resolved]

        text = self._filter_string.text().strip().lower()
        if text:
            sites = [s for s in sites if self._matches(s, text)]
        return sites

    def _matches(self, site: IndirectJumpSite, text: str) -> bool:
        haystack = [f"{site.address:#x}", self._function_name(site.func_addr), site.kind]
        haystack += [f"{target:#x}" for target in site.targets]
        haystack += [self._function_name(target) for target in site.targets]
        return any(text in part.lower() for part in haystack if part)

    def _rebuild_model(self) -> None:
        model = QStandardItemModel()
        model.setHorizontalHeaderLabels(self.HEADERS)

        for site in self._visible_sites():
            model.appendRow(self._site_row(site))

        self._tree.setModel(model)
        self._tree.setSortingEnabled(True)
        self._tree.sortByColumn(self.COL_ADDRESS, Qt.SortOrder.AscendingOrder)
        for col in range(len(self.HEADERS) - 1):
            self._tree.resizeColumnToContents(col)

    def _site_row(self, site: IndirectJumpSite) -> list[QStandardItem]:
        address = self._item(f"{site.address:#x}", sort_value=site.address, addr=site.address)
        if site.block_addr is not None and site.block_addr != site.address:
            address.setToolTip(f"In the block at {site.block_addr:#x}")

        kind = "Call" if site.kind == "call" else ("Jump table" if site.jumptable else "Jump")
        row = [
            address,
            self._item(self._function_name(site.func_addr), addr=site.func_addr),
            self._item(kind),
            self._item("Resolved" if site.resolved else "Unresolved"),
            self._item(str(len(site.targets)) if site.resolved else "", sort_value=len(site.targets)),
            self._item(site.source),
        ]
        for item in row:
            item.setData(site, SITE_ROLE)

        for target in sorted(site.targets):
            child = [
                self._item(f"{target:#x}", sort_value=target, addr=target),
                self._item(self._function_name(target), addr=target),
                self._item(""),
                self._item(""),
                self._item(""),
                self._item(site.source_of(target)),
            ]
            for item in child:
                item.setData(site, SITE_ROLE)
                item.setData(target, TARGET_ROLE)
            address.appendRow(child)

        return row

    @staticmethod
    def _item(text: str, sort_value: Any = None, addr: int | None = None) -> QStandardItem:
        item = QIndirectJumpTreeItem(text)
        item.setEditable(False)
        item.setData(sort_value if sort_value is not None else text, SORT_ROLE)
        if addr is not None:
            item.setData(addr, ADDRESS_ROLE)
        return item

    def _function_name(self, addr: int | None) -> str:
        if addr is None or self.instance.kb is None:
            return ""
        func = self.instance.kb.functions.get_by_addr(addr) if addr in self.instance.kb.functions else None
        return func.name if func is not None else f"{addr:#x}"

    def _update_status(self) -> None:
        resolved = sum(1 for site in self._sites if site.resolved)
        text = f"{resolved} of {len(self._sites)} indirect jump and call sites resolved."

        result = self.instance.indirect_jump_resolution.am_obj
        if result is None:
            text += " Run the indirect jump analysis to resolve more."
        else:
            # the analysis counts sites its own way - it does not consider jump tables its business, and it sees
            # sites in functions the CFG never flagged - so its numbers are reported as its own, not as the view's
            text += f" Last analysis run: {result.summary}."
            if result.aborted:
                text += " It was stopped early, so its results are partial."
        self._status_label.setText(text)

    #
    # Widgets
    #

    def _init_widgets(self) -> None:
        self._function_list = QFunctionComboBox(
            show_all_functions=True, selection_callback=self._on_function_selected, parent=self
        )
        self._function_list.setToolTip("Show only the indirect jumps and calls inside this function")

        self._status_filter = QComboBox(self)
        self._status_filter.addItem("All", "all")
        self._status_filter.addItem("Resolved", "resolved")
        self._status_filter.addItem("Unresolved", "unresolved")
        self._status_filter.currentIndexChanged.connect(self._on_filter_changed)

        self._filter_string = QLineEdit(self)
        self._filter_string.setPlaceholderText("Filter by address or function name")
        self._filter_string.textChanged.connect(self._on_filter_changed)

        self._run_button = QPushButton("Resolve Indirect Jumps", self)
        self._run_button.setToolTip(
            "Run the whole-binary indirect jump resolution analysis. This decompiles every function, so it takes a "
            "while on a large binary; it reports progress and can be cancelled."
        )
        self._run_button.clicked.connect(self.run_analysis)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Function:", self))
        filter_layout.addWidget(self._function_list, 10)
        filter_layout.addWidget(QLabel("Status:", self))
        filter_layout.addWidget(self._status_filter)
        filter_layout.addWidget(QLabel("Filter:", self))
        filter_layout.addWidget(self._filter_string, 10)
        filter_layout.addWidget(self._run_button)
        filter_layout.setContentsMargins(3, 3, 3, 3)
        filter_layout.setSpacing(3)

        self._tree = QTreeView(self)
        self._tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._tree.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_context_menu)
        self._tree.doubleClicked.connect(self._on_double_click)
        self._tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._tree.header().setStretchLastSection(True)

        self._status_label = QLabel(self)
        self._status_label.setWordWrap(True)

        layout = QVBoxLayout()
        layout.addLayout(filter_layout)
        layout.addWidget(self._tree)
        layout.addWidget(self._status_label)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    #
    # Event handlers
    #

    def _on_data_updated(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.reload()

    def _on_function_selected(self, func) -> None:
        self._selected_function = func if isinstance(func, Function) else None
        self._rebuild_model()

    def _on_filter_changed(self, *args) -> None:  # pylint:disable=unused-argument
        self._rebuild_model()

    def _on_double_click(self, index) -> None:
        addr = index.siblingAtColumn(self.COL_ADDRESS).data(ADDRESS_ROLE)
        if addr is None:
            addr = index.data(ADDRESS_ROLE)
        if addr is not None:
            self.workspace.jump_to(addr)

    def _on_context_menu(self, pos) -> None:
        index = self._tree.indexAt(pos)
        menu = QMenu("", self)

        if index.isValid():
            site = index.data(SITE_ROLE)
            target = index.data(TARGET_ROLE)
            if target is not None:
                menu.addAction(f"Jump to target {target:#x}", lambda: self.workspace.jump_to(target))
            if site is not None:
                menu.addAction(f"Jump to site {site.address:#x}", lambda: self.workspace.jump_to(site.address))
                if site.func_addr is not None:
                    menu.addAction(
                        f"Jump to function {self._function_name(site.func_addr)}",
                        lambda: self.workspace.jump_to(site.func_addr),
                    )
            menu.addSeparator()

        menu.addAction("Resolve indirect jumps across the binary", self.run_analysis)
        menu.exec_(self._tree.viewport().mapToGlobal(pos))
