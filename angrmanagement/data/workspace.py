from atom.api import Atom, Int, Long, List, Typed, ForwardTyped, Value, Unicode, observe
from enaml.layout.dock_layout import AreaLayout

from angr import CFG, Project, Path, PathGroup
from angr.knowledge import Function


class WorkspaceData(Atom):
    item_idx = Int()
    name = Typed(str)
    sort = Typed(str)
    # who doesn't love back-references?
    inst = ForwardTyped(lambda: Instance)
    proj = Typed(Project)

    items = List()
    layout = Typed(AreaLayout)

    def __init__(self, **kwargs):
        super(WorkspaceData, self).__init__(**kwargs)

        if self.proj is None and self.inst is not None:
            self.proj = self.inst.proj

    def next_item_name(self):
        i = self.item_idx
        self.item_idx += 1
        return 'item_%d' % i


class SymexecView(WorkspaceData):
    selected_pg = Typed(PathGroup)
    selected_path = Typed(Path)

    def __init__(self, **kwargs):
        super(SymexecView, self).__init__(**kwargs)

        if self.inst is not None and len(self.inst.path_groups.groups) > 0:
            self.selected_pg = self.inst.path_groups.groups[0]

        if self.selected_pg is not None and len(self.selected_pg.active) > 0:
            self.selected_path = None
            self.selected_path = self.selected_pg.active[0]

class DisasmGraphView(WorkspaceData):
    selected_function = Typed(Function)
    selected_addr = Long()
    selected_label = Value()
    highlighted_insns = Typed(set)

    def __init__(self, **kwargs):
        super(DisasmGraphView, self).__init__(**kwargs)

        self.highlighted_insns = set()

from .instance import Instance
