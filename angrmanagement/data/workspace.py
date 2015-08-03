from threading import Thread

from atom.api import Atom, List, Typed
from enaml.application import schedule
from enaml.layout.dock_layout import AreaLayout

from angr import CFG, Function, Project, Path, PathGroup


class PathGroups(Atom):
    proj = Typed(Project)
    groups = List(PathGroup, [])

    def add_path_group(self):
        self.groups = self.groups + [self.proj.factory.path_group(immutable=False, strong_path_mapping=True)]


class WorkspaceData(Atom):
    name = Typed(str)
    proj = Typed(Project)
    path_groups = Typed(PathGroups)
    cfg = Typed(CFG)
    selected_pg = Typed(PathGroup)
    selected_path = Typed(Path)
    selected_function = Typed(Function)
    items = List()
    layout = Typed(AreaLayout)

    def __init__(self, **kwargs):
        super(WorkspaceData, self).__init__(**kwargs)
        self.path_groups = PathGroups(proj=self.proj)

    def generate_cfg(self):
        t = Thread(target=self._generate_cfg)
        t.start()

    def _generate_cfg(self):
        cfg = self.proj.analyses.CFG()
        def set_cfg():
            self.cfg = cfg
        schedule(set_cfg)
