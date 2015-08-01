from threading import Thread

from atom.api import Atom, Int, List, Typed
from enaml.application import schedule

from angr import Project, PathGroup, CFG


class PathGroups(Atom):
    proj = Typed(Project)
    groups = List(PathGroup, [])

    def add_path_group(self):
        self.groups = self.groups + [self.proj.factory.path_group(immutable=False, strong_path_mapping=True)]


class WorkspaceData(Atom):
    n = Int()
    proj = Typed(Project)
    path_groups = Typed(PathGroups)
    cfg = Typed(CFG)

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
