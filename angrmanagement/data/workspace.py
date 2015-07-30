from atom.api import Atom, Int, List, Typed

from angr import Project, PathGroup


class PathGroups(Atom):
    proj = Typed(Project)
    groups = List(PathGroup, [])

    def add_path_group(self):
        self.groups = self.groups + [self.proj.factory.path_group(immutable=False, strong_path_mapping=True)]


class WorkspaceData(Atom):
    n = Int()
    proj = Typed(Project)
    path_groups = Typed(PathGroups)

    def __init__(self, **kwargs):
        super(WorkspaceData, self).__init__(**kwargs)
        self.path_groups = PathGroups(proj=self.proj)
