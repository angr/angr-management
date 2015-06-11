from atom.api import Atom, List, Typed

from angr import Project, PathGroup


class PathGroups(Atom):
    proj = Typed(Project)
    groups = List(PathGroup, [])

    def add_path_group(self):
        self.groups = self.groups + [self.proj.path_group(immutable=False)]


class WorkspaceData(object):
    def __init__(self, proj):
        self.proj = proj
        self.path_groups = PathGroups(proj=proj)
