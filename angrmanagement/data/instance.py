import pickle

from atom.api import Atom, Int, List, Typed

import ana
from angr import CFG, PathGroup, Project

class PathGroups(Atom):
    proj = Typed(Project)
    groups = List(PathGroup, [])

    def add_path_group(self):
        self.groups = self.groups + [self.proj.factory.path_group(immutable=False, strong_path_mapping=True)]

class Instance(Atom):
    proj = Typed(Project)
    workspaces = List()
    path_groups = Typed(PathGroups)
    cfg = Typed(CFG)

    def __init__(self, **kwargs):
        super(Instance, self).__init__(**kwargs)

        if self.path_groups is None:
            self.path_groups = PathGroups(proj=self.proj)
            # ehhhhhh let's create one by default because i like to be lazy
            self.path_groups.add_path_group()

    def add_workspace(self, wk):
        self.workspaces = self.workspaces + [wk]

    def save(self, loc):
        with open(loc, 'wb') as f:
            pickled = pickle.dumps(self)
            store = ana.get_dl()._state_store
            pickle.dump({'store': store, 'pickled': pickled}, f)

    @staticmethod
    def from_file(loc):
        with open(loc, 'rb') as f:
            saved = pickle.load(f)
            ana.get_dl()._state_store = saved['store']
            return pickle.loads(saved['pickled'])

from .workspace import WorkspaceData
