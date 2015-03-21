from angr import Surveyor

class InteractiveExplorer(Surveyor):
    done = False

    def run(self, n=None):
        pass # no concept of running to completion

    def path_by_id(self, path_id):
        for pl in self.path_lists:
            for path in getattr(self, pl):
                if path.path_id == path_id:
                    return path

        raise KeyError("no such path")

    @property
    def all_paths(self):
        return {pl: getattr(self, pl) for pl in self.path_lists}

    def step_path_by_id(self, path_id):
        for i, p in enumerate(self.active):
            if p.path_id == path_id:
                break
        else:
            raise KeyError("path_id not found in active paths")

        if p.errored:
            if isinstance(p.error, PathUnreachableError):
                self.pruned.append(p)
            else:
                self._heirarchy.unreachable(p)
                self.errored.append(p)
            del self.active[i]
            return []
        elif len(p.successors) == 0 and len(p.unconstrained_successor_states) == 0:
            l.debug("Path %s has deadended.", p)
            self.suspend_path(p)
            self.deadended.append(p)
            del self.active[i]
            return []
        else:
            succ = self.tick_path(p)
            self.active[i:i+1] = succ
            return succ

        # ???
        if len(p.unconstrained_successor_states) > 0:
            self.unconstrained.append(p)
