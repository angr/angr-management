import angr
import simuvex

class Serializer(object):
    def __init__(self):
        pass

    def serialize(self, o):
        if isinstance(o, angr.Surveyor):
            return self._serialize_surveyor(o)
        if isinstance(o, angr.Path):
            return self._serialize_path(o)
        if isinstance(o, simuvex.SimState):
            return self._serialize_state(o)
        else:
            return "NOT SERIALIZED: %s" % o

    def _serialize_state(self, s):
        raise NotImplementedError("TODO")

    def _serialize_path(self, p):
        return {
            'id': id(p),
            'length': p.length,
            'extra_length': p.extra_length,
            'backtrace': p.backtrace,
            'addr_backtrace': p.addr_backtrace,
            'callstack': p.callstack,
            'blockcounter_stack': p.blockcounter_stack,
            'refs': [ self.serialize(r) for r in p.refs() ],
        }

    def _serialize_surveyor(self, s):
        return {
            'id': id(s),
            'type': s.__class__.__name__,
            'path_lists': { n:[ self.serialize(p) for p in getattr(s, n) ] for n in s.path_lists },
            'step': s._current_step,
            'max_concurrency': s._max_concurrency,
            'save_deadends': s._save_deadends,
        }
