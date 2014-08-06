import angr
import simuvex

import types

class Serializer(object):
    def __init__(self):
        pass

    def serialize(self, o, ref=False):
        if type(o) in (long, int, str, unicode, float, bool):
            return o
        if isinstance(o, angr.Surveyor):
            return self._serialize_surveyor(o)
        if isinstance(o, angr.Path):
            return self._serialize_path(o)
        if isinstance(o, simuvex.SimState):
            return self._serialize_state(o)
        if isinstance(o, simuvex.SimRun):
            return self._serialize_simrun(o, ref)
        if isinstance(o, angr.PathEvent):
            return self._serialize_path_event(o)
        else:
            return "NOT SERIALIZED: %s" % o

    def _serialize_state(self, s):
        return str(s)

    def _serialize_public(self, o):
        r = { }
        for k in dir(o):
            #if k in attr_blacklist: continue
            if k.startswith('_'): continue
            if type(getattr(o, k)) in (types.BuiltinFunctionType, types.BuiltinMethodType, types.FunctionType, types.ClassType, type): continue
            r[k] = self.serialize(getattr(o, k))
        return r

    def _serialize_path_event(self, e):
        r = { }
        r['type'] = e.__class__.__name__
        r.update(self._serialize_public(e))
        return r

    def _serialize_path(self, p):
        return {
            'id': id(p),
            'length': p.length,
            'extra_length': p.extra_length,
            'backtrace': p.backtrace,
            'addr_backtrace': p.addr_backtrace,
            'callstack': p.callstack,
            'blockcounter_stack': p.blockcounter_stack,
            'event_log': [ self.serialize(e) for e in p.event_log ],
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

    def _serialize_simrun(self, s, ref):
        if isinstance(s, simuvex.SimIRSB):
            data = {'type': 'IRSB', 'addr': s.addr}
            if not ref:
                data['irsb'] = s._crawl_vex(s.irsb)
            return data
        if isinstance(s, simuvex.SimProcedure):
            return {'type': 'proc', 'name': s.__class__.__name__}
        else:
            raise Exception("Can't serialize SimRun {}".format(s))
