import angr
import simuvex
import claripy

import types
from rpyc.utils.classic import obtain

class Serializer(object):
    def __init__(self):
        pass

    def serialize(self, o, ref=False):
        if o is None:
            return None
        if type(o) in (long, int, str, unicode, float, bool):
            return o
        if type(o) in (list, tuple, set) or type(o).__module__ == '__builtin__' and type(o).__name__ in ('list', 'tuple', 'set'):
            return [ self.serialize(e) for e in o ]
        if type(o) is dict or type(o).__module__ == '__builtin__' and type(o).__name__ == "dict":
            return { self.serialize(k):self.serialize(v) for k,v in o.iteritems() }
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
        if isinstance(o, claripy.E):
            return self._serialize_expression(o)
        if isinstance(o, claripy.A):
            return self._serialize_ast(o)
        if isinstance(o, claripy.BVV):
            return self._serialize_bvv(o)
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
        r['event_type'] = e.__class__.__name__
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
            'last_addr': p.last_run.addr if p.last_run is not None else "NOT STARTED",
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
                print "serializing 0x{:x}".format(s.addr)
                data['irsb'] = obtain(s._crawl_vex(s.irsb))
            return data
        if isinstance(s, simuvex.SimProcedure):
            return {'type': 'proc', 'name': s.__class__.__name__}
        else:
            raise Exception("Can't serialize SimRun {}".format(s))

    def _serialize_ast(self, a):
        return {
            'expr_type': 'ast',
            'op': a._op,
            'ast_type': ( 'binop' if a._op.startswith('__') and len(a._args) == 2 else
                          'unop' if a._op.startswith('__') and len(a._args) == 1 else
                          a._op ),
            'args': self.serialize(a._args)
        }

    def _serialize_expression(self, e):
        return {
            'id': id(e),
            'expr_type': 'e',
            'ast': self.serialize(e.abstract())
        }

    def _serialize_bvv(self, b):
        return {
            'expr_type': 'bvv',
            'value': b.value,
            'bits': b.bits
        }
