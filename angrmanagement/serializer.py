import angr
import simuvex
import claripy

import types
from rpyc.utils.classic import obtain

class Serializer(object):
    def __init__(self):
        pass

    def serialize(self, o, ref=False, extra=None):
        r = self._serialize_switch(o, ref=ref, extra=extra)
        if extra is not None and type(r) is dict:
            r.update(extra)
        return obtain(r)

    def _serialize_switch(self, o, ref=False, extra=None):
        if o is None:
            return None
        if type(o) in (long, int, str, unicode, float, bool):
            return o
        if type(o) in (list, tuple, set) or type(o).__module__ == '__builtin__' and type(o).__name__ in ('list', 'tuple', 'set'):
            return [ self.serialize(e, extra=extra) for e in o ]
        if type(o) is dict or type(o).__module__ == '__builtin__' and type(o).__name__ == "dict":
            return { self.serialize(k, extra=extra):self.serialize(v, extra=extra) for k,v in o.iteritems() }
        if isinstance(o, angr.Surveyor):
            return self._serialize_surveyor(o, extra=extra)
        if isinstance(o, angr.Path):
            return self._serialize_path(o, extra=extra)
        if isinstance(o, simuvex.SimState):
            return self._serialize_state(o, extra=extra)
        if isinstance(o, simuvex.SimRun):
            return self._serialize_simrun(o, ref, extra=extra)
        if isinstance(o, angr.PathEvent):
            return self._serialize_path_event(o, extra=extra)
        if isinstance(o, claripy.E):
            return self._serialize_expression(o, extra=extra)
        if isinstance(o, claripy.A):
            return self._serialize_ast(o, extra=extra)
        if isinstance(o, claripy.BVV):
            return self._serialize_bvv(o, extra=extra)
        if isinstance(o, angr.CFG):
            return self._serialize_cfg(o, extra=extra)
        else:
            return "NOT SERIALIZED: %s" % o

    def _serialize_state(self, s, extra=None): #pylint:disable=W0613
        return str(s)

    def _serialize_public(self, o, extra=None):
        r = { }
        for k in dir(o):
            #if k in attr_blacklist: continue
            if k.startswith('_'): continue
            if type(getattr(o, k)) in (types.BuiltinFunctionType, types.BuiltinMethodType, types.FunctionType, types.ClassType, type): continue
            r[k] = self.serialize(getattr(o, k), extra=extra)
        return r

    def _serialize_path_event(self, e, extra=None): #pylint:disable=W0613
        r = { }
        r['event_type'] = e.__class__.__name__
        r.update(self._serialize_public(e, extra=extra))
        return r

    def _serialize_call_frame(self, cf):
        return {
            'faddr': self.serialize(cf.faddr),
            'taddr': self.serialize(cf.taddr),
            'sptr': self.serialize(cf.sptr),
        }

    def _serialize_path(self, p, extra=None):
        if extra is None: extra = { 'path_id': id(p) }
        else: extra['path_id'] = id(p)

        return {
            'id': id(p),
            'length': p.length,
            'extra_length': p.extra_length,
            'backtrace': p.backtrace,
            'addr_backtrace': p.addr_backtrace,
            'callstack': [self._serialize_call_frame(cf) for cf in p.callstack],
            'blockcounter_stack': p.blockcounter_stack,
            'last_addr': p.last_run.addr if p.last_run is not None else "NOT STARTED",
            'event_log': [ self.serialize(e, extra=extra) for e in p.event_log ],
        }

    def _serialize_surveyor(self, s, extra=None):
        if extra is None: extra = { 'surveyor_id': id(s) }
        else: extra['surveyor_id'] = id(s)

        return {
            'id': id(s),
            'type': s.__class__.__name__,
            'path_lists': { n:[ self.serialize(p, extra=extra) for p in getattr(s, n) ] for n in s.path_lists },
            'step': s._current_step,
            'max_concurrency': s._max_concurrency,
            'save_deadends': s._save_deadends,
        }

    def _serialize_simrun(self, s, ref, extra=None): #pylint:disable=W0613
        if isinstance(s, simuvex.SimIRSB):
            data = {'type': 'IRSB', 'addr': s.addr}
            if not ref:
                print "serializing 0x{:x}".format(s.addr)
                data['irsb'] = s._crawl_vex(s.irsb)
            return data
        if isinstance(s, simuvex.SimProcedure):
            return {'type': 'proc', 'name': s.__class__.__name__}
        else:
            raise Exception("Can't serialize SimRun {}".format(s))

    def _serialize_ast(self, a, extra=None):
        return {
            'expr_type': 'ast',
            'op': a.op,
            'ast_type': ( 'binop' if a.op.startswith('__') and len(a.args) == 2 else
                          'unop' if a.op.startswith('__') and len(a.args) == 1 else
                          a.op ),
            'args': self.serialize(a.args, extra=extra)
        }

    def _serialize_expression(self, e, extra=None):
        return {
            'id': id(e),
            'expr_type': 'e',
            'ast': self.serialize(e._model, extra=extra),
            'symbolic': e.symbolic,
            'variables': self.serialize(e.variables, extra=extra)
        }

    def _serialize_bvv(self, b, extra=None): #pylint:disable=W0613
        return {
            'expr_type': 'bvv',
            'value': b.value,
            'bits': b.bits
        }

    def _serialize_cfg(self, cfg, extra=None):
        graph = cfg._graph
        return {
            'nodes': [self.serialize(node) for node in graph.nodes()],
            'edges': [{
                    'from': self.serialize(from_, ref=True),
                    'to': self.serialize(to, ref=True)}
                for from_, to in graph.edges()
                if any(
                    any(exit.can_target(to.addr) for exit in irsb.exits(reachable=True))
                    for irsb in cfg.get_all_irsbs(from_.addr))],
            'functions': {addr: obtain(f.basic_blocks) for addr, f in cfg.get_function_manager().functions.items()}
        }
