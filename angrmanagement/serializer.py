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
            raise Exception("Can't serialize %s", o)

    def _serialize_state(self, s):
        raise NotImplementedError("TODO")

    def _serialize_path(self, p):
        raise NotImplementedError("TODO")

    def _serialize_surveyor(self, s):
        return { 'id': s, 'active': 'TODO' }
