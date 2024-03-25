from __future__ import annotations

try:
    import bintrace
    from bintrace.debugger_angr import get_angr_project_load_options_from_trace
except ImportError:
    bintrace = None


class Trace:
    """
    Base class for different trace formats.
    """

    @property
    def source(self) -> str:
        raise NotImplementedError

    @classmethod
    def trace_backend_enabled(cls) -> bool:
        return False

    def get_project_load_options(self):  # pylint:disable=no-self-use
        return None


class BintraceTrace(Trace):
    """
    Bintrace execution trace.
    """

    def __init__(self, trace: bintrace.Trace) -> None:
        assert BintraceTrace.trace_backend_enabled()
        self.trace: bintrace.Trace = trace

    @property
    def source(self) -> str:
        return self.trace.path

    @classmethod
    def load_trace(cls, path: str) -> BintraceTrace:
        trace = bintrace.Trace()
        trace.load_trace(path)
        return cls(trace)

    @classmethod
    def trace_backend_enabled(cls) -> bool:
        return bintrace is not None

    def get_project_load_options(self):
        return get_angr_project_load_options_from_trace(self.trace)
