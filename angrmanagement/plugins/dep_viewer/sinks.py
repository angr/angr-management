from collections import defaultdict
from typing import Dict, List, Optional, Tuple


class VulnerabilityType:
    PATH_TRAVERSAL = 1
    COMMAND_INJECTION = 2
    SQL_INJECTION = 3

    @staticmethod
    def to_string(vuln_type: int):
        if vuln_type == VulnerabilityType.PATH_TRAVERSAL:
            return "Path travesal"
        elif vuln_type == VulnerabilityType.COMMAND_INJECTION:
            return "Command injection"
        elif vuln_type == VulnerabilityType.SQL_INJECTION:
            return "SQL injection"

        return "Unknown"


class BaseSink:
    pass


class FunctionArgumentSink(BaseSink):
    def __init__(self, lib: Optional[str], func_name, arg_idx, platforms: Optional[List[str]] = None):
        self.lib = lib
        self.func_name = func_name
        self.arg_idx = arg_idx
        self.platforms = platforms

    def __repr__(self):
        return "<TS %s:arg %d>" % (self.func_name, self.arg_idx)


class SinkManager:
    def __init__(self, sinks: Dict[int, List[BaseSink]]):
        self.sinks = sinks

        # lookup caches
        self._func_to_sinks: Dict[str, List[Tuple[int, FunctionArgumentSink]]] = defaultdict(list)

        self._init_caches()

    def _init_caches(self):
        for vuln_type, sinks in self.sinks.items():
            for sink in sinks:
                if isinstance(sink, FunctionArgumentSink):
                    self._func_to_sinks[sink.func_name].append((vuln_type, sink))

    def has_function_sink(self, func_name, lib: Optional[str] = None) -> bool:
        if func_name not in self._func_to_sinks:
            return False
        if lib is None:
            return True
        # compare lib name
        sinks = self._func_to_sinks[func_name]
        return any(sink[1].lib == lib for sink in sinks)

    def get_function_sinks(self, func_name, lib: Optional[str] = None) -> List[Tuple[int, FunctionArgumentSink]]:
        if func_name not in self._func_to_sinks:
            return []
        if lib is None:
            return self._func_to_sinks[func_name]
        # compare lib name
        sinks = self._func_to_sinks[func_name]
        return list(sink for sink in sinks if sink[1].lib == lib)


FAS = FunctionArgumentSink

_path_traversal_sinks = [
    FAS("libc", "fopen", 0),
    FAS("libc", "chdir", 0),
    FAS(None, "std::basic_ifstream::__ctor__", 1),
]

_command_injection_sinks = [
    FAS("libc", "system", 0),
    FAS("libc", "popen", 0),
]

# TODO: SQL injection sinks require certain conditions to be met
_sql_injection_sinks = [
    FAS("libc", "asprintf", 0),
    FAS("libc", "sprintf", 0),
]

_sinks = {
    VulnerabilityType.PATH_TRAVERSAL: _path_traversal_sinks,
    VulnerabilityType.COMMAND_INJECTION: _command_injection_sinks,
}

sink_manager = SinkManager(_sinks)
