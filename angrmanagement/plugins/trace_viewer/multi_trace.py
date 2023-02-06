import math

from PySide6.QtGui import QColor

from .trace_statistics import TraceStatistics

try:
    from slacrs import Slacrs
    from slacrs.model import Input
except ImportError:
    Slacrs = None
    HumanFatigue = None


class MultiTrace:
    HIT_COLOR = QColor(0x00, 0x99, 0x00, 0x60)
    MISS_COLOR = QColor(0xEE, 0xEE, 0xEE)
    FUNCTION_NOT_VISITED_COLOR = QColor(0x99, 0x00, 0x00, 0x20)
    BUCKET_COLORS = [
        QColor(0xEF, 0x65, 0x48, 0x20),
        QColor(0xFC, 0x8D, 0x59, 0x60),
        QColor(0xFD, 0xBB, 0x84, 0x60),
        QColor(0xFD, 0xD4, 0x9E, 0x60),
    ]

    def __init__(self, workspace):
        self.workspace = workspace
        self._traces_summary = []
        self._traces = {}
        self.function_info = {}
        self.is_active_tab = False
        self.addr_color_map = {}
        # self.base_addr = base_addr

    def add_trace(self, trace, base_addr):
        traceStats = TraceStatistics(self.workspace, trace, base_addr)
        self._traces[trace["id"]] = traceStats
        self._traces_summary.extend(traceStats.mapped_trace)
        # self._make_addr_map()
        return traceStats

    def get_hit_miss_color(self, addr):
        # hexstr_addr = hex(addr)
        if addr in self.addr_color_map.keys():
            # return MultiTrace.BUCKET_COLORS[self.addr_color_map[addr]]
            return self.addr_color_map[addr]
        else:
            return MultiTrace.MISS_COLOR

    def get_percent_color(self, func):
        addr = func.addr
        if addr in self.addr_color_map.keys():
            # return MultiTrace.BUCKET_COLORS[self.addr_color_map[addr]]
            return self.addr_color_map[addr]
        return None

        # if func.addr not in self.function_info:
        #     self._calc_function_info(func)

        # return self.function_info[func.addr]["color"]

    def get_coverage(self, func):
        if func.addr not in self.function_info:
            self._calc_function_info(func)
        return self.function_info[func.addr]["coverage"]

    def get_any_trace(self, addr):
        for trace in self._traces.values():
            if addr in trace["trace"]:
                return trace["trace"]

        return None

    def get_all_trace_ids(self):
        return self._traces.keys()

    def get_input_id_for_trace_id(self, trace_id):
        if trace_id not in self._traces.keys():
            self.workspace.log("ERROR - trace id %s not present in multitrace" % trace_id)
            return None
        trace = self._traces[trace_id]
        return trace.input_id

    def get_trace_with_id(self, trace_id):
        if trace_id not in self._traces.keys():
            self.workspace.log("ERROR - trace id %s not present in multitrace" % trace_id)
            return None
        return self._traces[trace_id]

    def get_input_seed_for_id(self, trace_id):
        input_seed_string = "<>"

        if not Slacrs:
            self.workspace.log("slacrs not installed, unable to retrieve trace seed inputs")
            return "<>"

        connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
        if connector is None:
            # chess connector does not exist
            return None
        slacrs_instance = connector.slacrs_instance()
        if slacrs_instance is None:
            # slacrs does not exist. continue
            return None

        session = slacrs_instance.session()
        if session:
            result = session.query(Input).filter_by(id=trace_id).first()
            if result:
                input_seed_string = result.value
            session.close()
        if input_seed_string == "<>":
            self.workspace.log("Unable to retrieve seed input for trace: %s" % trace_id)
        return input_seed_string

    def clear_heatmap(self):
        self._make_addr_map([])

    def reload_heatmap(self, targets):
        addrs_of_interest = []
        for trace_id in targets:
            if trace_id not in self._traces.keys():
                self.workspace.log("%s not found in traces" % trace_id)
                continue
            addr_list = self._traces[trace_id].mapped_trace
            addrs_of_interest.extend(addr_list)
        self._make_addr_map(addrs_of_interest)

    def _make_addr_map(self, addrs_of_interest):
        # TODO: Probably exists a more efficient way to generate this mapping
        self.addr_color_map.clear()
        hit_map = {}
        for addr in addrs_of_interest:
            if addr not in hit_map.keys():
                hit_map[addr] = 0
            hit_map[addr] += 1

        buckets = {}
        for addr, count in hit_map.items():
            if count not in buckets.keys():
                buckets[count] = []
            buckets[count].append(addr)

        strata_size = math.floor(len(set(addrs_of_interest)) / 9)

        total = 0
        bucket_counts = sorted(buckets.keys())
        for count in bucket_counts:
            addrs = buckets[count]
            density = 50 + math.floor(total / strata_size) * 20
            color = QColor(0xFF, 0xFF, 0x30, density)
            for addr in addrs:
                self.addr_color_map[addr] = color
            total += len(addrs)

    def _calc_function_info(self, func):
        blocks = list(func.block_addrs)
        hit_count = 0

        for block_addr in blocks:
            # hexstr_addr = hex(block)
            if block_addr in self._traces_summary:
                hit_count += 1

        if hit_count == 0:
            self.function_info[func.addr] = {"color": MultiTrace.FUNCTION_NOT_VISITED_COLOR, "coverage": 0}
        elif hit_count == len(blocks):
            self.function_info[func.addr] = {"color": MultiTrace.HIT_COLOR, "coverage": 100}
        else:
            hit_percent = (hit_count / len(blocks)) * 100
            bucket_size = 100 / len(MultiTrace.BUCKET_COLORS)
            bucket_pos = math.floor(hit_percent / bucket_size)
            self.function_info[func.addr] = {"color": MultiTrace.BUCKET_COLORS[bucket_pos], "coverage": hit_percent}
