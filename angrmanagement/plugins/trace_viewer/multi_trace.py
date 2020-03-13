import math

from PySide2.QtGui import QColor


class MultiTrace:

    HIT_COLOR = QColor(0xee, 0xee, 0xee)
    MISS_COLOR = QColor(0x99, 0x00, 0x00, 0x30)
    FUNCTION_NOT_VISITED_COLOR = QColor(0x99, 0x00, 0x00, 0x20)
    BUCKET_COLORS = [QColor(0xef, 0x65, 0x48, 0x20), QColor(0xfc, 0x8d, 0x59, 0x60),
                     QColor(0xfd, 0xbb, 0x84, 0x60), QColor(0xfd, 0xd4, 0x9e, 0x60)]

    def __init__(self, workspace, multi_trace, base_addr):
        self.workspace = workspace
        self._traces_summary = multi_trace["summary"]
        self._traces = multi_trace["traces"]
        self.function_info = {}
        self.base_addr = base_addr

    def get_hit_miss_color(self, addr):
        hexstr_addr = hex(addr)
        if hexstr_addr not in self._traces_summary:
            return MultiTrace.MISS_COLOR
        else:
            return MultiTrace.HIT_COLOR

    def get_percent_color(self, func):
        if func.addr not in self.function_info:
            self._calc_function_info(func)

        return self.function_info[func.addr]["color"]

    def get_coverage(self, func):
        if func.addr not in self.function_info:
            self._calc_function_info(func)
        return self.function_info[func.addr]["coverage"]

    def get_any_trace(self, addr):
        for trace in self._traces.values():
            if addr in trace["trace"]:
                return trace["trace"]

        return None

    def _calc_function_info(self, func):
        blocks = list(func.block_addrs)
        hit_count = 0

        for block in blocks:
            hexstr_addr = hex(block)
            if hexstr_addr in self._traces_summary:
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
