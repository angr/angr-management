import math
import logging

from PySide2.QtGui import QColor

_l = logging.getLogger(__name__)
# _l.setLevel('DEBUG')


try:
    from slacrs import Slacrs
    from slacrs.model import Input
except ImportError as ex:
    Slacrs = None
    HumanFatigue = None

class MultiPOI:
    """
    Multiple POIs
    """

    HIT_COLOR = QColor(0x00, 0x99, 0x00, 0x60)
    MISS_COLOR = QColor(0xee, 0xee, 0xee)
    FUNCTION_NOT_VISITED_COLOR = QColor(0x99, 0x00, 0x00, 0x20)
    BUCKET_COLORS = [QColor(0xef, 0x65, 0x48, 0x20), QColor(0xfc, 0x8d, 0x59, 0x60),
                     QColor(0xfd, 0xbb, 0x84, 0x60), QColor(0xfd, 0xd4, 0x9e, 0x60)]

    def __init__(self, workspace):
        self.workspace = workspace
        self._traces_summary = list()
        self._pois = dict()
        self.function_info = {}
        self.is_active_tab = False
        self.addr_color_map = dict()
        self.slacrs_url = "sqlite://"
        # self.base_addr = base_addr

    # def add_trace(self, trace, base_addr):
    #     traceStats = TraceStatistics(self.workspace, trace, base_addr)
    #     self._pois[trace["id"]] = traceStats
    #     self._traces_summary.extend(traceStats.mapped_trace)
    #     # self._make_addr_map()
    #     return traceStats

    def add_poi(self, poi_id, poi):
        _l.debug("adding poi: %s", poi)
        self._pois[poi_id] = poi

    def remove_poi(self, poi_id):
        self._pois.pop(poi_id, None)

    def update_poi(self, poi_id, column, content):
        poi = self.get_poi_by_id(poi_id)
        if column == 1:
            if content.isdecimal():
                poi['output']['bbl'] = int(content, 10)
            else:
                try:
                    poi['output']['bbl'] = int(content, 16)
                except ValueError:
                    poi['output']['bbl'] = ''
        if column == 2:
            poi['category'] = content
        if column == 3:
            poi['output']['diagnose'] = content
        self._pois[poi_id] = poi
        return poi

    def get_poi_by_id(self, poi_id):
        return self._pois[poi_id]

    def get_content_by_id_column(self, poi_id, column):
        if column == 0:
            return poi_id
        poi = self.get_poi_by_id(poi_id)
        if column == 1:
            return poi['output'].get('bbl', '')
        if column == 2:
            return poi.get('category', '')
        if column == 3:
            return poi['output'].get('diagnose', '')
        return ''

    def get_hit_miss_color(self, addr):
        # hexstr_addr = hex(addr)
        if addr in self.addr_color_map.keys():
            # return MultiTrace.BUCKET_COLORS[self.addr_color_map[addr]]
            return self.addr_color_map[addr]
        else:
            return MultiPOI.MISS_COLOR

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
        for trace in self._pois.values():
            if addr in trace["trace"]:
                return trace["trace"]

        return None

    def get_all_poi_ids(self):
        _l.debug('get_all_poi_ids: current pois: %s', self._pois)
        return self._pois.keys()

    def get_input_id_for_trace_id(self, trace_id):
        if trace_id not in self._pois.keys():
            self.workspace.log("ERROR - trace id %s not present in multitrace" % trace_id)
            return None
        trace = self._pois[trace_id]
        return trace.input_id

    def get_trace_with_id(self, trace_id):
        if trace_id not in self._pois.keys():
            self.workspace.log("ERROR - trace id %s not present in multitrace" % trace_id)
            return None
        return self._pois[trace_id]

    def get_last_slacrs_url(self):
        return self.slacrs_url

    def set_last_slacrs_url(self, url):
        self.slacrs_url = url

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
                input_seed_string = result.values('value')
            session.close()
        if input_seed_string == "<>":
            self.workspace.log("Unable to retrieve seed input for trace: %s" % trace_id)
        return input_seed_string

    def clear_heatmap(self):
        self._make_addr_map([])

    def reload_heatmap(self, poi_id):
        _l.debug('reloading heatmap')
        addrs_of_interest = []
        addr_list = self._pois[poi_id]['output']['bbl_history']
        addrs_of_interest.extend(addr_list)
        self._make_addr_map(addrs_of_interest)

    def _make_addr_map(self, addrs_of_interest):
        #TODO: Probably exists a more efficient way to generate this mapping
        self.addr_color_map.clear()
        hit_map = dict()
        for addr in addrs_of_interest:
            if addr not in hit_map.keys():
                hit_map[addr] = 0
            hit_map[addr] += 1

        buckets = dict()
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
            self.function_info[func.addr] = {"color": MultiPOI.FUNCTION_NOT_VISITED_COLOR, "coverage": 0}
        elif hit_count == len(blocks):
            self.function_info[func.addr] = {"color": MultiPOI.HIT_COLOR, "coverage": 100}
        else:
            hit_percent = (hit_count / len(blocks)) * 100
            bucket_size = 100 / len(MultiPOI.BUCKET_COLORS)
            bucket_pos = math.floor(hit_percent / bucket_size)
            self.function_info[func.addr] = {"color": MultiPOI.BUCKET_COLORS[bucket_pos], "coverage": hit_percent}
