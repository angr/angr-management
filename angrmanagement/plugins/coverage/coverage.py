import asyncio
import json
import logging
import math
import threading
import time

from typing import List, Iterator

from angr.sim_manager import SimulationManager
from angrmanagement.config import Conf
from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.widgets.qblock import QBlock
from angrmanagement.ui.widgets.qinst_annotation import QInstructionAnnotation, QPassthroughCount
from angrmanagement.utils.io import isurl, download_url
from angrmanagement.errors import UnexpectedStatusCodeError

from .parse_trace import trace_to_bb_addrs

from PySide2.QtGui import QColor

from tornado.platform.asyncio import AnyThreadEventLoopPolicy

l = logging.getLogger(__name__)
l.setLevel(logging.INFO)

try:
    import slacrs.model
except ImportError as ex:
    l.error("You don't have slacrs module installed locally, CoveragePlugin going to have a bad time.")
    pass

def generate_light_gradients(color, number, lightness=20):
    """
    return a List of QColors, where the colors are ordered in terms of
    lightness (last is given as color) the rest (total of number) are
    each lightness (%) lighter.
    """
    to_return = [color]
    for i in range(number):
        last_color = to_return[-1]
        to_return.append(last_color.lighter(100+lightness))
    to_return.reverse()
    return to_return

# TODO: This should really be a property of the target
TRACE_BASE = 0x4000000000

class CoveragePlugin(BasePlugin):
    def __init__(self, workspace):
        super().__init__(workspace)

        self.workspace = workspace

        # attempt to connect to the necessary components
        self.connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")

        if self.connector is None:
            self.workspace.log("Unable to retrieve plugin ChessConnector")

        self.slacrs_instance = self.connector.slacrs_instance()
        if self.slacrs_instance is None:
            self.workspace.log("Unable to retrieve Slacrs instance")

        self.hit_color = QColor(0, 20, 147)
        self.num_gradients = 8
        self.gradients = generate_light_gradients(self.hit_color, self.num_gradients)

        self.running = False
        self.slacrs_thread = None

        self.coverage_lock = threading.Lock()
        self.reset_coverage()
        
    MENU_BUTTONS = [
        'Start Showing Coverage',
        'Stop Showing Coverage',
    ]
    START_SHOWING_COVERAGE = 0
    STOP_SHOWING_COVERAGE = 1

    def handle_click_menu(self, idx):
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return
        
        mapping = {
            self.START_SHOWING_COVERAGE: self.start,
            self.STOP_SHOWING_COVERAGE: self.stop,
        }

        mapping.get(idx)()
        
    def start(self):
        self.running = True
        self.slacrs_thread = threading.Thread(target=self.listen_for_events)
        self.slacrs_thread.setDaemon(True)
        self.slacrs_thread.start()

    def stop(self):
        self.running = False

    def color_block(self, addr):
        if not self.running:
            return None
        with self.coverage_lock:
            if addr in self.bbl_coverage:
                return QColor(0, 20, 147)

    def color_func(self, func):
        if not self.running:
            return None

        func_bbls = func.block_addrs_set
        total_bbls = len(func_bbls)

        # Be paranoid
        if total_bbls == 0:
            return None
        
        with self.coverage_lock:
            covered_bbls = self.bbl_coverage & func_bbls

        # Never want to highlight something that wasn't covered
        if len(covered_bbls) == 0:
            return None

        fraction_covered = len(covered_bbls) / total_bbls

        gradient_number = math.ceil(fraction_covered * len(self.gradients))
        return self.gradients[gradient_number-1]

    def reset_coverage(self):
        with self.coverage_lock:
            self.seen_traces = set()
            self.bbl_coverage = set()

    def update_coverage_from_list(self, trace_addrs):
        l.info(f"Processing {len(trace_addrs)} from the trace")
        with self.coverage_lock:
            for addr in trace_addrs:
                self.bbl_coverage.add(addr)
            
    def update_coverage(self):
        session = self.slacrs_instance.session()
        if session:
            for trace in session.query(slacrs.model.Trace).filter(
                    slacrs.model.Trace.input.has(target_image_id=self.connector.target_image_id)).order_by(slacrs.model.Trace.created_at):
                self.update_one_coverage(trace)
    
    def update_one_coverage(self, trace):
        with self.coverage_lock:
            if trace.id in self.seen_traces:
                l.info(f"Already seen trace {trace.id}, skipping")
                return
            
        l.info(f"Processing trace {trace.id} {trace.input_id} {trace.created_at}")

        if not Conf.checrs_rest_endpoint_url:
            l.error(f"Unable to fetch trace {trace.id} because there is no CHECRS REST endpoint.")
            return

        url = f"{Conf.checrs_rest_endpoint_url}v1/targets/{self.connector.target_image_id}/seeds/{trace.input_id}/trace"
        try:
            trace_bytes = download_url(url, parent=self.workspace._main_window, to_file=False)
        except UnexpectedStatusCodeError:
            l.exception(f"Unable to download {url}")
            return
        try:
            parsed_trace = json.loads(trace_bytes)
        except json.JSONDecodeError as ex:
            l.exception("Unable to parse {url} as JSON")
            return

        bbl_addrs = trace_to_bb_addrs(parsed_trace, self.workspace.instance.project, TRACE_BASE)
        self.update_coverage_from_list(bbl_addrs)
        
        with self.coverage_lock:
            self.seen_traces.add(trace.id)
        l.info(f"Done processing trace {trace.id}")
    
    def listen_for_events(self):
        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())
        while not self.connector and self.running:
            self.connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
            time.sleep(1)

        while not self.slacrs_instance and self.running:
            self.slacrs_instance = self.connector.slacrs_instance()
            time.sleep(1)

        while not self.connector.target_image_id and self.running:
            time.sleep(1)

        if not self.running:
            return

        self.update_coverage()

        prev_target = self.connector.target_image_id
        while self.running:
            if self.connector.target_image_id != prev_target:
                self.reset_coverage()
                self.update_coverage()

            new_event_count = self.slacrs_instance.fetch_events()
            for _ in range(new_event_count):
                e = self.slacrs_instance.event_queue.get_nowait()
                session = self.slacrs_instance.session()
                if e.kind == "trace":
                    obj = e.get_object(session)
                    if session.query(slacrs.model.Trace).filter_by(id=e.object_id) == 1:
                        trace = session.query(slacrs.model.Trace).filter_by(obj.object_id).one()
                        self.update_one_coverage(trace)
                session.close()
