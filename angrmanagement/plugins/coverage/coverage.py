import asyncio
import json
import logging
import math
import threading
import time

from tornado.platform.asyncio import AnyThreadEventLoopPolicy
from PySide2.QtGui import QColor

from angrmanagement.config import Conf
from angrmanagement.errors import UnexpectedStatusCodeError
from angrmanagement.logic.threads import gui_thread_schedule, gui_thread_schedule_async
from angrmanagement.plugins import BasePlugin
from angrmanagement.utils.io import download_url

from .parse_trace import trace_to_bb_addrs

l = logging.getLogger(__name__)

try:
    import slacrs.model
except ImportError as ex:
    l.error("You don't have slacrs module installed locally, CoveragePlugin going to have a bad time.")


def generate_light_gradients(color, number, lightness=20):
    """
    return a List of QColors, where the colors are ordered in terms of
    lightness (last is given as color) the rest (total of number) are
    each lightness (%) lighter.
    """
    to_return = [color]
    for _ in range(number):
        last_color = to_return[-1]
        to_return.append(last_color.lighter(100+lightness))
    to_return.reverse()
    return to_return

# TODO: This should really be a property of the target
TRACE_BASE = 0x4000000000


class CoveragePlugin(BasePlugin):
    """
    Implements the fuzzing coverage view.
    """

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

        self.dark_theme_color = QColor(0, 20, 147)
        self.light_theme_color = QColor(225, 174, 0)
        self.hit_color = self.dark_theme_color if Conf.theme_name == "dark" else self.light_theme_color
        self.num_gradients = 16
        self.gradients = generate_light_gradients(self.hit_color, self.num_gradients, lightness=int(100 / 16))

        self.running = False
        self.slacrs_thread = None

        self.seen_traces = None
        self.bbl_coverage = None
        self.bbl_coverage_hash = 0

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
        self.slacrs_thread = threading.Thread(target=self.listen_for_events, daemon=True)
        self.slacrs_thread.start()
        gui_thread_schedule(self._refresh_gui)

    def stop(self):
        self.running = False
        gui_thread_schedule(self._refresh_gui)
        if self.workspace._main_window is not None:
            gui_thread_schedule_async(self.workspace._main_window.progress_done)

    def _coverage_of_func(self, func):
        """
        return (set of covered_bbls, and num_of_function_bbls)
        """
        func_bbls = func.block_addrs_set
        with self.coverage_lock:
            covered_bbls = self.bbl_coverage & func_bbls

        return covered_bbls, len(func_bbls)

    def color_block(self, addr):
        if not self.running:
            return None
        with self.coverage_lock:
            if addr in self.bbl_coverage:
                return self.dark_theme_color if Conf.theme_name == "dark" else self.light_theme_color
        return None

    def color_func(self, func):
        if not self.running:
            return None

        covered_bbls, total_bbls = self._coverage_of_func(func)

        # Be paranoid
        if total_bbls == 0:
            return None

        # Never want to highlight something that wasn't covered
        if len(covered_bbls) == 0:
            return None

        fraction_covered = len(covered_bbls) / total_bbls

        gradient_number = math.ceil(fraction_covered * len(self.gradients))
        return self.gradients[gradient_number-1]

    FUNC_COLUMNS = ('Fuzzing Coverage',)

    def extract_func_column(self, func, idx):
        assert idx == 0
        if not self.running:
            return 0, "0%"

        covered_bbls, total_bbls = self._coverage_of_func(func)
        if len(covered_bbls) == 0:
            return 0, "0%"

        fraction_covered = len(covered_bbls) / total_bbls

        return fraction_covered, f"{int(round(fraction_covered*100,0))}%"

    def _refresh_gui(self):
        self.workspace.refresh()

    def reset_coverage(self):
        with self.coverage_lock:
            self.seen_traces = set()
            self.bbl_coverage = set()
            self.bbl_coverage_hash = 0

    def update_coverage_from_list(self, trace_addrs):
        l.info("Processing %d from the trace", len(trace_addrs))
        with self.coverage_lock:
            for addr in trace_addrs:
                self.bbl_coverage.add(addr)

        new_hash = hash(frozenset(self.bbl_coverage))
        if new_hash != self.bbl_coverage_hash:
            self.bbl_coverage_hash = new_hash
            gui_thread_schedule(self._refresh_gui)

    def update_coverage(self):
        self.set_status("Retrieving fuzzing coverage information...", 0.)
        session = self.slacrs_instance.session()
        if session:
            for idx, trace in enumerate(session.query(slacrs.model.Trace).filter(
                    slacrs.model.Trace.input.has(target_image_id=self.connector.target_image_id)
            ).order_by(slacrs.model.Trace.created_at)):
                if not self.running:
                    break
                self.set_status(f"Processing trace {idx}...", 50.)
                self.update_one_coverage(trace)
        self.set_status("Fuzzing coverage updated", 100.)

    def update_one_coverage(self, trace):
        with self.coverage_lock:
            if trace.id in self.seen_traces:
                l.info("Already seen trace %s, skipping", trace.id)
                return

        l.info("Processing trace %s %s %s", trace.id, trace.input_id, trace.created_at)

        if not Conf.checrs_rest_endpoint_url:
            l.error("Unable to fetch trace %d because there is no CHECRS REST endpoint.", trace.id)
            return

        url = f"{Conf.checrs_rest_endpoint_url}v1/targets/{self.connector.target_image_id}/seeds/{trace.input_id}/trace"
        try:
            trace_bytes = download_url(url, parent=self.workspace._main_window, to_file=False)
        except UnexpectedStatusCodeError:
            l.exception("Unable to download %s.", url)
            return
        try:
            parsed_trace = json.loads(trace_bytes)
        except json.JSONDecodeError:
            l.exception("Unable to parse %s as JSON.", url)
            return

        bbl_addrs = trace_to_bb_addrs(parsed_trace, self.workspace.instance.project, TRACE_BASE)
        self.update_coverage_from_list(bbl_addrs)

        with self.coverage_lock:
            self.seen_traces.add(trace.id)
        l.info("Done processing trace %s.", trace.id)

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

            self.set_status("Retrieving fuzzing coverage information...", 0.)
            new_event_count = self.slacrs_instance.fetch_events()
            trace_idx = 0
            for idx in range(new_event_count):
                e = self.slacrs_instance.event_queue.get_nowait()
                session = self.slacrs_instance.session()
                if e.kind == "trace":
                    obj = e.get_object(session)
                    if session.query(slacrs.model.Trace).filter_by(id=e.object_id) == 1:
                        if not self.running:
                            break
                        trace = session.query(slacrs.model.Trace).filter_by(obj.object_id).one()
                        self.set_status(f"Processing trace {trace_idx}...", idx * 100 / new_event_count)
                        trace_idx += 1
                        self.update_one_coverage(trace)
                session.close()
            self.set_status("Fuzzing coverage updated", 100.)

    def set_status(self, status: str, percentage: float):
        if self.workspace._main_window is not None:
            gui_thread_schedule_async(self.workspace._main_window.progress, (status, percentage))
