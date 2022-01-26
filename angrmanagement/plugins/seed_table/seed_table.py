import asyncio
import threading

from time import sleep
from typing import Dict, List
from tornado.platform.asyncio import AnyThreadEventLoopPolicy

try:
    from slacrs import Slacrs
    from slacrs.model import Input, InputTag
except ImportError as ex:
    Slacrs = None


class Seed:
    def __init__(self, seed: Input, id: int):
        self.created_at = seed.created_at
        self.tags: List[str] = [x.value for x in seed.tags]
        self.value: bytes = seed.value
        self._realid = seed.id
        self.id: str = hex(id)[2:].rjust(8, "0")

class SeedTable:
    """
    Multiple POIs
    """
    query_signal = None

    def __init__(self, workspace, query_signal, seed_callback=None):
        self.workspace = workspace
        self.seed_callback = seed_callback
        self.connector = None
        self.slacrs_instance = None
        self.should_exit = False
        self.query_signal = query_signal

        self.init_instance()
        self.has_populated_seeds = False

        self.slacrs_thread = threading.Thread(target=self.listen_for_events)
        self.slacrs_thread.setDaemon(True)
        self.slacrs_thread.start()


    def init_instance(self):
        self.connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")

        if self.connector is None:
            self.workspace.log("Unable to retrieve plugin ChessConnector")
            return False

        self.slacrs_instance = self.connector.slacrs_instance()

        if self.slacrs_instance is None:
            self.workspace.log("Unable to retrieve Slacrs instance")
            return False

        return True


    def listen_for_events(self):
        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())
        while not self.connector:
            self.connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
            sleep(1)

        while not self.slacrs_instance:
            self.slacrs_instance = self.connector.slacrs_instance()
            sleep(1)

        while not self.connector.target_image_id:
            sleep(1)

        self.seed_callback(self.get_all_seeds())
        self.has_populated_seeds = True

        prev_target = self.connector.target_image_id
        while not self.should_exit:
            if self.connector.target_image_id != prev_target:
                prev_target = self.connector.target_image_id
                self.seed_callback(self.get_all_seeds())

            new_event_count = self.slacrs_instance.fetch_events()
            for _ in range(new_event_count):
                e = self.slacrs_instance.event_queue.get_nowait()
                session = self.slacrs_instance.session()
                if e.kind == "input":
                    obj = e.get_object(session)
                    if session.query(Input).filter_by(id=e.object_id).filter_by(target_image_id=self.connector.target_image_id) == 1:
                        seed = session.query(Input).filter_by(obj.object_id).one()
                        self.seed_callback(seed)
                session.close()

    def filter_seeds_by_value(self, value: bytes):
        self.query_signal.querySignal.emit(True)
        session = self.slacrs_instance.session()
        seeds: List[Seed] = []
        if session:
            query = str(session.query(Input.id))
            query += f"\nWHERE POSITION('\\x{value.hex()}'::bytea in input.value) != 0\nORDER BY input.created_at"
            result = session.execute(query)
            seeds = [Seed(session.query(Input).filter_by(id=s_id[0]).first(), idx) for idx, s_id in enumerate(result)]
            session.close()
        return seeds

    def filter_seeds_by_tag(self, tags: List[str]=[]) -> List[Seed]:
        self.query_signal.querySignal.emit(True)
        session = self.slacrs_instance.session()
        seeds: List[Seed] = []
        if session:
            result = session.query(Input).join(Input.tags)
            for tag in tags:
                result = result.filter(Input.tags.any(InputTag.value == tag))
            result = result.order_by(Input.created_at).all()
            seeds = [Seed(inp, idx) for idx, inp in enumerate(result)]
        return seeds

    def get_all_seeds(self, filter=None):
        self.query_signal.querySignal.emit(True)
        session = self.slacrs_instance.session()
        seeds: List[Seed] = []
        if session:
            result = session.query(Input).filter_by(target_image_id=self.connector.target_image_id).order_by(Input.created_at).all()
            seeds = [Seed(inp, idx) for idx, inp in enumerate(result)]
            #seeds = list(map(lambda val, i: Seed(val, i), enumerate(result))
            session.close()
        if len(seeds) == 0:
            self.workspace.log("Unable to retrieve seeds for target_image_id: %s" % self.connector.target_image_id)

        return seeds