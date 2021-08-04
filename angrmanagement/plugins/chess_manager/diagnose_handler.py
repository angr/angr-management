import asyncio
import json
import logging
import os.path
import threading
from logging import Formatter
from time import sleep
from typing import Optional

from getmac import get_mac_address as gma
from sqlalchemy.exc import OperationalError
from tornado.platform.asyncio import  AnyThreadEventLoopPolicy

from angrmanagement.config import Conf

try:
    from slacrs import Slacrs
    from slacrs.model import Poi
except ImportError as _:
    Slacrs = None
    Poi = None

l = logging.getLogger(__name__)
l.setLevel('INFO')

def _init_logger():
    user_dir = os.path.expanduser('~')
    log_dir = os.path.join(user_dir, 'am-logging')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'poi_diagnose.log')
    fh = logging.FileHandler(log_file)
    fh.setLevel('INFO')
    formatter: Formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    l.addHandler(fh)


class DiagnoseHandler:
    """
    Handling POI records in slacrs
    """
    def __init__(self, project_name=None, project_md5=None):
        _init_logger()

        self.project_name = project_name
        self.project_md5 = project_md5

        self._log_list = [ ]
        self.workspace = None
        self.slacrs_thread = None
        self.user = gma()

        if Slacrs is None or Poi is None:
            self._active = False
        else:
            self._active = True

    def init(self, workspace):
        l.debug("workspace initing")
        self.workspace = workspace
        self._active = True
        self.slacrs_thread = threading.Thread(target=self._commit_pois)
        self.slacrs_thread.setDaemon(True)
        self.slacrs_thread.start()

    def get_image_id(self) -> Optional[str]:
        connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
        if connector is None:
            return None
        try:
            return connector.target_image_id
        except (ValueError, AttributeError):
            return None

    def submit_updated_poi(self, poi_id: str, poi_json):
        # reference: https://github.com/checrs/slacrs7/blob/master/slacrs/plugins/arbiter.py#L81
        image_id = self.get_image_id()
        if image_id is None:
            l.warning("Cannot submit POI %s since the current target ID is unknown.",
                      poi_id)
            return

        poi = Poi()
        poi.plugin = self.user
        poi.target_image_id = image_id
        poi.id = poi_id
        poi.poi = json.dumps(poi_json)

        # Additional fields according to Slacrs's Base and Poi classes.
        poi.source = self.user  # https://github.com/checrs/slacrs7/blob/master/slacrs/model/poi.py#L13
        poi.created_by = self.user # https://github.com/checrs/slacrs7/blob/master/slacrs/model/base.py#L17

        l.debug('adding poi: %s', poi)
        l.info('adding poi: %s, id: %s, id: %s ', poi, poi.id, poi_id)
        self._log_list.append(poi)
        l.debug('current log list: %s', self._log_list)

    def get_pois(self):
        if not Conf.checrs_backend_str:
            return None

        try:
            connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
            if connector is None:
                # chess connector does not exist
                return None
            slacrs_instance = connector.slacrs_instance()
            if slacrs_instance is None:
                # slacrs does not exist. continue
                return None
            session = slacrs_instance.session()
        except OperationalError:
            # Cannot connect
            return None

        image_id = self.get_image_id()
        if image_id is not None:
            result = session.query(Poi).filter(Poi.target_image_id==image_id).all()
        else:
            result = session.query(Poi).all()
        session.close()
        l.debug('result: %s', result)
        return result


    def deactivate(self):
        self._active = False

    def _commit_pois(self):
        l.debug("database: %s", Conf.checrs_backend_str)
        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())
        while self._active:
            sleep(3)
            if self._log_list:
                # we have things to submit!
                try:
                    connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
                    if connector is None:
                        # chess connector does not exist
                        continue
                    slacrs_instance = connector.slacrs_instance()
                    if slacrs_instance is None:
                        # slacrs does not exist. continue
                        continue
                    session = slacrs_instance.session()
                except OperationalError:
                    l.error("Failed to CHECRS backend. Try again later...")
                    continue

                with session.no_autoflush:
                    while self._log_list:
                        poi = self._log_list.pop()
                        # query first to see if the poi id already exist
                        result = session.query(Poi).filter(Poi.id == poi.id).first()
                        if result is None:
                            l.info('Adding poi %s to slacrs', poi)
                            session.add(poi)
                        else:
                            l.info('Updating poi %s to slacrs', poi)
                            result.poi = poi.poi
                        l.debug('log_list: %s', self._log_list)
                    session.commit()
                session.close()
