import asyncio
import json
import logging
import os.path
import threading
from logging import Formatter
from time import sleep
from getmac import get_mac_address as gma
from tornado.platform.asyncio import  AnyThreadEventLoopPolicy

from angrmanagement.config import Conf

try:
    from slacrs import Slacrs
    from slacrs.model import Poi
except ImportError as _:
    Slacrs = None
    Poi = None

l = logging.getLogger(__name__)
l.setLevel('DEBUG')

user_dir = os.path.expanduser('~')
log_dir = os.path.join(user_dir, 'am-logging')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'poi_diagnose.log')
fh = logging.FileHandler(log_file)
fh.setLevel('INFO')
formatter: Formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
l.addHandler(fh)

class DiagnoseHandler(object):
    def __init__(self, project_name=None, project_md5=None, image_id=None):
        self.project_name = project_name
        self.project_md5 = project_md5
        self.image_id = image_id

        self._log_list = list()
        self.slacrs_thread = None
        self.slacrs = Slacrs(database=Conf.checrs_backend_str)
        self.user = gma()

        if Slacrs is None or Poi is None:
            self._active = False
        else:
            self._active = True

    def init(self, workspace):
        l.debug("workspace initing")
        self._active = True
        self.slacrs_thread = threading.Thread(target=self._commit_pois)
        self.slacrs_thread.setDaemon(True)
        self.slacrs_thread.start()

    def submit_updated_poi(self, id, poi_json):
        # reference: https://github.com/checrs/slacrs7/blob/master/slacrs/plugins/arbiter.py#L81
        poi = Poi()
        poi.plugin = self.user
        poi.target_image_id = self.image_id
        poi.id = id
        poi.poi = json.dumps(poi_json)

        # Additional fields according to Slacrs's Base and Poi classes.
        poi.source = self.user  # https://github.com/checrs/slacrs7/blob/master/slacrs/model/poi.py#L13
        poi.created_by = self.user # https://github.com/checrs/slacrs7/blob/master/slacrs/model/base.py#L17

        l.debug('adding poi: %s', poi)
        l.info('adding poi: %s', poi)
        self._log_list.append(poi)
        l.debug('current log list: %s', self._log_list)

    def get_pois(self):
        self.session = self.slacrs.session()
        return self.session.query(Poi).all()

    def deactivate(self):
        self._active = False

    def _commit_pois(self):
        l.debug("database: %s", Conf.checrs_backend_str)
        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())
        while self._active:
            if self.slacrs is None:
                self.slacrs = Slacrs(database=Conf.checrs_backend_str)
            self.session = self.slacrs.session()
            with self.session.no_autoflush:
                while len(self._log_list) > 0:
                    poi = self._log_list.pop()
                    # query first to see if the poi id already exist
                    result = self.session.query(Poi).filter(Poi.id == poi.id).first()
                    if result is None:
                        self.session.add(poi)
                    else:
                        result.poi = poi.poi
                self.session.commit()
            self.session.close()
            sleep(3)
