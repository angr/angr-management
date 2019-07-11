import logging
import os

import slacrs

from ..base_plugin import BasePlugin


_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)


class SlacrsPlugin(BasePlugin):
    DISPLAY_NAME = 'Slacrs Plugin'
    is_autostart = True
    is_autoenabled = False

    def __init__(self, plugin_manager, workspace):
        super().__init__(plugin_manager, workspace)

        slacrs_host = os.getenv('SLACRS_HOST')
        if not slacrs_host:
            raise Exception("must set environment variable `SLACRS_HOST`")

        workspace.instance.slacrs = self
        self.client = slacrs.RemoteClient(host=slacrs_host)

    def run(self):
        self.client.wait()

    def publish(self, event):
        self.client.add_state(stype='angr-management', new_state=event)

    def subscribe(self, name, selector, callback):
        self.add_simple_selector(name, selector)
        self.add_callback(name, callback)
