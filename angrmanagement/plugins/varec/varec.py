from typing import Set, Tuple
import re
import json
import itertools
import random
import string
from collections import defaultdict

import requests
from sortedcontainers import SortedDict

from PySide2.QtGui import Qt
from PySide2.QtWidgets import QMessageBox

from angrmanagement.config import Conf
from ..base_plugin import BasePlugin


class VaRec(BasePlugin):
    """
    The plugin for supporting the VaRec plugin (private for now until it is released to the public).
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.transitions: Set[Tuple[int,int]] = set()
        self.covered_blocks = SortedDict()

        self.sink_color = Qt.yellow

    MENU_BUTTONS = [
        '&Infer variable names',
    ]
    INFER_VARIABLE_NAMES = 0

    def handle_click_menu(self, idx):

        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        if self.workspace.instance.project.am_none:
            return

        mapping = {
            VaRec.INFER_VARIABLE_NAMES: self.infer_variable_names,
        }

        mapping.get(idx)()

    @staticmethod
    def _restore_stage(view):
        # shrug
        for v in view.codegen._variable_kb.variables[view.function.addr]._unified_variables:
            m = re.match(r"@@(\S+)@@(\S+)@@", v.name)
            if m is not None:
                var_name = m.group(1)
                v.name = var_name
        # refresh the view
        view.codegen.regenerate_text()
        view.codegen.am_event()

    @staticmethod
    def randstr(n=8):
        return "".join(random.choice(string.ascii_lowercase) for _ in range(n))

    def infer_variable_names(self):
        view = self.workspace._get_or_create_pseudocode_view()
        if view.codegen.am_none:
            QMessageBox.critical(self.workspace._main_window,
                                 "Error in variable name prediction",
                                 "Cannot predict variable names. No pseudocode exists in the pseudocode view.",
                                 QMessageBox.Ok
                                 )
            return
        if view.codegen._variable_kb is None:
            QMessageBox.critical(self.workspace._main_window,
                                 "Error in variable name prediction",
                                 "Cannot predict variable names. The pseudocode view does not have associated "
                                 "variables KB.",
                                 QMessageBox.Ok
                                 )
            return

        if Conf.http_proxy or Conf.https_proxy:
            proxies = {
                "http": Conf.http_proxy,
                "https": Conf.https_proxy,
            }
        else:
            proxies = None

        for v in view.codegen._variable_kb.variables[view.function.addr]._unified_variables:
            if not v.renamed:
                v.name = "@@%s@@%s@@" % (v.name, VaRec.randstr())

        view.codegen.regenerate_text()
        d = {
            'code': [
                {
                    "raw_codes": [
                        view.codegen.text,
                    ]
                }
            ]
        }
        r = requests.post(f"{Conf.varec_endpoint}", data=json.dumps(d), proxies=proxies)
        try:
            result = json.loads(r.text)
        except json.JSONDecodeError:
            self._restore_stage(view)

            QMessageBox.critical(self.workspace._main_window,
                                 "Error in variable name prediction",
                                 "Failed to predict names for all variables involved.",
                                 QMessageBox.Ok
                                 )

            return

        varname_blacklist = {'UNK', 'null', "true", "false", }
        varname_to_predicted = defaultdict(list)

        # handle failure cases
        if 'code' not in result or not result['code']:
            self._restore_stage(view)
            QMessageBox.critical(self.workspace._main_window,
                                 "Error in variable name prediction",
                                 "Unexpected output returned from the backend. 'code' is not found or empty.",
                                 QMessageBox.Ok
                                 )
            return
        if 'predictions' not in result['code'][0] or not result['code'][0]['predictions']:
            QMessageBox.critical(self.workspace._main_window,
                                 "Error in variable name prediction",
                                 "Unexpected output returned from the backend. 'predictions' is not found or empty.",
                                 QMessageBox.Ok
                                 )
            self._restore_stage(view)
            return
        if len(result['code'][0]['predictions']) == 1 and isinstance(result['code'][0]['predictions'][0], str):
            QMessageBox.critical(self.workspace._main_window,
                                 "Error in variable name prediction",
                                 f"Prediction failed. Error: {result['code'][0]['predictions'][0]}",
                                 QMessageBox.Ok
                                 )
            self._restore_stage(view)
            return

        for idx, m in enumerate(re.finditer(r"@@(\S+)@@(\S+)@@", view.codegen.text)):
            var_name = m.group(1)
            prediction = result['code'][0]['predictions'][0][idx]
            topk = prediction['top-k']
            # remove variable names that we don't like
            filtered_topk = [item for item in topk if item['pred_name'] not in varname_blacklist]
            if filtered_topk:
                varname_to_predicted[var_name].extend(filtered_topk)

        ctrs = defaultdict(itertools.count)

        # rename them all
        used_names = set()
        for v in view.codegen._variable_kb.variables[view.function.addr]._unified_variables:
            m = re.match(r"@@(\S+)@@\S+@@", v.name)
            if m is not None:
                var_name = m.group(1)
                predicted = varname_to_predicted[var_name]
                predicted = sorted(predicted, key=lambda x: x['confidence'], reverse=True)
                v.candidate_names = set(pred['pred_name'] for pred in predicted)
                for pred in predicted:
                    if pred['pred_name'] not in used_names:
                        v.name = pred['pred_name']
                        used_names.add(v.name)
                        break
                else:
                    if predicted:
                        v.name = predicted[0]['pred_name'] + "_" + str(next(ctrs[predicted[0]['pred_name']]))
                    else:
                        v.name = var_name  # restore the original name
        view.codegen.am_event()
