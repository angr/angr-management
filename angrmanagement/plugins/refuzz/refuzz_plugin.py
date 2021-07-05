from ..base_plugin import BasePlugin
from ...data.object_container import ObjectContainer

from PySide2.QtCore import Qt, QAbstractTableModel
from PySide2.QtGui import QColor
from PySide2.QtWidgets import (
    QApplication,
    QInputDialog,
    QMessageBox,
    QVBoxLayout,
    QGridLayout,
    QAbstractItemView,
    QPushButton,
    QHeaderView,
    QLineEdit,
    QLabel,
)
from angrmanagement.ui.views import BaseView
from angrmanagement.ui.widgets.qfunction_combobox import QFunctionComboBox
from angr.analyses.decompiler.decompilation_options import (
    DecompilationOption,
    options as dec_options,
)
from angr.analyses.decompiler.optimization_passes import (
    get_default_optimization_passes,
    get_optimization_passes,
)
from angr.analyses.decompiler.peephole_optimizations import EXPR_OPTS, STMT_OPTS
from .hqfunction_table import *
import json
import requests
import base64
import asyncio
import time
from pathlib import Path


class ReFuzzView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        if "plugin" not in kwargs:
            return
        else:
            self.plugin = kwargs["plugin"]
            del kwargs["plugin"]

        super().__init__("refuzz", workspace, default_docking_position, *args, **kwargs)

        self.caption = "ReFuzz"
        self.category = "Patching"

        self._init_widgets()

    def _init_widgets(self):
        layout = QVBoxLayout()
        self.get_suggestions_button = QPushButton("Get Reinterface Suggestions")
        self.get_suggestions_button.clicked.connect(self.plugin.get_patch_suggestions)
        self.patch_function_button = QPushButton("Reinterface Selected Function")
        self.patch_function_button.clicked.connect(self.plugin.patch_function)
        self.patch_function_button.setEnabled(False)
        self.refresh_button = QPushButton("Refresh Listing")
        self.refresh_button.clicked.connect(self.refresh_listing)

        self.patch_server_url_label = QLabel()
        self.patch_server_url_label.setText("Patch Server URL:")
        self.patch_server_url_entry = QLineEdit()
        self.patch_server_url_entry.setText(RefuzzPlugin.DEFAULT_SERVER)
        self.patch_server_url_entry.textChanged.connect(self.set_patch_server_url_info)
        self.set_patch_server_url_info(RefuzzPlugin.DEFAULT_SERVER)

        self.server_url_label = QLabel()
        self.server_url_label.setText("Analysis Server URL:")
        self.server_url_entry = QLineEdit()
        self.server_url_entry.setText(RefuzzPlugin.DEFAULT_SERVER)
        self.server_url_entry.textChanged.connect(self.set_server_url_info)
        self.set_server_url_info(RefuzzPlugin.DEFAULT_SERVER)

        # {"func_addr":"0x400827","buf_addr":"arg_sym_reg_rdx","buf_outlen_addr":"arg_sym_reg_rcx;","buf_maxlen":"-1"}%
        self.buffer_addr_box = QLabel()
        self.buffer_outlen_addr_box = QLabel()
        self.buffer_maxlen_box = QLabel()

        self.server_status_label = QLabel()
        self.server_status_label.setText("Server Status:")
        self.server_status_label_value = QLabel()
        self.server_status_label_value.setText("")

        self.connect_to_server = QPushButton("Connect to Server")
        self.connect_to_server.clicked.connect(self.plugin.connect_to_server_event)
        self.stop_server = QPushButton("Stop Server")
        self.stop_server.clicked.connect(self.plugin.stop_server_event)

        self.patch_function_selector = QHFunctionTable(
            self,
            workspace=self.plugin.workspace,
            selection_callback=self.plugin.set_selected_function,
            plugin=self.plugin,
        )
        # self.patch_function_selector_view = QFunctionTableView(parent=self.patch_function_selector, workspace=self.plugin.workspace, selection_callback=self.plugin.set_selected_function)
        g1_layout = QGridLayout()
        g1_layout.addWidget(self.server_url_label, 0, 0, 1, 1)
        g1_layout.addWidget(self.server_url_entry, 0, 1, 1, 1)
        g1_layout.addWidget(self.patch_server_url_label, 1, 0, 1, 1)
        g1_layout.addWidget(self.patch_server_url_entry, 1, 1, 1, 1)
        layout.addLayout(g1_layout)

        g2_layout = QGridLayout()
        g2_layout.addWidget(self.connect_to_server, 0, 0, 1, 1)
        g2_layout.addWidget(self.stop_server, 0, 1, 1, 1)
        layout.addLayout(g2_layout)

        g3_layout = QGridLayout()
        g3_layout.addWidget(self.get_suggestions_button, 0, 0, 1, 1)
        g3_layout.addWidget(self.patch_function_button, 0, 1, 1, 1)
        layout.addLayout(g3_layout)

        layout.addWidget(self.refresh_button)
        g4_layout = QGridLayout()
        g4_layout.addWidget(self.server_status_label, 0, 0, 1, 1)
        g4_layout.addWidget(self.server_status_label_value, 0, 1, 1, 1)
        layout.addLayout(g4_layout)
        layout.addWidget(self.patch_function_selector)

        g5_layout = QGridLayout()
        g5_layout.addWidget(self.buffer_addr_box, 0, 0, 1, 1)
        g5_layout.addWidget(self.buffer_outlen_addr_box, 0, 1, 1, 1)
        g5_layout.addWidget(self.buffer_maxlen_box, 0, 2, 1, 1)
        layout.addLayout(g5_layout)

        self.setLayout(layout)

    def set_function_count(self, i):
        pass

    def set_displayed_function_count(self, i):
        pass

    def set_server_url_info(self, text):
        self.plugin.set_server_url(text)

    def set_patch_server_url_info(self, text):
        self.plugin.set_patch_server_url(text)

    def refresh_listing(self):
        if self.patch_function_selector:
            if self.plugin.workspace.instance.cfg is not None:
                self.patch_function_selector.function_manager = (
                    self.plugin.workspace.instance.kb.functions
                )
                # self._function_table.refresh()
        self.buffer_addr_box.setText(self.plugin.buffer_addr)
        self.buffer_maxlen_box.setText(self.plugin.buffer_maxlen)
        self.buffer_outlen_addr_box.setText(self.plugin.buffer_outlen)
        self.patch_function_button.setEnabled(False)


class RefuzzPlugin(BasePlugin):
    REQUIRE_WORKSPACE = True
    DEFAULT_SERVER = "http://44.234.64.65:12321"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.workspace.instance.register_container(
            "refuzz", lambda: None, None, "Refuzz Control Panel"
        )
        self.view = ReFuzzView(
            plugin=self, workspace=self.workspace, default_docking_position="center"
        )
        self.workspace.add_view(self.view, self.view.caption, self.view.category)
        self.handlers = {0: self.get_patch_suggestions, 1: self.patch_function, 2: self.connect_to_server_event, 3: self.stop_server_event, 4:self.set_selected_function}
        self.suggested = []
        self.session = requests.Session()
        self.server_url = self.DEFAULT_SERVER
        self.patch_server_url = self.DEFAULT_SERVER
        self.state = None
        self.set_state("init")
        self.selected_function = None
        self.buffer_addr = ""
        self.buffer_maxlen = ""
        self.buffer_outlen = ""

    def set_state(self, nstate):
        if nstate == "init":
            self.view.get_suggestions_button.setEnabled(False)
            #self.view.patch_function_button.setEnabled(False)
            self.view.connect_to_server.setEnabled(True)
            self.view.stop_server.setEnabled(False)
        elif nstate == "connected":
            self.view.get_suggestions_button.setEnabled(True)
            #self.view.patch_function_button.setEnabled(True)
            self.view.connect_to_server.setEnabled(False)
            self.view.stop_server.setEnabled(True)
        elif nstate == "checking":
            self.view.get_suggestions_button.setEnabled(False)
            #self.view.patch_function_button.setEnabled(True)
            self.view.connect_to_server.setEnabled(False)
            self.view.stop_server.setEnabled(True)

        self.state = nstate    

    def set_patch_server_url(self, url):
        self.patch_server_url = url

    def set_server_url(self, url):
        self.server_url = url

    def handle_click_menu(self, idx):
        if idx < 0 or idx > len(self.buttons):
            return

        if self.workspace.instance.project is None:
            return

        self.handlers[idx]()

    def connect_to_server_event(self):
        self.set_state("connected")
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, self.server_status_thread)

    def stop_server_event(self):
        res = self.session.get(f"{self.server_url}/stop")
        self.set_state("init")

    def server_status_thread(self):
        while True:
            res = self.session.get(f"{self.server_url}/status")
            if res != None:
                self.view.server_status_label_value.setText(res.text)
            else:
                self.view.server_status_label_value.setText("None")
            time.sleep(2)
            if self.state == "init":
                self.view.server_status_label_value.setText("")
                break

    def get_patch_suggestions(self):
        query_functions = {}
        if self.workspace.instance.kb is None:
            print("Err: Must load a binary.")
            return

        if self.server_url == "":
            print("Err: Must specify url")
            return

        if self.state == "init":
            print("Err: Connect to the server first.")

        if self.state == "checking":
            print("Err: Already waiting for a result. Wait for the server to finish or press Stop Server.")

        opts = list(map(lambda o: (o, True), dec_options))
        peephole_opts = STMT_OPTS + EXPR_OPTS
        passes = get_optimization_passes(
            self.workspace.instance.project.arch,
            self.workspace.instance.project.simos.name,
        )
        print(opts)
        for addr in self.workspace.instance.kb.functions:
            func = self.workspace.instance.kb.functions[addr]
            """
            if (
                func.prototype is not None
                and not func.is_syscall
                and not func.is_simprocedure
            ):
            """
            """
            try:
                d = self.workspace.instance.project.analyses.Decompiler(
                    func,
                    cfg=self.workspace.instance.cfg,
                    options=opts,
                    optimization_passes=passes,
                    peephole_optimizations=peephole_opts,
                )
                code = d.codegen.text
                proto = code[0 : code.find("{")].rstrip()
                print(proto)
                print(f"Decompiled function at {hex(func.addr)}")

                query_functions[hex(func.addr)] = proto
            except Exception as e:
                print(f"Could not decompile function at {hex(func.addr)}: {e}")
            """

        with open(self.workspace.instance.project.filename, "rb") as binfile:
            contents = binfile.read()
            status = self.session.get(f"{self.server_url}/status")
            # js_status = json.loads(status.text)
            self.session.get(f"{self.server_url}/stop")

            res = self.session.get(
                f"{self.server_url}/start?{Path(self.workspace.instance.project.filename).name}"
            )

            """
            res = self.session.post(
                f"{self.server_url}/start?{Path(self.workspace.instance.project.filename).name}",
                json={
                    "functions": query_functions,
                    "binary": base64.b64encode(contents).decode("UTF-8"),
                },
            )
            """
            self.set_state("checking")
            self.start_checker()

    def start_checker(self):
        self.set_state("checking")
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, self.checker_thread)

    def checker_thread(self):
        import traceback
        # the issue is that exceptions happening here are silently discared
        try:
            time.sleep(5)
            #print("checker started")
            while True:
                if(self.state != "checking"):
                    return
                res = self.session.get(f"{self.server_url}/status")
                #print("checker looping")
                if res is not None:
                    js_res = json.loads(res.text)
                    if js_res["status"] == "finished":
                        req = f"{self.server_url}/result?{Path(self.workspace.instance.project.filename).name}"
                        print(f"Requesting {req}:")
                        fres = self.session.get(req)
                        print(fres.text)
                        #js_fres = {"func_addr":"0x400827","buf_addr":"arg_sym_reg_rdx","buf_outlen_addr":"arg_sym_reg_rcx;","buf_maxlen":"-1"} #json.loads(fres.text)
                        js_fres = json.loads(fres.text)
                        self.last_result = js_fres
                        self.suggested = [int(self.last_result["func_addr"], 16)]

                        # {"func_addr":"0x400827","buf_addr":"arg_sym_reg_rdx","buf_outlen_addr":"arg_sym_reg_rcx;","buf_maxlen":"-1"}%
                        self.buffer_addr = self.last_result["buf_addr"]
                        self.buffer_outlen = self.last_result["buf_outlen_addr"]
                        self.buffer_maxlen = self.last_result["buf_maxlen"]
                        #self.view.refresh_listing()
                        self.set_state("connected")
                        return

                    #self.view.server_status_label_value.setText(res.text)
                time.sleep(10)
        except:
            traceback.print_exc()

    def patch_function(self):
        f = {"bin": open(self.workspace.instance.project.filename, "rb")}
        res = self.session.post(f"{self.patch_server_url}/analyze/", files=f)
        res2 = self.session.get(
            f"{self.patch_server_url}/run/?addr={int(self.selected_function, 16) - 0x400000}"
        )
        if res2 is not None:
            js_res2 = json.loads(res2.text)
            file_content = js_res2["file"]
            real_content = base64.b64decode(file_content)
            with open(
                f"{self.workspace.instance.project.filename}-patched", "wb"
            ) as patchfile:
                patchfile.write(real_content)

    def set_selected_function(self, func):
        self.view.patch_function_button.setEnabled(True)
        self.selected_function = hex(func.addr)
