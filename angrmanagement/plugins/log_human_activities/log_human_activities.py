import asyncio
import logging
import threading
import os
from time import sleep
from getmac import get_mac_address as gma
from tornado.platform.asyncio import AnyThreadEventLoopPolicy
from angrmanagement.config import Conf
import angrmanagement.ui.views as Views
from ..base_plugin import BasePlugin


l = logging.getLogger(__name__)
l.setLevel('INFO')


try:
    from slacrs import Slacrs
    from slacrs.model import HumanActivity, HumanActivityEnum
except ImportError as ex:
    Slacrs = None  # type: Optional[type]


class LogHumanActivitiesPlugin(BasePlugin):
    """
    Log human activities
    """
    def __init__(self, *args, **kwargs):
        if not Slacrs:
            raise Exception("Skipping LogHumanActivities Plugin. Please install Slacrs.")
        super().__init__(*args, **kwargs)
        self._init_logger()
        self.session = None
        self.project_name = None
        self.project_md5 = None
        self._log_list = list()
        self.user = gma()
        self.active = True
        self.slacrs_thread = None

    def _init_logger(self): # pylint:disable=no-self-use
        user_dir = os.path.expanduser('~')
        log_dir = os.path.join(user_dir, "am-logging")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, 'human_activities.log')
        fh = logging.FileHandler(log_file)
        fh.setLevel('INFO')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        l.addHandler(fh)

    def on_workspace_initialized(self, workspace):
        self.slacrs_thread = threading.Thread(target=self._commit_logs)
        self.slacrs_thread.setDaemon(True)
        self.slacrs_thread.start()

    def handle_variable_rename(self, func, offset: int, old_name: str, new_name: str, type_: str, size: int):
        """
        Log a user's activity of variable renaming.
        """
        variable_rename = HumanActivity(
            project=self.project_name,
            project_md5=self.project_md5,
            category=HumanActivityEnum.VariableRename,
            function=func._name,
            old_name=old_name,
            new_name=new_name,
            created_by=self.user,
        )
        self._log_list.append(variable_rename)
        l.info("Add variable rename sesssion to slacrs")

    def handle_function_rename(self, func, old_name: str, new_name: str):
        """
        Log a user's activity of function renaming.
        """
        function_rename = HumanActivity(
            project=self.project_name,
            project_md5=self.project_md5,
            category=HumanActivityEnum.FunctionRename,
            addr=func.addr,
            old_name=old_name,
            new_name=new_name,
            created_by=self.user,
        )
        self._log_list.append(function_rename)
        l.info("Add function rename sesssion to slacrs, project name %s, old_name %s, new_name %s",
                self.project_name, old_name, new_name)

    def handle_click_block(self, qblock, event):
        block_click = HumanActivity(
            project=self.project_name,
            project_md5=self.project_md5,
            category=HumanActivityEnum.ClickBlock,
            addr=qblock.addr,
            created_by=self.user,
        )
        self._log_list.append(block_click)
        l.info("Block %x is clicked", qblock.addr)
        return False

    def handle_click_insn(self, qinsn, event):
        insn_click = HumanActivity(
            project=self.project_name,
            project_md5=self.project_md5,
            category=HumanActivityEnum.ClickInsn,
            addr=qinsn.addr,
            created_by=self.user,
        )
        self._log_list.append(insn_click)
        l.info("Instruction %x is clicked", qinsn.addr)
        return False

    def handle_raise_view(self, view):
        view_name = view.__class__.__name__
        func = self._get_function_from_view(view)
        if func is not None and not func.am_none:
            func_name = func._name
            addr = func.addr
        else:
            func_name = None
            addr = None
        raise_view = HumanActivity(
            project=self.project_name,
            project_md5=self.project_md5,
            category=HumanActivityEnum.RaiseView,
            view=view_name,
            created_by=self.user,
            function=func_name,
            addr=addr
        )
        self._log_list.append(raise_view)
        l.info("View %s is raised with function %s", view_name, func_name)

    def handle_comment_changed(self, addr: int, cmt: str, new: bool, decomp: bool):
        """
        Log a user's activity of changing comment
        @param new: T if a new comment. We don't log it in slacrs.
        @param comp: T if comment is in decompiler view
        """
        comment_change = HumanActivity(
            project=self.project_name,
            project_md5=self.project_md5,
            category=HumanActivityEnum.CommentChanged,
            addr=addr,
            cmt=cmt,
            decomp=decomp,
            created_by=self.user,
        )
        self._log_list.append(comment_change)
        l.info("Comment is added at %x", addr)
        return False

    def handle_project_initialization(self):
        """
        Set project name
        """
        if self.workspace.instance.img_name is not None:
            self.project_name = self.workspace.instance.img_name
        else:
            filename = self.workspace.instance.project.filename
            self.project_name = filename
            self.project_md5 = self.workspace.instance.project.loader.main_object.md5.hex()
            l.info("Set project md5 to %s", self.project_md5)
        l.info("Set project name to %s", self.project_name)

    @staticmethod
    def _get_function_from_view(view):
        if isinstance(view, Views.DisassemblyView):
            return view._current_function
        if isinstance(view, (Views.CodeView, Views.ProximityView)):
            return view.function
        return None

    def _commit_logs(self):
        l.info("database: %s", Conf.checrs_backend_str)
        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())
        while self.active:
            try:
                sleep(3)
                connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
                if connector is None:
                    # chess connector does not exist
                    return None
                slacrs_instance = connector.slacrs_instance()
                if slacrs_instance is None:
                    # slacrs does not exist. continue
                    continue
                self.session = slacrs_instance.session()
                with self.session.no_autoflush:
                    while len(self._log_list) > 0:
                        log = self._log_list.pop()
                        self.session.add(log)
                    self.session.commit()
                self.session.close()
            except Exception:  # pylint:disable=broad-except
                pass

    def teardown(self):
        self.active = False
