import logging
from ..base_plugin import BasePlugin
from angrmanagement.config import Conf
import angrmanagement.ui.views as Views

l = logging.getLogger(__name__)
l.setLevel('INFO')

try:
    from slacrs import Slacrs
    from slacrs.model import HumanActivity, HumanActivityEnum
except ImportError as ex:
    Slacrs = None  # type: Optional[type]
    HumanActivityVariableRename = None  # type: Optional[type]
    HumanActivityFunctionRename = None  # type: Optional[type]


# TODO: add created_by field
TODO = "TODO"


class LogHumanActivitiesPlugin(BasePlugin):
    def __init__(self, *args, **kwargs):
        if not Slacrs:
            raise Exception("Skipping LogHumanActivities Plugin. Please install Slacrs to Initialize it.")
        super().__init__(*args, **kwargs)
        self.session = None
        self.project_name = None
        self.project_md5 = None
        self._commit_list = list()   # TODO: slacrs list

    def on_workspace_initialized(self, workspace):
        self.slacrs = Slacrs(database=Conf.checrs_backend_str)
        self.session = self.slacrs.session()
        print(self.session)

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
            created_by=TODO,
        )
        # self.slacrs.session().add(variable_rename)
        self.session.add(variable_rename)
        self.session.commit()
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
            created_by=TODO,
        )
        self.session.add(function_rename)
        self.session.commit()
        l.info("Add function rename sesssion to slacrs, project name %s, old_name %s, new_name %s", self.project_name, old_name, new_name)

    def handle_click_block(self, qblock, event):
        block_click = HumanActivity(
            project=self.project_name,
            project_md5=self.project_md5,
            category=HumanActivityEnum.ClickBlock,
            addr=qblock.addr,
            created_by=TODO,
        )
        self.session.add(block_click)
        self.session.commit()
        l.info("Block %x is clicked", qblock.addr)
        return False

    def handle_click_insn(self, qinsn, event):
        insn_click = HumanActivity(
            project=self.project_name,
            project_md5=self.project_md5,
            category=HumanActivityEnum.ClickInsn,
            addr=qinsn.addr,
            created_by=TODO,
        )
        self._submit_to_slacrs(insn_click)
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
            created_by=TODO,
            function=func_name,
            addr=addr
        )
        self._submit_to_slacrs(raise_view)
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
            created_by=TODO,
        )
        self.session.add(comment_change)
        self.session.commit()
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

    def _submit_to_slacrs(self, activity_instance):
        self.session.add(activity_instance)
        self.session.commit()

    def _get_function_from_view(self, view):
        if isinstance(view, Views.DisassemblyView):
            return view._current_function
        elif isinstance(view, Views.CodeView):
            return view.function
        elif isinstance(view, Views.ProximityView):
            l.info("proximity view")
            return view.function
        else:
            return None

    def teardown(self):
        self.session.close()
