from ..base_plugin import BasePlugin
import logging

l = logging.getLogger(__name__)
l.setLevel('DEBUG')

try:
    from slacrs import Slacrs
    from slacrs.model import HumanActivityVariableRename, HumanActivityFunctionRename
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
        self.session = Slacrs().session()
        self.project_name = None

    def handle_variable_rename(self, func, offset: int, old_name: str, new_name: str):
        """
        Log a user's activity of variable renaming.
        """
        variable_rename = HumanActivityVariableRename(
            project=self.project_name,
            function=func._name,
            old_name=old_name,
            new_name=new_name,
            created_by=TODO)
        self.session.add(variable_rename)
        l.info("Add variable rename sesssion to slacrs")

    def handle_function_rename(self, func, old_name: str, new_name: str):
        """
        Log a user's activity of function renaming.
        """
        function_rename = HumanActivityFunctionRename(
            project=self.project_name,
            old_name=old_name,
            new_name=new_name,
            created_by=TODO)
        self.session.add(function_rename)
        l.info("Add function rename sesssion to slacrs")

    def handle_project_initialization(self):
        """
        Set project name
        """
        if self.workspace.instance.img_name is not None:
            self.project_name = self.workspace.instance.img_name
        else:
            self.project_name = self.workspace.instance.project.filename
        l.info("Set project name")

    def teardown(self):
        self.session.close()
