import logging
import hashlib
from ..base_plugin import BasePlugin

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
        self.project_md5 = None

    def handle_variable_rename(self, func, offset: int, old_name: str, new_name: str):
        """
        Log a user's activity of variable renaming.
        """
        variable_rename = HumanActivityVariableRename(
            project=self.project_name,
            project_md5=self.project_md5,
            function=func._name,
            old_name=old_name,
            new_name=new_name,
            created_by=TODO,
        )
        self.session.add(variable_rename)
        self.session.commit()
        l.info("Add variable rename sesssion to slacrs")

    def handle_function_rename(self, func, old_name: str, new_name: str):
        """
        Log a user's activity of function renaming.
        """
        function_rename = HumanActivityFunctionRename(
            project=self.project_name,
            project_md5=self.project_md5,
            old_name=old_name,
            new_name=new_name,
            created_by=TODO,
        )
        self.session.add(function_rename)
        self.session.commit()
        l.info("Add function rename sesssion to slacrs, project name %s, old_name %s, new_name %s", self.project_name, old_name, new_name)
        result = self.session.query(HumanActivityFunctionRename).filter(HumanActivityFunctionRename.project == self.project_name).first()
        l.info("Query result: old_name %s, new_name %s", result.old_name, result.new_name)

    def handle_project_initialization(self):
        """
        Set project name
        """
        if self.workspace.instance.img_name is not None:
            self.project_name = self.workspace.instance.img_name
        else:
            filename = self.workspace.instance.project.filename
            self.project_name = filename
            with open(filename, 'rb') as f:
                self.project_md5 = hashlib.md5(f.read()).hexdigest()
            l.info("Set project md5 to %s", self.project_md5)
        l.info("Set project name to %s", self.project_name)

    def teardown(self):
        self.session.close()
