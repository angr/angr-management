from angrmanagement.config import Conf

from ..base_plugin import BasePlugin

try:
    from slacrs import Slacrs
    from slacrs.model import VariableRename, FunctionRename, ReverseEngineeringProgress
except ImportError as ex:
    Slacrs = None  # type: Optional[type]
    VariableRename = None  # type: Optional[type]
    FunctionRename = None  # type: Optional[type]
    ReverseEngineeringProgress = None  # type: Optional[type]


class LogReverseEngineeringPlugin(BasePlugin):
    """
    Plugin for logging the reverse engineering of a program
    """

    def __init__(self, workspace):
        if not Slacrs:
            raise Exception(
                "Please install Slacrs to Initialize LogReverseEngineering Plugin"
            )
        super().__init__(workspace)
        self.session = Slacrs(database=Conf.checrs_backend_str).session()
        self.project = (
            self.workspace.instance.img_name
            if self.workspace.instance.img_name
            else self.workspace.instance.project.filename
        )

    def handle_stack_var_renamed(self, func, offset, old_name, new_name):
        """
        Logic to check if the same variable has already been renamed, if not add to the current session.
        """
        if offset:
            new_name = old_name
        variable_rename = (
            self.session.query(VariableRename)
                .filter(
                VariableRename.project == self.project,
                VariableRename.function == func._name,
                VariableRename.variable == old_name,
                )
                .first()
        )
        if variable_rename:
            self.session.delete(variable_rename)
        variable_rename = VariableRename()
        variable_rename.project = self.project
        variable_rename.function = func._name
        variable_rename.variable = new_name
        self.session.add(variable_rename)

    def handle_function_renamed(self, func, old_name: str, new_name: str):
        """
        Logic to check if the same Function has already been renamed, if not add to the current session.
        """
        function_rename = (
            self.session.query(FunctionRename)
            .filter(
                FunctionRename.project == self.project,
                FunctionRename.function == old_name,
            )
            .first()
        )
        if old_name.startswith("sub") or function_rename:
            if function_rename:
                self.session.delete(function_rename)
            function_rename = FunctionRename()
            function_rename.project = self.project
            function_rename.function = new_name
            self.update_function_name(old_name, new_name)
            self.session.add(function_rename)

    def handle_project_save(self, file_name: str):
        """
        Commit the current session only when user saves the project, uncommitted session objects will be discarded
        at teardown.
        """
        variables_renamed_count = len(
            self.session.query(VariableRename)
            .filter(VariableRename.project == self.project)
            .all()
        )
        total_variables_count = len(
            self.workspace.instance.project.kb.variables.global_manager._variables
        )
        reverse_eng_progress = (
            self.session.query(ReverseEngineeringProgress)
            .filter(ReverseEngineeringProgress.project == self.project)
            .first()
        )
        if not reverse_eng_progress:
            reverse_eng_progress = ReverseEngineeringProgress()
            self.session.add(reverse_eng_progress)
        reverse_eng_progress.project = self.project
        reverse_eng_progress.variables_renamed = variables_renamed_count
        reverse_eng_progress.total_variables = total_variables_count
        (
            reverse_eng_progress.functions_renamed,
            reverse_eng_progress.total_functions,
        ) = self.get_function_rename_stats()
        self.session.commit()

    def update_function_name(self, old_name, new_name):
        """
        To update the function names for all variable_rename if function gets renamed.
        """
        variables_renamed = self.session.query(VariableRename).filter(
            VariableRename.project == self.project, VariableRename.function == old_name
        )
        for obj in variables_renamed:
            obj.function = new_name

    def get_function_rename_stats(self):
        functions_renamed = [
            func.function
            for func in self.session.query(FunctionRename)
            .filter(FunctionRename.project == self.project)
            .all()
        ]

        functions_renamed_count = 0
        total_functions_count = 0

        for key in self.workspace.instance.project.kb.functions._function_map:
            if (
                self.workspace.instance.project.kb.functions._function_map[key]._name
                in functions_renamed
            ):
                functions_renamed_count = functions_renamed_count + 1
                total_functions_count = total_functions_count + 1
            elif self.workspace.instance.project.kb.functions._function_map[
                key
            ]._name.startswith("sub"):
                total_functions_count = total_functions_count + 1

        return [functions_renamed_count, total_functions_count]

    def teardown(self):
        self.session.close()
