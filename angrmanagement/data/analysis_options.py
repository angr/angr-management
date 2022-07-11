from typing import Mapping, Any, Sequence, Union

import angr


def extract_first_paragraph_from_docstring(desc: str) -> str:
    desc = desc.splitlines()
    last_line, first_line = -1, -1
    for idx, line in enumerate(desc):
        if first_line < 0:
            if len(line.strip()) > 0:
                first_line = idx
        else:
            if len(line.strip()) == 0:
                last_line = idx
                break

    if first_line >= 0:
        if last_line < 0:
            last_line = len(desc)
        desc = desc[first_line:last_line]
        num_whitespace_chars = len(desc[0]) - len(desc[0].lstrip())
        desc = ' '.join(l[num_whitespace_chars:] for l in desc)
    else:
        desc = ''

    return desc


class AnalysesConfiguration:
    """
    Configuration for a sequence of analyses.
    """

    def __init__(self, analyses: Sequence['AnalysisConfiguration'], workspace: 'Workspace'):
        self.workspace: 'Workspace' = workspace
        self.analyses: Sequence['AnalysisConfiguration'] = analyses

    def __len__(self):
        return len(self.analyses)

    def __iter__(self):
        return iter(self.analyses)

    def __getitem__(self, key: Union[int, str]):
        if isinstance(key, int):
            return self.analyses[key]
        return self.by_name(key)

    def by_name(self, name: str) -> 'AnalysisConfiguration':
        for a in self.analyses:
            if a.name == name:
                return a
        raise KeyError(name)


class AnalysisConfiguration:
    """
    Configuration for an analysis.
    """

    def __init__(self, workspace: 'Workspace'):
        self.workspace: 'Workspace' = workspace
        self.project: angr.Project = workspace.instance.project.am_obj
        self.enabled: bool = False
        self.name: str = ''
        self.display_name: str = ''
        self.description: str = 'Description not available'
        self.options: Mapping[str, AnalysisOption] = {}

    def __getitem__(self, key: str):
        return self.options[key]

    def to_dict(self):
        """
        Return dictionary with configuration for this option.
        """
        o = {}
        self.update_dict(o)
        return o

    def update_dict(self, out: Mapping[str, Any]):
        """
        Update dictionary `out` with configuration for this option.
        """
        for o in self.options.values():
            o.update_dict(out)


class AnalysisOption:
    """
    Configurable option for an analysis.
    """

    def __init__(self, name: str, display_name: str):
        self.name: str = name
        self.display_name: str = display_name

    def update_dict(self, out: Mapping[str, Any]):
        """
        Update dictionary `out` with configuration for this option.
        """


class PrimitiveAnalysisOption(AnalysisOption):
    """
    Configurable option for an analysis, with a fundamental type (e.g. bool)
    """

    def __init__(self, name: str, description: str, default: Any):
        super().__init__(name, description)
        self.default: Any = default
        self.value: Any = default

    def update_dict(self, out: Mapping[str, Any]):
        """
        Update `out` dictionary with configuration for this option.
        """
        out[self.name] = self.value


class BoolAnalysisOption(PrimitiveAnalysisOption):
    """
    Boolean option for an analysis.
    """

    def __init__(self, name: str, description: str, default: bool = False):
        super().__init__(name, description, default)


class CFGAnalysisConfiguration(AnalysisConfiguration):
    """
    Configuration for CFGFast analysis.
    """

    def __init__(self, workspace: 'Workspace'):
        super().__init__(workspace)
        self.name = 'cfg'
        self.display_name = 'Control-Flow Graph Recovery'
        self.description = extract_first_paragraph_from_docstring(self.project.analyses.CFGFast.__doc__)
        self.enabled = True
        self.options = {o.name: o for o in [
            BoolAnalysisOption('resolve_indirect_jumps', 'Resolve indirect jumps', True),
            BoolAnalysisOption('data_references', 'Collect cross-references and guess data types', True),
            BoolAnalysisOption('cross_references', 'Perform deep analysis on cross-references (slow)'),
            BoolAnalysisOption('skip_unmapped_addrs', 'Skip unmapped addresses', True),
            ]}


class FlirtAnalysisConfiguration(AnalysisConfiguration):
    """
    Configuration for Flirt analysis.
    """

    def __init__(self, workspace: 'Workspace'):
        super().__init__(workspace)
        self.name = 'flirt'
        self.display_name = 'Signature Matching'
        self.description = self.project.analyses.Flirt.__doc__.strip()
        self.enabled = True


class VariableRecoveryConfiguration(AnalysisConfiguration):
    """
    Configuration for VariableRecovery analysis.
    """

    def __init__(self, workspace: 'Workspace'):
        super().__init__(workspace)
        self.name = 'varec'
        self.display_name = 'Variable Recovery'
        self.description = extract_first_paragraph_from_docstring(self.project.analyses.VariableRecovery.__doc__)
        self.enabled = True
        self.options = {o.name: o for o in [
            BoolAnalysisOption('skip_signature_matched_functions', 'Skip variable recovery for signature-matched '
                                                                   'functions', True),
            ]}
