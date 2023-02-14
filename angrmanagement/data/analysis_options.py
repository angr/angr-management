import multiprocessing
import platform
from enum import Enum
from typing import TYPE_CHECKING, Any, Mapping, Optional, Sequence, Union

if TYPE_CHECKING:
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
        desc = " ".join(line[num_whitespace_chars:] for line in desc)
    else:
        desc = ""

    return desc


class AnalysesConfiguration:
    """
    Configuration for a sequence of analyses.
    """

    def __init__(self, analyses: Sequence["AnalysisConfiguration"], instance):
        self.instance = instance
        self.analyses: Sequence["AnalysisConfiguration"] = analyses

    def __len__(self):
        return len(self.analyses)

    def __iter__(self):
        return iter(self.analyses)

    def __getitem__(self, key: Union[int, str]):
        if isinstance(key, int):
            return self.analyses[key]
        return self.by_name(key)

    def by_name(self, name: str) -> "AnalysisConfiguration":
        for a in self.analyses:
            if a.name == name:
                return a
        raise KeyError(name)


class AnalysisConfiguration:
    """
    Configuration for an analysis.
    """

    def __init__(self, instance):
        self.instance = instance
        self.project: angr.Project = self.instance.project.am_obj
        self.enabled: bool = False
        self.name: str = ""
        self.display_name: str = ""
        self.description: str = "Description not available"
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

    def __init__(self, name: str, display_name: str, tooltip: str):
        self.name: str = name
        self.display_name: str = display_name
        self.tooltip: str = tooltip

    def update_dict(self, out: Mapping[str, Any]):
        """
        Update dictionary `out` with configuration for this option.
        """


class PrimitiveAnalysisOption(AnalysisOption):
    """
    Configurable option for an analysis, with a fundamental type (e.g. bool)
    """

    def __init__(self, name: str, description: str, default: Any, tooltip: str):
        super().__init__(name, description, tooltip)
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

    def __init__(self, name: str, description: str, default: bool = False, tooltip: str = ""):
        super().__init__(name, description, default, tooltip)


class IntAnalysisOption(PrimitiveAnalysisOption):
    """
    Integer option for an analysis.
    """

    def __init__(
        self,
        name: str,
        description: str,
        default: int = 0,
        tooltip: str = "",
        minimum: Optional[int] = None,
        maximum: Optional[int] = None,
    ):
        super().__init__(name, description, default, tooltip)
        self.minimum_value = minimum
        self.maximum_value = maximum


class ChoiceAnalysisOption(PrimitiveAnalysisOption):
    """
    A multi-value choice.
    """

    def __init__(self, name: str, description: str, choices: Mapping[Any, str], default: Any, tooltip: str = ""):
        super().__init__(name, description, default, tooltip)
        self.choices = choices


class CFGForceScanMode(Enum):
    """
    CFG scanning mode options.
    """

    Disabled = 0
    SmartScan = 1
    CompleteScan = 2


class CFGAnalysisConfiguration(AnalysisConfiguration):
    """
    Configuration for CFGFast analysis.
    """

    def __init__(self, instance):
        super().__init__(instance)
        self.name = "cfg"
        self.display_name = "Control-Flow Graph Recovery"
        self.description = extract_first_paragraph_from_docstring(self.project.analyses.CFGFast.__doc__)
        self.enabled = True
        self.options = {
            o.name: o
            for o in [
                BoolAnalysisOption("resolve_indirect_jumps", "Resolve indirect jumps", True),
                BoolAnalysisOption("data_references", "Collect cross-references and guess data types", True),
                BoolAnalysisOption("cross_references", "Perform deep analysis on cross-references (slow)"),
                BoolAnalysisOption("skip_unmapped_addrs", "Skip unmapped addresses", True),
                ChoiceAnalysisOption(
                    "scanning_mode",
                    "Scan to maximize identified code blocks",
                    {
                        CFGForceScanMode.Disabled: "Disabled",
                        CFGForceScanMode.SmartScan: "Smart Scan",
                        CFGForceScanMode.CompleteScan: "Complete Scan",
                    },
                    CFGForceScanMode.SmartScan,
                ),
            ]
        }


class FlirtAnalysisConfiguration(AnalysisConfiguration):
    """
    Configuration for Flirt analysis.
    """

    def __init__(self, instance):
        super().__init__(instance)
        self.name = "flirt"
        self.display_name = "Signature Matching"
        self.description = self.project.analyses.Flirt.__doc__.strip()
        self.enabled = True


class VariableRecoveryConfiguration(AnalysisConfiguration):
    """
    Configuration for VariableRecovery analysis.
    """

    SMALL_BINARY_SIZE = 65536
    MEDIUM_BINARY_SIZE = 400000

    def __init__(self, instance):
        super().__init__(instance)
        self.name = "varec"
        self.display_name = "Complete Variable Recovery"
        self.description = (
            "Perform a full-project variable recovery and calling-convention recovery analysis. "
            "Recommended for small- to medium-sized binaries. This analysis takes a long time to "
            "finish on large binaries. You can manually perform a variable recovery and "
            "calling-convention recovery analysis on an individual basis after loading the project."
        )
        self.enabled = self.get_main_obj_size() <= self.MEDIUM_BINARY_SIZE
        self.options = {
            o.name: o
            for o in [
                IntAnalysisOption(
                    "workers",
                    "Number of parallel workers",
                    tooltip="0 to disable parallel analysis. Default to the number of available cores "
                    "minus one in the local system. Automatically default to 0 for small binaries "
                    "on all platforms, and small- to medium-sized binaries on Windows and MacOS "
                    "(to avoid the cost of spawning new angr-management processes).",
                    default=self.get_default_workers(),
                    minimum=0,
                ),
                BoolAnalysisOption(
                    "skip_signature_matched_functions",
                    "Skip variable recovery for signature-matched functions",
                    True,
                ),
            ]
        }

    def get_main_obj_size(self) -> int:
        main_obj_size = 0
        if self.project.loader.main_object is not None:
            main_obj = self.project.loader.main_object
            if main_obj.segments:
                for seg in main_obj.segments:
                    if seg.is_executable:
                        main_obj_size += seg.memsize
            if main_obj_size == 0 and main_obj.sections:
                # fall back to sections
                for sec in main_obj.sections:
                    if sec.is_executable:
                        main_obj_size += sec.memsize
        return main_obj_size

    def get_default_workers(self) -> int:
        main_obj_size = self.get_main_obj_size()

        default_workers = max(multiprocessing.cpu_count() - 1, 1)
        if default_workers == 1:
            return 0

        if platform.system() in {"Windows", "Darwin"}:
            if main_obj_size <= self.MEDIUM_BINARY_SIZE:
                return 0
            return default_workers

        if main_obj_size <= self.SMALL_BINARY_SIZE:
            return 0
        return default_workers
