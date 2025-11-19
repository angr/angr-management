from __future__ import annotations

import multiprocessing
import platform
import textwrap
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from angrmanagement.data.instance import Instance


def extract_first_paragraph_from_docstring(desc: str) -> str:
    desc = textwrap.dedent(desc).strip()  # Remove docstring indent
    desc = desc[0 : desc.find("\n\n")]  # First paragraph
    desc = desc.replace("\n", " ")  # Unwrap
    return desc


class AnalysesConfiguration:
    """
    Configuration for a sequence of analyses.
    """

    def __init__(self, analyses: Sequence[AnalysisConfiguration], instance: Instance) -> None:
        self.instance = instance
        self.analyses: Sequence[AnalysisConfiguration] = analyses

    def __len__(self) -> int:
        return len(self.analyses)

    def __iter__(self):
        return iter(self.analyses)

    def __getitem__(self, key: int | str):
        if isinstance(key, int):
            return self.analyses[key]
        return self.by_name(key)

    def by_name(self, name: str) -> AnalysisConfiguration:
        for a in self.analyses:
            if a.name == name:
                return a
        raise KeyError(name)


class AnalysisConfiguration:
    """
    Configuration for an analysis.
    """

    def __init__(self, instance: Instance) -> None:
        self.instance = instance
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

    def update_dict(self, out: dict[str, Any]) -> None:
        """
        Update dictionary `out` with configuration for this option.
        """
        for o in self.options.values():
            if getattr(o, "enabled", None) is False:
                continue
            o.update_dict(out)

    def get_main_obj_size(self) -> int:
        main_obj_size = 0
        if self.instance.project.loader.main_object is not None:
            main_obj = self.instance.project.loader.main_object
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


class AnalysisOption:
    """
    Configurable option for an analysis.
    """

    def __init__(self, name: str, display_name: str, tooltip: str) -> None:
        self.name: str = name
        self.display_name: str = display_name
        self.tooltip: str = tooltip

    def update_dict(self, out: dict[str, Any]) -> None:
        """
        Update dictionary `out` with configuration for this option.
        """


class PrimitiveAnalysisOption(AnalysisOption):
    """
    Configurable option for an analysis, with a fundamental type (e.g. bool)
    """

    def __init__(self, name: str, description: str, default: Any, tooltip: str) -> None:
        super().__init__(name, description, tooltip)
        self.default: Any = default
        self.value: Any = default

    def update_dict(self, out: dict[str, Any]) -> None:
        """
        Update `out` dictionary with configuration for this option.
        """
        out[self.name] = self.value


class BoolAnalysisOption(PrimitiveAnalysisOption):
    """
    Boolean option for an analysis.
    """

    def __init__(self, name: str, description: str, default: bool = False, tooltip: str = "") -> None:
        super().__init__(name, description, default, tooltip)


class StringAnalysisOption(PrimitiveAnalysisOption):
    """
    String option for an analysis.
    """

    def __init__(self, name: str, description: str, default: str = "", tooltip: str = "") -> None:
        super().__init__(name, description, default, tooltip)

    @property
    def enabled(self):
        return bool(self.value)


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
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> None:
        super().__init__(name, description, default, tooltip)
        self.minimum_value = minimum
        self.maximum_value = maximum


class ChoiceAnalysisOption(PrimitiveAnalysisOption):
    """
    A multi-value choice.
    """

    def __init__(
        self, name: str, description: str, choices: Mapping[Any, str], default: Any, tooltip: str = ""
    ) -> None:
        super().__init__(name, description, default, tooltip)
        self.choices = choices


class VariableRecoveryConfiguration(AnalysisConfiguration):
    """
    Configuration for VariableRecovery analysis.
    """

    SMALL_BINARY_SIZE = 65536
    MEDIUM_BINARY_SIZE = 400000

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "varec"
        self.display_name = "Recover Variables on All Functions"
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
                BoolAnalysisOption(
                    "analyze_callsites",
                    "Analyze callsites of each function to improve prototype recovery",
                    False,
                ),
            ]
        }

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


class APIDeobfuscationConfiguration(AnalysisConfiguration):
    """
    Configuration for API deobfuscation.
    """

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "api_deobfuscation"
        self.display_name = "Deobfuscate API usage"
        self.description = "Search for 'obfuscated' API use and attempt to deobfuscate it."
        self.enabled = False


class StringDeobfuscationConfiguration(AnalysisConfiguration):
    """
    Configuration for String deobfuscation.
    """

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "string_deobfuscation"
        self.display_name = "Deobfuscate Strings"
        self.description = "Search for 'obfuscated' strings and attempt to deobfuscate them."
        self.enabled = False
