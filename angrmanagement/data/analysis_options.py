from __future__ import annotations

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

    def __init__(self, analyses: Sequence[AnalysisConfiguration]) -> None:
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
