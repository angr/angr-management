from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.data.analysis_options import AnalysisConfiguration, ChoiceAnalysisOption

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


SUPPORTED_LANGUAGES = {
    "c": "C",
    "go": "Go",
    "rust": "Rust",
    "swift": "Swift",
    "unknown": "Unknown",
}


def _detect_default_language(instance: Instance) -> str:
    if instance.project.am_none:
        return "unknown"
    try:
        languages = instance.project.languages()
    except Exception:
        return "unknown"
    if not languages:
        return "unknown"
    first = languages[0]
    return first if first in SUPPORTED_LANGUAGES else "unknown"


class OverviewConfiguration(AnalysisConfiguration):
    """
    Fake analysis configuration that surfaces overview/metadata about the binary
    (currently: the language detected by angr).
    """

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "overview"
        self.display_name = "Overview"
        self.description = (
            "Overview of binary properties detected by angr. Changing the language here can affect which "
            "language-specific analyses are enabled below."
        )
        self.enabled = True

        default_language = _detect_default_language(instance)
        self.options = {
            "languages": ChoiceAnalysisOption(
                "languages",
                "Languages",
                SUPPORTED_LANGUAGES,
                default_language,
                tooltip="The programming language angr detected for this binary. You may override it manually.",
            ),
        }
