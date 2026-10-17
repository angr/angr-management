"""
The Run Analysis dialog without a toolkit: the option sheet of an analysis, and what changing the binary's language
does to the analyses that depend on it.

The Qt AnalysisOptionsDialog and the terminal's analysis options screen both show the analyses with a check box each,
the selected one's description, and its options as rows of :class:`OptionRow`. Picking a language in the overview's
options asks whether to turn the analyses for that language on, and those for other languages off.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from angrmanagement.data.analysis_options import (
    BoolAnalysisOption,
    ChoiceAnalysisOption,
    IntAnalysisOption,
    StringAnalysisOption,
)

if TYPE_CHECKING:
    from angrmanagement.data.analysis_options import AnalysesConfiguration, AnalysisConfiguration, AnalysisOption

#: language -> (display name, analyses enabled by default only for binaries of that language)
LANGUAGE_DEPENDENT_ANALYSES: dict[str, tuple[str, tuple[str, ...]]] = {
    "rust": ("Rust", ("rust_symbol_recovery", "rust_typedb_loader")),
    "go": ("Go", ("go_globals_recovery",)),
}
RUST_DEPENDENT_ANALYSES = LANGUAGE_DEPENDENT_ANALYSES["rust"][1]

#: the overview analysis's option that names the binary's language
LANGUAGE_ANALYSIS = "overview"
LANGUAGE_OPTION = "languages"


@dataclass
class OptionRow:
    """
    One option as the option sheet shows it: kind ``bool``, ``int``, ``choice`` or ``text``, its label, value, help,
    the (value, caption) choices of a choice, and the bounds of a number.
    """

    option: AnalysisOption
    kind: str
    label: str
    value: Any
    description: str = ""
    choices: tuple[tuple[Any, str], ...] = ()
    minimum: int = -(2**31)
    maximum: int = 2**31 - 1


def option_row(option: AnalysisOption) -> OptionRow:
    """The row of ``option``; raises ValueError for an option of a kind the sheet cannot show, as the Qt one does."""
    if isinstance(option, BoolAnalysisOption):
        return OptionRow(option, "bool", option.display_name, option.value, option.tooltip)
    if isinstance(option, IntAnalysisOption):
        return OptionRow(
            option,
            "int",
            option.display_name,
            option.value,
            option.tooltip,
            minimum=option.minimum_value if option.minimum_value is not None else -(2**31),
            maximum=option.maximum_value if option.maximum_value is not None else 2**31 - 1,
        )
    if isinstance(option, ChoiceAnalysisOption):
        return OptionRow(
            option, "choice", option.display_name, option.value, option.tooltip, tuple(option.choices.items())
        )
    if isinstance(option, StringAnalysisOption):
        return OptionRow(option, "text", option.display_name, option.value, option.tooltip)
    raise ValueError("Mapper not implemented")


def option_rows(analysis: AnalysisConfiguration) -> list[OptionRow]:
    return [option_row(option) for option in analysis.options.values()]


def is_language_option(analysis: AnalysisConfiguration, option: AnalysisOption) -> bool:
    """Whether setting ``option`` picks the binary's language."""
    return analysis.name == LANGUAGE_ANALYSIS and option.name == LANGUAGE_OPTION


@dataclass
class LanguagePrompt:
    """A question the dialog asks after the language changes: turn ``targets`` on (or off)?"""

    want_enabled: bool
    lang_name: str
    targets: list[AnalysisConfiguration]

    @property
    def title(self) -> str:
        action_word = "enable" if self.want_enabled else "disable"
        return f"{action_word.capitalize()} {self.lang_name}-specific analyses?"

    @property
    def text(self) -> str:
        action_word = "enable" if self.want_enabled else "disable"
        display_names = ", ".join(c.display_name for c in self.targets)
        return (
            f"The selected language is {self.lang_name if self.want_enabled else 'not ' + self.lang_name}. "
            f"Would you like to {action_word} the following {self.lang_name}-specific "
            f"{'analyses' if len(self.targets) > 1 else 'analysis'}?\n\n"
            f"{display_names}"
        )

    def apply(self) -> None:
        """The user said yes."""
        for config in self.targets:
            config.enabled = self.want_enabled


def set_language(analyses: AnalysesConfiguration, language: Any) -> list[LanguagePrompt]:
    """
    Record ``language`` as the project's, and return the questions to ask about the language-dependent analyses, in
    the order the dialog asks them; an analysis already as the language wants it is not asked about.
    """
    try:
        overview = analyses.by_name(LANGUAGE_ANALYSIS)
    except KeyError:
        overview = None
    if overview is not None and not overview.instance.project.am_none:
        overview.instance.project._languages = [language]  # pylint:disable=protected-access

    prompts = []
    for lang, (lang_name, names) in LANGUAGE_DEPENDENT_ANALYSES.items():
        want_enabled = language == lang
        targets = []
        for name in names:
            try:
                config = analyses.by_name(name)
            except KeyError:
                continue
            if config.enabled != want_enabled:
                targets.append(config)
        if targets:
            prompts.append(LanguagePrompt(want_enabled, lang_name, targets))
    return prompts


__all__ = [
    "LANGUAGE_DEPENDENT_ANALYSES",
    "RUST_DEPENDENT_ANALYSES",
    "LanguagePrompt",
    "OptionRow",
    "is_language_option",
    "option_row",
    "option_rows",
    "set_language",
]
