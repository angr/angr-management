"""
The terminal's Run Analysis screen: the Qt AnalysisOptionsDialog's list of analyses with a check box each, the
highlighted one's description, and its option sheet.

The options change in place as they are edited, as the Qt property editor changes them. Picking the binary's language
in the overview's options asks, as the Qt dialog does, whether to turn the analyses for that language on and those for
the others off. "Run Analysis" dismisses with True; Cancel and Escape with None.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select, SelectionList, Static

from angrmanagement.present.analysis_options import OptionRow, is_language_option, option_rows, set_language

from . import QuestionScreen, dialog_css

if TYPE_CHECKING:
    from textual.app import ComposeResult
    from textual.widget import Widget

    from angrmanagement.data.analysis_options import AnalysesConfiguration, AnalysisConfiguration
    from angrmanagement.present.analysis_options import LanguagePrompt


class AnalysisOptionsScreen(ModalScreen["bool | None"]):
    """Run Analysis: which analyses to run, and with what options."""

    DEFAULT_CSS = (
        dialog_css("AnalysisOptionsScreen")
        + """
AnalysisOptionsScreen > Vertical { width: 110; height: 80%; }
AnalysisOptionsScreen #panes { height: 1fr; }
AnalysisOptionsScreen #analyses { width: 40; height: 1fr; }
AnalysisOptionsScreen #details { width: 1fr; height: 1fr; padding: 0 0 0 1; }
AnalysisOptionsScreen #description { height: auto; max-height: 8; color: $text-muted; }
AnalysisOptionsScreen #options { height: 1fr; }
AnalysisOptionsScreen .option { height: auto; }
AnalysisOptionsScreen .option > Label { width: 32; padding: 0 1 0 0; }
AnalysisOptionsScreen .option > Input, AnalysisOptionsScreen .option > Select { width: 1fr; }
AnalysisOptionsScreen .group { text-style: bold; }
"""
    )
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, analyses: AnalysesConfiguration) -> None:
        super().__init__()
        self.title_text = "Run Analysis"
        self.analyses = analyses
        self.current: AnalysisConfiguration | None = None
        #: the row of each option editor shown
        self.rows: dict[Widget, OptionRow] = {}

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            with Horizontal(id="panes"):
                with Vertical(id="analyses-pane"):
                    yield Label("Available Analyses", classes="group")
                    yield SelectionList[str](
                        *((a.display_name or a.name, a.name, a.enabled) for a in self.analyses), id="analyses"
                    )
                with Vertical(id="details"):
                    yield Label("Analysis Description", classes="group")
                    yield Static("Select analysis to view options.", id="description")
                    yield Label("Options", classes="group")
                    yield VerticalScroll(id="options")
            with Horizontal(classes="buttons"):
                yield Button("Run Analysis", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        if not self.query("#analyses"):
            # the app tore the screen down while it mounted (it exits)
            return
        if len(self.analyses) > 0:
            self.show_analysis(self.analyses[0])
        with contextlib.suppress(Exception):
            self.query_one("#ok", Button).focus()

    #
    # The selected analysis
    #

    def show_analysis(self, analysis: AnalysisConfiguration) -> None:
        """Show the description and the options of ``analysis``."""
        self.current = analysis
        self.query_one("#description", Static).update(Text(analysis.description))
        pane = self.query_one("#options", VerticalScroll)
        pane.remove_children()
        self.rows = {}
        widgets = []
        for row in option_rows(analysis):
            editor = self._editor(row)
            self.rows[editor] = row
            label = Label(Text(row.label))
            if row.description:
                label.tooltip = editor.tooltip = row.description
            widgets.append(Horizontal(label, editor, classes="option"))
        if widgets:
            pane.mount_all(widgets)

    @staticmethod
    def _editor(row: OptionRow) -> Widget:
        if row.kind == "bool":
            return Checkbox("", bool(row.value), compact=True)
        if row.kind == "int":
            return Input(str(row.value), type="integer", compact=True)
        if row.kind == "choice":
            values = [value for value, _caption in row.choices]
            return Select(
                [(caption, idx) for idx, (_value, caption) in enumerate(row.choices)],
                value=values.index(row.value) if row.value in values else Select.NULL,
                compact=True,
            )
        return Input(str(row.value), compact=True)

    def _set(self, editor: Widget, value: Any) -> None:
        row = self.rows.get(editor)
        if row is None or self.current is None:
            return
        row.option.value = value
        if is_language_option(self.current, row.option):
            self._ask_language(set_language(self.analyses, value))

    def _ask_language(self, prompts: list[LanguagePrompt]) -> None:
        """Ask the language questions one after another."""
        if not prompts:
            return
        prompt, rest = prompts[0], prompts[1:]

        def answered(reply: str | None) -> None:
            if reply == "Yes":
                prompt.apply()
                selections = self.query_one("#analyses", SelectionList)
                for config in prompt.targets:
                    (selections.select if prompt.want_enabled else selections.deselect)(config.name)
            self._ask_language(rest)

        self.app.push_screen(QuestionScreen(prompt.title, prompt.text, ["Yes", "No"], "Yes"), answered)

    #
    # Events
    #

    def on_selection_list_selection_highlighted(self, event: SelectionList.SelectionHighlighted) -> None:
        event.stop()
        name = event.selection.value
        with contextlib.suppress(KeyError):
            analysis = self.analyses.by_name(name)
            if analysis is not self.current:
                self.show_analysis(analysis)

    def on_selection_list_selected_changed(self, event: SelectionList.SelectedChanged) -> None:
        event.stop()
        selected = set(event.selection_list.selected)
        for analysis in self.analyses:
            analysis.enabled = analysis.name in selected

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        event.stop()
        self._set(event.checkbox, event.value)

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()
        row = self.rows.get(event.input)
        if row is None:
            return
        if row.kind == "int":
            try:
                value = int(event.value)
            except ValueError:
                return
            if not row.minimum <= value <= row.maximum:
                return
            self._set(event.input, value)
        else:
            self._set(event.input, event.value)

    def on_select_changed(self, event: Select.Changed) -> None:
        event.stop()
        row = self.rows.get(event.select)
        if row is not None and isinstance(event.value, int):
            self._set(event.select, row.choices[event.value][0])

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "ok":
            self.dismiss(True)
        elif event.button.id == "cancel":
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


__all__ = ["AnalysisOptionsScreen"]
