"""
The pattern view of the terminal frontend: the pattern's graph on the left, and on the right the Pattern tab (the
project's patterns, the property sheet of the pattern and the selected node, the editing and search buttons, the
occurrences of the last search and the status line) and the Discover tab (the discovery knobs, the families found and
their status line), as in the Qt view.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, Input, Label, Select, Static, TabbedContent, TabPane

from angrmanagement.present.patterns import STATEMENT_MODES, PatternPresenter
from angrmanagement.tui.widgets.table import TableWidget

from .graphs import GraphTuiView

if TYPE_CHECKING:
    from textual import events
    from textual.app import ComposeResult
    from textual.widget import Widget

    from angrmanagement.present.patterns import PatternNodeRef, PropertyGroup, PropertySpec

LOOSEN_TIP = "Let every constant match any value"
CUT_TIP = "Wildcard subexpressions below the depth shape search can see"
CAPTURES_TIP = "Stop requiring interior values to flow through one variable"
APPLY_TIP = "Turn the pattern on, save it, then decompile its function again with it applied"
SUGGEST_TIP = "Re-lift the pattern from the single-entry part of the selected occurrence"
DISCOVER_TIP = "Find families of similar code in the function shown in the pseudocode view"


class PropertySheet(VerticalScroll):
    """
    The pattern's properties and the selected node's, a row each: Enter in a text field applies it, a check box
    applies as it is toggled, a choice as it is picked. A row whose property cannot change is disabled.
    """

    DEFAULT_CSS = """
    PropertySheet {
        height: 1fr;
    }
    PropertySheet > .group {
        text-style: bold;
        padding: 0 1;
        margin-top: 1;
    }
    PropertySheet > .property {
        height: 1;
    }
    PropertySheet > .property > Label {
        width: 28;
        padding: 0 1;
    }
    PropertySheet > .property > Input, PropertySheet > .property > Select {
        width: 1fr;
    }
    """

    def __init__(self, view: PatternTuiView) -> None:
        super().__init__(id="properties")
        self.view = view
        #: the property of each editor
        self.specs: dict[Widget, PropertySpec] = {}
        #: each group's header and its property rows with their labels, for the filter
        self._groups: list[tuple[Widget, str, list[tuple[Widget, str]]]] = []
        self.filter_text = ""

    def show(self, groups: list[PropertyGroup]) -> None:
        """Show ``groups``, keeping the focus on the row it was on."""
        focused = self.app.focused if self.is_attached else None
        focused_key = self.specs[focused].key if focused in self.specs else None
        self.specs = {}
        self._groups = []
        self.remove_children()
        rows: list[Widget] = []
        refocus = None
        for group in groups:
            header = Label(Text(group.name), classes="group")
            header.tooltip = group.description
            rows.append(header)
            members: list[tuple[Widget, str]] = []
            for spec in group.items:
                editor = self._editor(spec)
                self.specs[editor] = spec
                if spec.key == focused_key:
                    refocus = editor
                label = Label(Text(spec.label))
                if spec.description:
                    label.tooltip = editor.tooltip = spec.description
                row = Horizontal(label, editor, classes="property")
                rows.append(row)
                members.append((row, spec.label))
            self._groups.append((header, group.name, members))
        self.set_filter(self.filter_text)
        if rows:
            self.mount_all(rows)
        if refocus is not None:
            self.call_after_refresh(refocus.focus)

    def set_filter(self, text: str) -> None:
        """
        Show only the rows whose label holds ``text``, ignoring case, and the groups that keep a row or whose own name
        holds it, as the Qt property editor's filter box does.
        """
        self.filter_text = text
        needle = text.lower()
        for header, name, members in self._groups:
            shown = 0
            for row, label in members:
                row.display = not needle or needle in label.lower()
                shown += row.display
            header.display = not needle or shown > 0 or needle in name.lower()

    @staticmethod
    def _editor(spec: PropertySpec) -> Widget:
        if spec.kind == "bool":
            return Checkbox("", bool(spec.value), compact=True, disabled=spec.readonly)
        if spec.kind == "combo":
            options = [(choice, choice) for choice in spec.choices]
            return Select(options, value=spec.value, allow_blank=False, compact=True, disabled=spec.readonly)
        kinds: dict[str, Any] = {"int": "integer", "float": "number"}
        value = f"{spec.value:g}" if spec.kind == "float" else str(spec.value)
        return Input(value, type=kinds.get(spec.kind, "text"), compact=True, disabled=spec.readonly)

    def _apply(self, editor: Widget, value: Any) -> None:
        spec = self.specs.get(editor)
        if spec is None or value == spec.value:
            return
        if spec.kind == "int":
            value = int(value or 0)
        elif spec.kind == "float":
            value = float(value or 0)
        self.view.presenter.set_property(spec.key, value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self._apply(event.input, event.value)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        event.stop()
        self._apply(event.checkbox, event.value)

    def on_select_changed(self, event: Select.Changed) -> None:
        event.stop()
        self._apply(event.select, event.value)


class PropertyEditor(Vertical):
    """
    The property sheet with the Qt property editor's chrome: a "Filter by name..." box and a Docs toggle above it,
    and under it a description of the focused property, which the toggle shows and hides.
    """

    DEFAULT_CSS = """
    PropertyEditor {
        height: 1fr;
    }
    PropertyEditor > .tools {
        height: 1;
        margin-top: 1;
    }
    PropertyEditor > .tools > Input {
        width: 1fr;
    }
    PropertyEditor > .tools > Button {
        margin: 0 0 0 1;
        min-width: 6;
    }
    PropertyEditor > #description {
        height: 4;
        padding: 0 1;
        border-top: solid $foreground 30%;
    }
    """

    def __init__(self, sheet: PropertySheet) -> None:
        super().__init__(id="property-editor")
        self.sheet = sheet
        self.filter_box = Input(placeholder="Filter by name...", id="property-filter", compact=True)
        self.docs_button = Button("Docs", id="property-docs", compact=True, tooltip="Show or hide the description")
        self.description = Static("", id="description")

    def compose(self) -> ComposeResult:
        with Horizontal(classes="tools"):
            yield self.filter_box
            yield self.docs_button
        yield self.sheet
        yield self.description

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input is self.filter_box:
            event.stop()
            self.sheet.set_filter(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input is self.filter_box:
            event.stop()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button is self.docs_button:
            event.stop()
            self.description.display = not self.description.display

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        spec = self.sheet.specs.get(event.widget)
        if spec is not None:
            self.describe(spec)

    def describe(self, spec: PropertySpec | None) -> None:
        """Show ``spec``'s name in bold and its description, as the Qt description box does."""
        if spec is None:
            self.description.update("")
            return
        self.description.update(Text.assemble((spec.label, "bold"), "\n", spec.description))


class PatternTuiView(GraphTuiView):
    """
    One pattern as a graph of nodes. Enter (or a double click) on a node with children expands or collapses it; a
    selected node's constraints are in the property sheet; E and C expand and collapse everything, U undoes. The
    library's Enabled column toggles with Space, Enter on a pattern edits it; Enter on an occurrence goes to it, and
    on a family highlights its copies in the pseudocode.
    """

    PRESENTER_CLASS = PatternPresenter
    #: short enough for half the window; the Pattern tab's status line and the pseudocode view's menu say the rest
    EMPTY_TEXT = "No pattern loaded"
    DEFAULT_CSS = """
    PatternTuiView > Horizontal {
        height: 1fr;
    }
    PatternTuiView BoxGraphWidget {
        width: 1fr;
    }
    PatternTuiView #tabs {
        width: 1fr;
        min-width: 72;
    }
    PatternTuiView .buttons {
        height: 1;
        margin-top: 1;
    }
    PatternTuiView .buttons > Button {
        margin: 0 1 0 0;
        min-width: 6;
    }
    PatternTuiView .knobs {
        height: 1;
        margin-bottom: 1;
    }
    PatternTuiView .knobs > Label {
        padding: 0 1;
    }
    PatternTuiView .knobs > Input {
        width: 8;
    }
    PatternTuiView .knobs > Select {
        width: 26;
    }
    PatternTuiView .knobs > Button {
        margin: 0 0 0 1;
    }
    PatternTuiView #library {
        height: 7;
    }
    PatternTuiView #matches {
        height: 7;
        margin-top: 1;
    }
    PatternTuiView #families {
        height: 1fr;
    }
    PatternTuiView .status {
        height: auto;
        padding: 0 1;
        margin-top: 1;
    }
    """

    presenter: PatternPresenter

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        presenter = self.presenter
        presenter.on_graph_changed = self.pattern_graph_changed
        self.library = TableWidget(presenter.library, id="library")
        self.matches = TableWidget(presenter.matches_model, id="matches")
        self.families = TableWidget(presenter.families_model, id="families")
        self.properties = PropertySheet(self)
        self.property_editor = PropertyEditor(self.properties)
        self.status = Label(Text(presenter.status), classes="status", id="status")
        self.discover_status = Label(Text(presenter.discover_status), classes="status", id="discover-status")
        self.undo_button = Button("Undo", id="undo", compact=True, disabled=True)
        self.tabs = TabbedContent(id="tabs")

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield self.graph
            with self.tabs:
                with TabPane("Pattern", id="pattern-tab"):
                    yield Label("Project patterns")
                    yield self.library
                    with Horizontal(classes="buttons"):
                        yield Button("Edit", id="lib-edit", compact=True)
                        yield Button("Delete", id="lib-delete", compact=True)
                        yield Button("Export...", id="lib-export", compact=True)
                        yield Button("Import...", id="lib-import", compact=True)
                    yield self.property_editor
                    with Horizontal(classes="buttons"):
                        yield self.undo_button
                        yield Button("Loosen constants", id="loosen", compact=True, tooltip=LOOSEN_TIP)
                        yield Button("Cut deep expressions", id="cut", compact=True, tooltip=CUT_TIP)
                    with Horizontal(classes="buttons"):
                        yield Button("Loosen interior captures", id="captures", compact=True, tooltip=CAPTURES_TIP)
                        yield Button("Save to project", id="save", compact=True)
                        yield Button("Save & Redecompile", id="apply", compact=True, tooltip=APPLY_TIP)
                    with Horizontal(classes="buttons"):
                        yield Button("Search this function", id="search-here", compact=True)
                        yield Button("Search all functions", id="search-all", compact=True)
                        yield Button("Use suggested sub-run", id="suggest", compact=True, tooltip=SUGGEST_TIP)
                    yield self.matches
                    yield self.status
                with TabPane("Discover", id="discover-tab"):
                    presenter = self.presenter
                    with Horizontal(classes="knobs"):
                        yield Label("Min statements")
                        yield Input(str(presenter.min_size), type="integer", id="min-size", compact=True)
                        yield Label("Min identity")
                        yield Input(f"{presenter.min_identity:g}", type="number", id="min-identity", compact=True)
                    with Horizontal(classes="knobs"):
                        yield Label("Statements")
                        yield Select(
                            [(label, mode) for label, mode, _tip in STATEMENT_MODES],
                            value=presenter.statements,
                            allow_blank=False,
                            id="statements",
                            compact=True,
                        )
                        yield Button("Discover in current function", id="discover", compact=True, tooltip=DISCOVER_TIP)
                    yield self.families
                    yield self.discover_status

    def on_mount(self) -> None:
        super().on_mount()
        self.properties_changed()
        self.status_changed()

    #
    # What the presenter calls
    #

    def pattern_graph_changed(self, recenter: bool) -> None:
        if self.is_attached:
            self.graph.rebuild(keep_view=not recenter)

    def properties_changed(self) -> None:
        if not self.is_attached:
            return
        self.properties.show(self.presenter.property_groups())
        editor = self.presenter.editor
        self.undo_button.disabled = editor is None or not editor.can_undo

    def status_changed(self) -> None:
        if self.is_attached:
            self.status.update(Text(self.presenter.status))
            self.discover_status.update(Text(self.presenter.discover_status))

    def show_tab(self, name: str) -> None:
        if self.is_attached:
            self.tabs.active = f"{name}-tab"

    #
    # What the workspace calls, as on the Qt view
    #

    @property
    def editor(self):
        return self.presenter.editor

    def load_pattern(self, pattern, **kwargs) -> None:
        self.presenter.load_pattern(pattern, **kwargs)

    def load_stored(self, stored) -> None:
        self.presenter.load_stored(stored)

    def show_discover_tab(self) -> None:
        self.presenter.show_discover_tab()

    def discover(self, func, blocking: bool = True) -> None:
        self.presenter.discover(func, blocking=blocking)

    def reload_library(self) -> None:
        self.presenter.reload_library()

    #
    # The graph
    #

    def box_selected(self, node: PatternNodeRef) -> None:
        self.presenter.select_ref(node)

    #
    # The widgets
    #

    def _library_selection(self):
        rows = self.library.selected_rows
        return self.presenter.library.row(rows[0]) if rows else None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        presenter = self.presenter
        actions: dict[str | None, Any] = {
            "undo": presenter.undo,
            "loosen": presenter.loosen_constants,
            "cut": presenter.cut_depth,
            "captures": presenter.loosen_interior_captures,
            "save": presenter.save,
            "apply": presenter.apply,
            "search-here": presenter.search_current_function,
            "search-all": presenter.search_all_functions,
            "suggest": lambda: presenter.use_suggestion(self._match_row()),
            "discover": presenter.discover_in_current_function,
            "lib-import": presenter.ask_import,
        }
        stored_actions: dict[str | None, Any] = {
            "lib-edit": presenter.edit_stored,
            "lib-delete": presenter.delete_stored,
            "lib-export": presenter.ask_export,
        }
        action = actions.get(event.button.id)
        if action is not None:
            event.stop()
            action()
            return
        stored_action = stored_actions.get(event.button.id)
        if stored_action is not None:
            event.stop()
            stored = self._library_selection()
            if stored is not None:
                stored_action(stored)

    def _match_row(self) -> int:
        rows = self.matches.selected_rows
        return rows[0] if rows else -1

    def on_table_widget_selection_changed(self, event: TableWidget.SelectionChanged) -> None:
        if event.table is self.matches:
            event.stop()
            self.presenter.show_match(event.row)

    def on_input_changed(self, event: Input.Changed) -> None:
        presenter = self.presenter
        if event.input.id == "min-size":
            event.stop()
            if event.value.strip().isdigit():
                presenter.min_size = max(2, min(256, int(event.value)))
        elif event.input.id == "min-identity":
            event.stop()
            with contextlib.suppress(ValueError):
                presenter.min_identity = max(0.3, min(1.0, float(event.value)))

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "statements":
            event.stop()
            self.presenter.statements = event.value


__all__ = ["PatternTuiView", "PropertyEditor", "PropertySheet"]
