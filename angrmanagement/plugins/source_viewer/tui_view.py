"""
The source viewer for the terminal: the Qt SourceViewer's tabs of source files, with line numbers that are bold where
a line has addresses, the find and avoid markers, and the marker menu (Add Find, Add Avoid, Jump to; Remove on a line
that has a marker). Enter, Shift+F10 or a click on a line number opens the menu; ``/`` or ``?`` edits the line's ``//``
comment, as in the Qt editor.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.segment import Segment
from rich.style import Style
from textual.binding import Binding
from textual.geometry import Size
from textual.scroll_view import ScrollView
from textual.strip import Strip
from textual.widgets import Static, TabbedContent, TabPane

from angrmanagement.logic import GlobalInfo
from angrmanagement.present.base import InstancePresenter
from angrmanagement.present.code_highlight import highlight_runs, kind_style
from angrmanagement.present.menus import Menu, MenuEntry
from angrmanagement.tui.views.base import TuiView
from angrmanagement.tui.widgets.styles import StyleCache

from .model import SourceMap, add_point, read_source, remove_point, with_comment

if TYPE_CHECKING:
    from textual import events
    from textual.app import ComposeResult

#: the markers' letters and styles: find and avoid, as the Qt marker panel's icons
MARKERS = {"find": ("F", "disasm.mark.find"), "avoid": ("A", "disasm.mark.avoid")}


class SourcePresenter(InstancePresenter):
    """The source viewer's state: the source map of the loaded binary and the markers set on its lines."""

    def __init__(self, workspace, instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "SourceViewer", instance, default_docking_position)
        self.base_caption = "Source Viewer"
        self.source_map = SourceMap()
        #: (file name, line) -> "find" or "avoid"
        self.markers: dict[tuple[str, int], str] = {}
        #: how a source file's text is read (from disk)
        self.read_source = read_source

    def load_from_project(self) -> bool:
        """Read the debug information's lines of the loaded binary; whether it has any."""
        if self.instance.project.am_none:
            return False
        main_object = self.instance.project.loader.main_object
        addr_to_line = getattr(main_object, "addr_to_line", None)
        if addr_to_line is None:
            return False
        self.source_map.load(addr_to_line)
        return True

    def add_marker(self, filename: str, line: int, typ: str) -> str:
        self.markers[(filename, line)] = typ
        return add_point(self.workspace, self.source_map, filename, line, typ)

    def remove_marker(self, filename: str, line: int) -> None:
        self.markers.pop((filename, line), None)
        remove_point(self.workspace, self.source_map, filename, line)

    def marker_menu(self, filename: str, line: int, refresh: Any = None) -> Menu | None:
        """The Qt marker panel's menus: Remove on a marked line; Add Find, Add Avoid and Jump to on a line with code."""

        def then(func: Any) -> Any:
            def run() -> None:
                func()
                if refresh is not None:
                    refresh()

            return run

        if (filename, line) in self.markers:
            return Menu("Marker", [MenuEntry("Remove", then(lambda: self.remove_marker(filename, line)))])
        if line not in self.source_map.valid_lines(filename):
            return None
        entries: list[Any] = [
            MenuEntry("Add Find", then(lambda: self.add_marker(filename, line, "find"))),
            MenuEntry("Add Avoid", then(lambda: self.add_marker(filename, line, "avoid"))),
        ]
        addrs = self.source_map.line_to_addr[(filename, line)]
        if addrs:
            entries.append(
                Menu("Jump to", [MenuEntry(f"0x{addr:x}", lambda a=addr: self.workspace.jump_to(a)) for addr in addrs])
            )
        return Menu("Marker", entries)


class SourceFileWidget(ScrollView, can_focus=True):
    """One source file: line numbers, markers and the highlighted text, with a line cursor."""

    DEFAULT_CSS = """
    SourceFileWidget {
        height: 1fr;
    }
    """
    BINDINGS: ClassVar = [
        Binding("up", "move(-1)", show=False),
        Binding("down", "move(1)", show=False),
        Binding("pageup", "move(-20)", show=False),
        Binding("pagedown", "move(20)", show=False),
        Binding("enter", "marker_menu", "Markers", show=False),
        Binding("shift+f10", "marker_menu", "Markers", show=False),
        Binding("slash", "comment", "Comment", show=False),
        Binding("question_mark", "comment", "Comment", show=False),
    ]

    def __init__(self, view: SourceTuiView, filename: str, text: str | None) -> None:
        super().__init__()
        self.view = view
        self.filename = filename
        self.readable = text is not None
        self.lines = text.splitlines() if text is not None else [f"(cannot read {filename})"]
        #: the line the cursor is on, from 1
        self.cursor_line = 1
        self.style_of = StyleCache(self)
        self.virtual_size = Size(max((len(line) for line in self.lines), default=0) + 12, len(self.lines))

    @property
    def gutter_width(self) -> int:
        return len(str(len(self.lines))) + 3

    def render_line(self, y: int) -> Strip:
        scroll_x, scroll_y = self.scroll_offset
        index = scroll_y + y
        width = self.size.width
        if index >= len(self.lines):
            return Strip.blank(width)
        line_no = index + 1
        presenter = self.view.presenter
        valid = line_no in presenter.source_map.valid_lines(self.filename)
        number = str(line_no).rjust(self.gutter_width - 3)
        segments = [Segment(number, Style(bold=True) if valid else Style(dim=True))]
        marker = presenter.markers.get((self.filename, line_no))
        if marker is not None:
            letter, key = MARKERS[marker]
            segments.append(Segment(f" {letter} ", self.style_of(key)))
        else:
            segments.append(Segment("   "))
        text = self.lines[index]
        runs, _ = highlight_runs(text, 0, None, None, False) if self.readable else ([], False)
        body: list[Segment] = []
        pos = 0
        for start, length, kind in runs:
            if start > pos:
                body.append(Segment(text[pos:start]))
            body.append(Segment(text[start : start + length], self.style_of(kind_style(kind))))
            pos = start + length
        if pos < len(text):
            body.append(Segment(text[pos:]))
        line_strip = Strip.join(
            [Strip(segments), Strip(body).crop(scroll_x, scroll_x + max(0, width - self.gutter_width))]
        )
        if line_no == self.cursor_line and self.has_focus:
            line_strip = line_strip.apply_style(Style(reverse=True))
        return line_strip.extend_cell_length(width).crop(0, width)

    def action_move(self, delta: int) -> None:
        self.cursor_line = max(1, min(len(self.lines), self.cursor_line + delta))
        self.scroll_to_region_of_line()
        self.refresh()

    def scroll_to_region_of_line(self) -> None:
        y = self.cursor_line - 1
        top = self.scroll_offset.y
        height = max(1, self.size.height)
        if y < top:
            self.scroll_to(y=y, animate=False)
        elif y >= top + height:
            self.scroll_to(y=y - height + 1, animate=False)

    def on_click(self, event: events.Click) -> None:
        line = self.scroll_offset.y + event.y + 1
        if 1 <= line <= len(self.lines):
            self.cursor_line = line
            self.refresh()
            if event.x < self.gutter_width:
                # the Qt marker panel opens its menu on a click
                self.action_marker_menu()

    def action_marker_menu(self) -> None:
        menu = self.view.presenter.marker_menu(self.filename, self.cursor_line, self.refresh)
        if menu is not None:
            self.view.open_menu(
                menu, (self.region.x + self.gutter_width, self.region.y + self.cursor_line - self.scroll_offset.y)
            )

    def action_comment(self) -> None:
        index = self.cursor_line - 1
        if not self.readable or not 0 <= index < len(self.lines):
            return
        text = self.lines[index]
        old = text.rsplit("//", 1)[1] if "//" in text else ""

        def then(answer: str | None) -> None:
            if answer is None:
                return
            self.lines[index] = with_comment(self.lines[index], answer)
            self.refresh()

        GlobalInfo.ui_services.prompt_text_async("Comment", "Comment", old, then)


class SourceTuiView(TuiView):
    """The source viewer: a tab per source file the binary's debug information names."""

    PRESENTER_CLASS = SourcePresenter

    presenter: SourcePresenter

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        self.tabs = TabbedContent(id="source-files")
        self.files: dict[str, SourceFileWidget] = {}
        self._generation = 0
        instance.project.am_subscribe(self._on_project)

    def compose(self) -> ComposeResult:
        yield self.tabs

    def on_mount(self) -> None:
        self.load_from_project()

    def _on_project(self, **_kwargs) -> None:
        if self.is_mounted:
            self.load_from_project()

    def load_from_project(self) -> None:
        """Open a tab for each source file of the loaded binary."""
        if not self.presenter.load_from_project():
            if not self.files:
                self.tabs.add_pane(TabPane("(no source)", Static("The binary has no line information."), id="empty"))
            return
        self.files = {}
        self.tabs.clear_panes()
        # clearing finishes later, so the new panes get names the old ones did not have
        self._generation += 1
        for idx, filename in enumerate(sorted(self.presenter.source_map.file_list)):
            widget = SourceFileWidget(self, filename, self.presenter.read_source(filename))
            self.files[filename] = widget
            pane_id = f"file-{self._generation}-{idx}"
            added = self.tabs.add_pane(TabPane(filename.rsplit("/", 1)[-1], widget, id=pane_id))
            if idx == 0:
                self.run_worker(self._activate(added, pane_id), exit_on_error=False)

    async def _activate(self, added: Any, pane_id: str) -> None:
        await added
        self.tabs.active = pane_id

    def open_menu(self, menu: Menu, offset: tuple[int, int]) -> None:
        open_context_menu = getattr(self.app, "open_context_menu", None)
        if open_context_menu is not None:
            open_context_menu(menu, offset)

    def close_view(self) -> None:
        self.instance.project.am_unsubscribe(self._on_project)
        super().close_view()

    def focus_view(self) -> None:
        for widget in self.files.values():
            if widget.display:
                widget.focus()
                return


__all__ = ["SourceFileWidget", "SourcePresenter", "SourceTuiView"]
