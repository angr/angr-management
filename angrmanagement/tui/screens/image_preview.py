"""
The preview of an exported image: what Save image is about to write, as a picture on a tier 3 terminal and as a
braille thumbnail on any other, with Save and Cancel. With ``large``, it is View > Graph Picture (picture mode): the
graph across the screen, drawn by Qt (angrmanagement.tui.picture_mode) when PySide6 is installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

from angrmanagement.tui.picture_mode import qt_picture
from angrmanagement.tui.pictures import braille_thumbnail, strips_image
from angrmanagement.tui.widgets.picture import graphics_tier, picture

from . import dialog_css, focus_if_present

if TYPE_CHECKING:
    from collections.abc import Sequence

    from textual.app import ComposeResult

    from angrmanagement.config.color import Color

#: The thumbnail's largest size, in cells.
PREVIEW_SIZE = (72, 18)


class ImagePreviewScreen(ModalScreen[bool]):
    """A preview of the image to save; answers True to save it."""

    DEFAULT_CSS = (
        dialog_css("ImagePreviewScreen")
        + f"""
ImagePreviewScreen #preview {{ width: {PREVIEW_SIZE[0]}; height: {PREVIEW_SIZE[1]}; }}
ImagePreviewScreen #size {{ color: $text-muted; }}
ImagePreviewScreen.large > Vertical {{ width: 95%; height: 95%; max-width: 95%; max-height: 95%; }}
ImagePreviewScreen.large #preview {{ width: 1fr; height: 1fr; }}
"""
    )
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(
        self, strips: Sequence[Any], caps: Any, background: Color, title: str = "Save image", large: bool = False
    ) -> None:
        super().__init__(classes="large" if large else None)
        self.title_text = title
        self.large = large
        self.strips = list(strips)
        self.caps = caps
        self.background = background

    def thumbnail(self) -> Static:
        size = (self.app.size.width - 8, self.app.size.height - 10) if self.large else PREVIEW_SIZE
        return Static(Text("\n".join(braille_thumbnail(self.strips, max(size[0], 10), max(size[1], 4)))))

    def image(self) -> Any:
        """The picture: drawn by Qt where PySide6 is installed (picture mode), else from the cells."""
        return qt_picture(self.strips, self.background) or strips_image(self.strips, self.background)

    def compose(self) -> ComposeResult:
        width = max((strip.cell_length for strip in self.strips), default=0)
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            # PIL comes with textual-image, so the picture is drawn only where it is shown
            image = self.image() if self.strips and graphics_tier(self.caps) else None
            yield picture(image, self.caps, self.thumbnail, id="preview")
            yield Label(Text(f"{width} x {len(self.strips)} cells"), id="size")
            with Horizontal(classes="buttons"):
                yield Button("Save...", id="save", variant="primary")
                yield Button("Close" if self.large else "Cancel", id="cancel")

    def on_mount(self) -> None:
        focus_if_present(self, "#save")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "save")

    def action_cancel(self) -> None:
        self.dismiss(False)


__all__ = ["ImagePreviewScreen"]
