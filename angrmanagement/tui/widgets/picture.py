"""
Pictures on a terminal that can draw them (tier 3), and the text drawing below it.

:func:`picture` gives a ``textual_image`` image widget when the terminal's tier is 3 and the package is installed (it
is in the ``tui`` extra), and the fallback widget otherwise. textual-image picks the kitty graphics protocol, Sixel,
half-cell blocks or Unicode itself, from what it found when it was imported; :func:`prepare_graphics` imports it
before the app starts, since its terminal queries do not work once Textual reads the input.
"""

from __future__ import annotations

import contextlib
import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual.widget import Widget

#: the tier that draws pictures
GRAPHICS_TIER = 3


def image_module() -> Any:
    """``textual_image.widget``, or None when textual-image is not installed."""
    try:
        return importlib.import_module("textual_image.widget")
    except ImportError:
        return None


def graphics_tier(caps: Any) -> bool:
    """Whether to draw pictures: tier 3 and textual-image installed."""
    tier = getattr(caps, "tier", caps if isinstance(caps, int) else 0)
    return tier >= GRAPHICS_TIER and image_module() is not None


def prepare_graphics() -> None:
    """Let textual-image ask the terminal what it can draw; call before the app runs."""
    with contextlib.suppress(ImportError):
        importlib.import_module("textual_image.renderable")


def picture(image: Any, caps: Any, fallback: Callable[[], Widget], **kwargs: Any) -> Widget:
    """
    An image widget of ``image`` (a PIL image or a path) on a tier 3 terminal; ``fallback()`` on any other.

    :param kwargs: The widget's ``id`` and ``classes``, given to whichever widget it is.
    """
    if graphics_tier(caps):
        module = image_module()
        return module.Image(image, **kwargs)
    widget = fallback()
    if "id" in kwargs and widget.id is None:
        widget.id = kwargs["id"]
    for name in str(kwargs.get("classes", "")).split():
        widget.add_class(name)
    return widget


def set_picture(widget: Widget, image: Any) -> bool:
    """Show ``image`` in ``widget`` if it is an image widget; whether it was one."""
    module = image_module()
    if module is not None and isinstance(widget, module.Image):
        widget.image = image
        return True
    return False


__all__ = ["GRAPHICS_TIER", "graphics_tier", "image_module", "picture", "prepare_graphics", "set_picture"]
