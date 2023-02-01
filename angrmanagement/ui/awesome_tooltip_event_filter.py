# pylint:disable=no-self-use

# https://stackoverflow.com/questions/4795757/is-there-a-better-way-to-wordwrap-text-in-qtooltip-than-just-using-regexp
# credit: Cecil Curry

import html

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import QWidget


class QAwesomeTooltipEventFilter(QObject):
    """
    Tooltip-specific event filter dramatically improving the tooltips of all
    widgets for which this filter is installed.

    Motivation
    ----------
    **Rich text tooltips** (i.e., tooltips containing one or more HTML-like
    tags) are implicitly wrapped by Qt to the width of their parent windows and
    hence typically behave as expected.

    **Plaintext tooltips** (i.e., tooltips containing no such tags), however,
    are not. For unclear reasons, plaintext tooltips are implicitly truncated to
    the width of their parent windows. The only means of circumventing this
    obscure constraint is to manually inject newlines at the appropriate
    80-character boundaries of such tooltips -- which has the distinct
    disadvantage of failing to scale to edge-case display and device
    environments (e.g., high-DPI). Such tooltips *cannot* be guaranteed to be
    legible in the general case and hence are blatantly broken under *all* Qt
    versions to date. This is a `well-known long-standing issue <issue_>`__ for
    which no official resolution exists.

    This filter globally addresses this issue by implicitly converting *all*
    intercepted plaintext tooltips into rich text tooltips in a general-purpose
    manner, thus wrapping the former exactly like the latter. To do so, this
    filter (in order):

    #. Auto-detects whether the:

       * Current event is a :class:`QEvent.ToolTipChange` event.
       * Current widget has a **non-empty plaintext tooltip**.

    #. When these conditions are satisfied:

       #. Escapes all HTML syntax in this tooltip (e.g., converting all ``&``
          characters to ``&amp;`` substrings).
       #. Embeds this tooltip in the Qt-specific ``<qt>...</qt>`` tag, thus
          implicitly converting this plaintext tooltip into a rich text tooltip.

    .. _issue:
        https://bugreports.qt.io/browse/QTBUG-41051
    """

    def eventFilter(self, widget: QObject, event: QEvent) -> bool:
        """
        Tooltip-specific event filter handling the passed Qt object and event.
        """

        # If this is a tooltip event...
        if event.type() == QEvent.ToolTipChange:
            # If the target Qt object containing this tooltip is *NOT* a widget,
            # raise a human-readable exception. While this should *NEVER* be the
            # case, edge cases are edge cases because they sometimes happen.
            if not isinstance(widget, QWidget):
                raise ValueError(f'QObject "{widget}" not a widget.')

            # Tooltip for this widget if any *OR* the empty string otherwise.
            tooltip = widget.toolTip()

            # If this tooltip is both non-empty and not already rich text...
            if tooltip and not Qt.mightBeRichText(tooltip):
                # Convert this plaintext tooltip into a rich text tooltip by:
                #
                # * Escaping all HTML syntax in this tooltip.
                # * Embedding this tooltip in the Qt-specific "<qt>...</qt>" tag.
                tooltip = f"<qt>{html.escape(tooltip)}</qt>"

                # Replace this widget's non-working plaintext tooltip with this
                # working rich text tooltip.
                widget.setToolTip(tooltip)

                # Notify the parent event handler this event has been handled.
                return True

        # Else, defer to the default superclass handling of this event.
        return super().eventFilter(widget, event)
