from __future__ import annotations

from typing import TYPE_CHECKING

from pyqodeng.core.api import SyntaxHighlighter
from PySide6.QtGui import QBrush, QColor, QFont, QTextCharFormat

from angrmanagement.config import Conf
from angrmanagement.present.code_highlight import (
    C_CPP_HIGHLIGHTING_RULES,
    GO_HIGHLIGHTING_RULES,
    RUST_HIGHLIGHTING_RULES,
    highlight_runs,
    node_kind,
)

if TYPE_CHECKING:
    from angrmanagement.ui.documents import QCodeDocument

FORMATS = {}


def create_char_format(color: QColor, weight: QFont.Weight, style: QFont.Style) -> QTextCharFormat:
    f = QTextCharFormat()
    f.setForeground(QBrush(color))
    f.setFontWeight(weight)
    if style == QFont.Style.StyleItalic:
        f.setFontItalic(True)
    return f


def reset_formats() -> None:
    bg = QTextCharFormat()
    bg.setBackground(Conf.palette_base)
    FORMATS["background"] = bg

    fg = QTextCharFormat()
    fg.setForeground(Conf.palette_text)
    fg.setFontWeight(QFont.Weight.Medium)
    FORMATS["normal"] = fg

    FORMATS["keyword"] = create_char_format(
        Conf.pseudocode_keyword_color, Conf.pseudocode_keyword_weight, Conf.pseudocode_keyword_style
    )

    FORMATS["quotation"] = create_char_format(
        Conf.pseudocode_quotation_color, Conf.pseudocode_quotation_weight, Conf.pseudocode_quotation_style
    )

    FORMATS["function"] = create_char_format(
        Conf.pseudocode_function_color, Conf.pseudocode_function_weight, Conf.pseudocode_function_style
    )

    FORMATS["library_function"] = create_char_format(
        Conf.pseudocode_library_function_color, Conf.pseudocode_function_weight, Conf.pseudocode_function_style
    )

    FORMATS["comment"] = create_char_format(
        Conf.pseudocode_comment_color, Conf.pseudocode_comment_weight, Conf.pseudocode_comment_style
    )

    FORMATS["variable"] = create_char_format(
        Conf.pseudocode_variable_color, Conf.pseudocode_variable_weight, Conf.pseudocode_variable_style
    )

    FORMATS["type"] = create_char_format(
        Conf.pseudocode_types_color, Conf.pseudocode_types_weight, Conf.pseudocode_types_style
    )

    FORMATS["label"] = create_char_format(
        Conf.pseudocode_label_color, Conf.pseudocode_label_weight, Conf.pseudocode_label_style
    )

    FORMATS["global_variable"] = create_char_format(
        Conf.pseudocode_global_variable_color,
        Conf.pseudocode_global_variable_weight,
        Conf.pseudocode_global_variable_style,
    )


def _format_node(obj):
    """
    Return the format for the given node.
    """
    return FORMATS[node_kind(obj)]


reset_formats()


class QCCodeHighlighter(SyntaxHighlighter):
    """
    A syntax highlighter for QCCodeEdit. The runs of each line come from
    :func:`angrmanagement.present.code_highlight.highlight_runs` (the position map's nodes, strings, comments and the
    flavor's keywords); this class applies them as the current color scheme's formats.
    """

    # the keyword rules of each flavor (angrmanagement.present.code_highlight has them)
    C_CPP_HIGHLIGHTING_RULES = C_CPP_HIGHLIGHTING_RULES
    GO_HIGHLIGHTING_RULES = GO_HIGHLIGHTING_RULES
    RUST_HIGHLIGHTING_RULES = RUST_HIGHLIGHTING_RULES

    def __init__(self, parent, color_scheme=None, flavor: str | None = None) -> None:
        super().__init__(parent, color_scheme=color_scheme)

        self.doc: QCodeDocument = parent
        self.comment_status = False
        self.flavor: str | None = flavor

    def highlight_block(self, text: str, block) -> None:
        # this code makes the assumption that this function is only ever called on lines in sequence in order
        # it might also fuck up if it ever calls it starting in the middle...
        if block.previous() is None:
            self.comment_status = False

        runs, self.comment_status = highlight_runs(
            text, block.position(), self.doc.posmap, self.flavor, self.comment_status
        )
        for start, count, kind in runs:
            self.setFormat(start, count, FORMATS[kind])
