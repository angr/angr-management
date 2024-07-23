from __future__ import annotations

import re
from typing import TYPE_CHECKING

from angr.analyses.decompiler.structured_codegen.c import (
    CArrayTypeLength,
    CClosingObject,
    CConstant,
    CExpression,
    CFunction,
    CFunctionCall,
    CLabel,
    CStatement,
    CStructFieldNameDef,
    CVariable,
)
from angr.sim_type import SimType
from pyqodeng.core.api import SyntaxHighlighter
from PySide6.QtGui import QBrush, QColor, QFont, QTextCharFormat

from angrmanagement.config import Conf

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


def _format_node(obj):
    """
    Return the format for the given node.
    """
    if isinstance(obj, SimType):
        return FORMATS["type"]
    elif isinstance(obj, CFunctionCall):
        if (
            obj.callee_func is not None
            and obj.callee_func.is_simprocedure
            or obj.callee_func.is_plt
            or obj.callee_func.is_syscall
        ):
            return FORMATS["library_function"]
        return FORMATS["function"]
    elif isinstance(obj, CFunction):
        return FORMATS["function"]
    elif isinstance(obj, CLabel):
        return FORMATS["label"]
    elif isinstance(obj, CVariable):
        return FORMATS["variable"]
    elif isinstance(obj, CArrayTypeLength):
        # This is the part that goes after a fixed-size array (the
        # "[20]" in "char foo[20];"), and it's highly unlikely
        # that anyone will want to change the color here. But if
        # you do, follow the format of the rest.
        return None
    elif isinstance(obj, CStructFieldNameDef):
        # This is the part that is a field name in a struct def,
        # and it's highly unlikely that anyone will want to change
        # the color here. But if you do, follow the format of the
        # rest.
        return None
    elif isinstance(obj, CClosingObject | CStatement | CConstant | CExpression):
        return None
    else:
        return None


reset_formats()


class QCCodeHighlighter(SyntaxHighlighter):
    """
    A syntax highlighter for QCCodeEdit. Uses a custom lexing scheme to detect C constructs (functions, keywords,
    comments, and strings) and adds styling to them based on the current color scheme.
    """

    HIGHLIGHTING_RULES = [
        # quotation
        # (r"\"([^\\\"]|(\\.))*\"", 'quotation'),
        # comment
        # (r"//[^\n]*", 'comment'),
        # (r"/\*[^\n]*\*/", 'comment'),
        # function
        (r"\bNULL\b", "function"),
        # keywords
        (r"\bauto\b", "keyword"),
        (r"\bbreak\b", "keyword"),
        (r"\bcase\b", "keyword"),
        (r"\bcatch\b", "keyword"),
        (r"\bclass\b", "keyword"),
        (r"\bconst\b", "keyword"),
        (r"\bcontinue\b", "keyword"),
        (r"\bdefault\b", "keyword"),
        (r"\bdelete\b", "keyword"),
        (r"\bdo\b", "keyword"),
        (r"\belse\b", "keyword"),
        (r"\benum\b", "keyword"),
        (r"\bexplicit\b", "keyword"),
        (r"\bextern\b", "keyword"),
        (
            r"\bfalse\b",
            "keyword",
        ),  # TODO: false isn't really a keyword, and other highlighters style it different from keywords
        (r"\bfor\b", "keyword"),
        (r"\bfriend\b", "keyword"),
        (r"\bgoto\b", "keyword"),
        (r"\bif\b", "keyword"),
        (r"\binline\b", "keyword"),
        (r"\bnamespace\b", "keyword"),
        (r"\bnew\b", "keyword"),
        (r"\boperator\b", "keyword"),
        (r"\bprivate\b", "keyword"),
        (r"\bprotected\b", "keyword"),
        (r"\bpublic\b", "keyword"),
        (r"\bregister\b", "keyword"),
        (r"\breturn\b", "keyword"),
        (r"\bsizeof\b", "keyword"),
        (r"\bstatic\b", "keyword"),
        (r"\bstruct\b", "keyword"),
        (r"\bswitch\b", "keyword"),
        (r"\btemplate\b", "keyword"),
        (r"\bthis\b", "keyword"),
        (
            r"\btrue\b",
            "keyword",
        ),  # TODO: true isn't really a keyword, and other highlighters style it different from keywords
        (r"\btypedef\b", "keyword"),
        (r"\btypename\b", "keyword"),
        (r"\bunion\b", "keyword"),
        (r"\bvirtual\b", "keyword"),
        (r"\bvolatile\b", "keyword"),
        (r"\bwhile\b", "keyword"),
    ]

    def __init__(self, parent, color_scheme=None) -> None:
        super().__init__(parent, color_scheme=color_scheme)

        self.doc: QCodeDocument = parent
        self.comment_status = False

    def highlight_block(self, text: str, block) -> None:
        # this code makes the assumption that this function is only ever called on lines in sequence in order
        # it might also fuck up if it ever calls it starting in the middle...
        if block.previous() is None:
            self.comment_status = False

        mark_in = 0

        quote_status = False
        quote_mark = None
        escape_counter = 0
        for col, _ in enumerate(text):
            if quote_status:
                assert not self.comment_status
                if escape_counter:
                    escape_counter -= 1
                elif text[col] == "\\":
                    escape_counter = 1
                elif text[col] == quote_mark:
                    quote_status = False
                    mark_out = col + 1
                    self.setFormat(mark_in, mark_out - mark_in, FORMATS["quotation"])
                    text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]
            else:
                if self.comment_status:
                    if text[col : col + 2] == "*/":
                        mark_out = col + 2
                        self.comment_status = False
                        self.setFormat(mark_in, mark_out - mark_in, FORMATS["comment"])
                        text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]
                else:
                    # regular mode is here
                    if text[col] in ('"', "'"):
                        mark_in = col
                        quote_status = True
                        quote_mark = text[col]
                    elif text[col : col + 2] == "/*":
                        mark_in = col
                        self.comment_status = True
                    elif text[col : col + 2] == "//":
                        # do not set comment_status. just format the line and break.
                        mark_in = col
                        mark_out = len(text)
                        self.setFormat(mark_in, mark_out - mark_in, FORMATS["comment"])
                        text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]
                        break
        if self.comment_status:
            # do not unset. this is a multiline comment
            mark_out = len(text)
            self.setFormat(mark_in, mark_out - mark_in, FORMATS["comment"])
            text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]

        # Go through AST and see about marking styles
        start_pos = block.position()
        current_idx = 0
        while current_idx < len(text):
            # if we know it's whitespace (b/c that can happen above due to comments), just skip it
            if text[current_idx] == " ":
                current_idx += 1
                continue

            current_pos = start_pos + current_idx
            element = self.doc.posmap.get_element(current_pos)
            if not element:
                current_idx += 1
                continue

            fmt = _format_node(element.obj)

            # Because of skipping spaces, we might end up inside an element, so don't use current_idx in the following
            if fmt:
                self.setFormat(element.start - start_pos, element.length, fmt)
            current_idx = (element.start - start_pos) + element.length

        for pattern, format_id in self.HIGHLIGHTING_RULES:
            for mo in list(re.finditer(pattern, text)):
                start = mo.start()
                end = mo.end()
                self.setFormat(start, end - start, FORMATS[format_id])
                # if format_id in {'quotation', 'comment'}:
                #    # remove the formatted parts so that we do not end up highlighting these parts again
                #    text = text[:start] + " " * (end-start) + text[end:]
