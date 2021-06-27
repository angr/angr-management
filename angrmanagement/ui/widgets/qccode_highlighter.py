
import re

from pyqodeng.core.api import SyntaxHighlighter
from PySide2.QtGui import QTextCharFormat, QFont, QBrush

from ..documents import QCodeDocument
from ...config import Conf

FORMATS = {}

def reset_formats():
    f = QTextCharFormat()
    f.setForeground(QBrush(Conf.pseudocode_keyword_color))
    f.setFontWeight(QFont.Bold)
    FORMATS['keyword'] = f

    f = QTextCharFormat()
    f.setForeground(QBrush(Conf.pseudocode_quotation_color))
    FORMATS['quotation'] = f

    f = QTextCharFormat()
    f.setForeground(QBrush(Conf.pseudocode_function_color))
    f.setFontWeight(QFont.Bold)
    FORMATS['function'] = f

    f = QTextCharFormat()
    f.setForeground(QBrush(Conf.pseudocode_comment_color))
    f.setFontWeight(QFont.Bold)
    FORMATS['comment'] = f

reset_formats()

class QCCodeHighlighter(SyntaxHighlighter):
    """
    A syntax highlighter for QCCodeEdit. Uses a custom lexing scheme to detect C constructs (functions, keywords,
    comments, and strings) and adds styling to them based on the current color scheme.
    """

    HIGHLIGHTING_RULES = [
        # quotation
        #(r"\"([^\\\"]|(\\.))*\"", 'quotation'),
        # comment
        #(r"//[^\n]*", 'comment'),
        #(r"/\*[^\n]*\*/", 'comment'),
        # function
        (r"\b[A-Za-z0-9_:]+\s*(?=\()", 'function'),
        (r"\bNULL\b", 'function'),
        # keywords
        (r"\bbool\b", 'keyword'),
        (r"\bbreak\b", 'keyword'),
        (r"\bcase\b", 'keyword'),
        (r"\bcatch\b", 'keyword'),
        (r"\bchar\b", 'keyword'),
        (r"\bclass\b", 'keyword'),
        (r"\bconst\b", 'keyword'),
        (r"\bcontinue\b", 'keyword'),
        (r"\bdefault\b", 'keyword'),
        (r"\bdelete\b", 'keyword'),
        (r"\bdo\b", 'keyword'),
        (r"\bdouble\b", 'keyword'),
        (r"\belse\b", 'keyword'),
        (r"\benum\b", 'keyword'),
        (r"\bexplicit\b", 'keyword'),
        (r"\bfloat\b", 'keyword'),
        (r"\bfor\b", 'keyword'),
        (r"\bfriend\b", 'keyword'),
        (r"\bgoto\b", 'keyword'),
        (r"\bif\b", 'keyword'),
        (r"\binline\b", 'keyword'),
        (r"\bint\b", 'keyword'),
        (r"\blong\b", 'keyword'),
        (r"\bnamespace\b", 'keyword'),
        (r"\bnew\b", 'keyword'),
        (r"\boperator\b", 'keyword'),
        (r"\bprivate\b", 'keyword'),
        (r"\bprotected\b", 'keyword'),
        (r"\bpublic\b", 'keyword'),
        (r"\bshort\b", 'keyword'),
        (r"\bsigned\b", 'keyword'),
        (r"\bsizeof\b", 'keyword'),
        (r"\bstatic\b", 'keyword'),
        (r"\bstruct\b", 'keyword'),
        (r"\btemplate\b", 'keyword'),
        (r"\bthis\b", 'keyword'),
        (r"\btrue\b", 'keyword'),
        (r"\btypedef\b", 'keyword'),
        (r"\btypename\b", 'keyword'),
        (r"\bunion\b", 'keyword'),
        (r"\bunsigned\b", 'keyword'),
        (r"\bvirtual\b", 'keyword'),
        (r"\bvoid\b", 'keyword'),
        (r"\bvolatile\b", 'keyword'),
        (r"\bwhile\b", 'keyword'),
        (r"\bswitch\b", 'keyword'),
        (r"\breturn\b", 'keyword'),
    ]

    def __init__(self, parent, color_scheme=None):
        super().__init__(parent, color_scheme=color_scheme)

        self.doc = parent  # type: QCodeDocument
        self.comment_status = False

    def highlight_block(self, text, block):
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
                elif text[col] == '\\':
                    escape_counter = 1
                elif text[col] == quote_mark:
                    quote_status = False
                    mark_out = col + 1
                    self.setFormat(mark_in, mark_out - mark_in, FORMATS['quotation'])
                    text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]
            else:
                if self.comment_status:
                    if text[col:col+2] == "*/":
                        mark_out = col + 2
                        self.comment_status = False
                        self.setFormat(mark_in, mark_out - mark_in, FORMATS['comment'])
                        text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]
                else:
                    # regular mode is here
                    if text[col] in ('"', "'"):
                        mark_in = col
                        quote_status = True
                        quote_mark = text[col]
                    elif text[col:col+2] == "/*":
                        mark_in = col
                        self.comment_status = True
                    elif text[col:col+2] == '//':
                        # do not set comment_status. just format the line and break.
                        mark_in = col
                        mark_out = len(text)
                        self.setFormat(mark_in, mark_out - mark_in, FORMATS['comment'])
                        text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]
                        break
        if self.comment_status:
            # do not unset. this is a multiline comment
            mark_out = len(text)
            self.setFormat(mark_in, mark_out - mark_in, FORMATS['comment'])
            text = text[:mark_in] + " " * (mark_out - mark_in) + text[mark_out:]

        for pattern, format_id in self.HIGHLIGHTING_RULES:
            for mo in list(re.finditer(pattern, text)):
                start = mo.start()
                end = mo.end()
                self.setFormat(start, end - start, FORMATS[format_id])
                #if format_id in {'quotation', 'comment'}:
                #    # remove the formatted parts so that we do not end up highlighting these parts again
                #    text = text[:start] + " " * (end-start) + text[end:]
