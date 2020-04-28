
import re

from pyqodeng.core.api import SyntaxHighlighter
from PySide2.QtGui import QTextCharFormat, QFont
from PySide2.QtCore import Qt

from ...config import Conf
from ..documents import QCodeDocument


FORMATS = {
    'keyword': None,
    'quotation': None,
    'function': None,
    'comment': None,
}


class QCCodeHighlighter(SyntaxHighlighter):

    HIGHLIGHTING_RULES = [
        # quotation
        (r"\".*\"", 'quotation'),
        # comment
        (r"/[^\n]*", 'comment'),
        (r"/\*[^\n]*\*/", 'comment'),
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
        # function
        (r"\b[A-Za-z0-9_:]+(?=\()", 'function'),
    ]

    def __init__(self, parent, color_scheme=None):
        # TODO: Use the color scheme. it's not used right now
        super().__init__(parent, color_scheme=color_scheme)

        self.doc = parent  # type: QCodeDocument

        if FORMATS['keyword'] is None:
            f = QTextCharFormat()
            f.setFont(Conf.code_font)
            f.setForeground(Qt.darkBlue)
            f.setFontWeight(QFont.Bold)
            FORMATS['keyword'] = f
        if FORMATS['quotation'] is None:
            f = QTextCharFormat()
            f.setFont(Conf.code_font)
            f.setForeground(Qt.darkGreen)
            FORMATS['quotation'] = f
        if FORMATS['function'] is None:
            f = QTextCharFormat()
            f.setFont(Conf.code_font)
            f.setForeground(Qt.blue)
            f.setFontWeight(QFont.Bold)
            FORMATS['function'] = f
        if FORMATS['comment'] is None:
            f = QTextCharFormat()
            f.setFont(Conf.code_font)
            f.setForeground(Qt.darkGreen)
            f.setFontWeight(QFont.Bold)
            FORMATS['comment'] = f

    def highlight_block(self, text, block):
        for pattern, format_id in self.HIGHLIGHTING_RULES:
            for mo in list(re.finditer(pattern, text)):
                start = mo.start()
                end = mo.end()
                self.setFormat(start, end - start, FORMATS[format_id])
                if format_id in {'quotation', 'comment'}:
                    # remove the formatted parts so that we do not end up highlighting these parts again
                    text = text[:start] + " " * (end-start) + text[end:]
