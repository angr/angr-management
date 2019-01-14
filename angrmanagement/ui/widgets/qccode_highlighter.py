
import re

from PySide2.QtGui import QSyntaxHighlighter, QTextCharFormat, QFont
from PySide2.QtCore import Qt

from ...config import Conf


FORMATS = {
    'keyword': None,
    'quotation': None,
    'function': None,
    'comment': None,
}


class QCCodeHighlighter(QSyntaxHighlighter):

    HIGHLIGHTING_RULES = [
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
        # quotation
        (r"\".*\"", 'quotation'),
        # function
        (r"\b[A-Za-z0-9_]+(?=\()", 'function'),
        # comment
        (r"/[^\n]*", 'comment'),
        (r"/\*[^\n]*\*/", 'comment'),
    ]

    def __init__(self, *args):
        super().__init__(*args)

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

    def highlightBlock(self, text):
        for pattern, format_id in self.HIGHLIGHTING_RULES:
            for mo in re.finditer(pattern, text):
                self.setFormat(mo.start(), mo.end() - mo.start(), FORMATS[format_id])
