from ...config import Conf

def repr_color(color):
    r,g,b,a = color.getRgb()
    return f'rgba({r},{g},{b},{a})'

#
# FIXME: Need to propagate CSS updates to more objects.
#

class CSS(object):

    @staticmethod
    def global_css():
        return """
QLabel[class=insn] {
    font: 10pt courier new;
    color: #000080;
}

QLabel[class=reg_viewer_label] {
    font: 10pt courier new;
    background-color: #ffffff;
}

QLabel[class=ast_viewer_size] {
    font: 10pt courier new;
}

QLabel[class=ast_viewer_ast_concrete] {
    font: 10pt courier new;
    color: blue;
}

QLabel[class=ast_viewer_ast_symbolic] {
    font: 10pt courier new;
    color: green;
}

QLabel[class=memory_viewer_address] {
    font: 10pt courier new;
}

QLabel[class=status_valid] {
    color: green;
}

QLabel[class=status_invalid] {
    color: red;
}

QFrame[class=insn_selected] {
    font: 10pt courier new;
    color: #000000;
    background-color: #efbfba;
}

QBlock {
    border: 1px solid black;
}

QBlockLabel {
    color: #0000ff;
}

QLabel[class=insn_addr] {
    font: 10pt courier new;
    color: black;
}

QLabel[class=insn_string] {
    font: 10pt courier new;
    color: gray;
    font-weight: bold;
}

QDockWidget::title {
    """ + f"background: {repr_color(Conf.palette_mid)};" + """
    border: 1px solid gray;
    padding: 0px 0px 0px 5px;
    margin: 0px 0px 2px 0px;
}

QPlainTextEdit, QTextEdit {
    """ + f"background-color: {repr_color(Conf.palette_base)};" + """
}

QTableView {
    """ + f"background-color: {repr_color(Conf.palette_base)};" + """
}
"""

