import sys

from PySide2.QtWidgets import QApplication
from PySide2.QtGui import QPalette

from ..widgets.qccode_highlighter import reset_formats
from ...data.object_container import ObjectContainer
from ...config import Conf
from ...logic import GlobalInfo


def repr_color(color):
    r,g,b,a = color.getRgb()
    return f'rgba({r},{g},{b},{a})'

#
# FIXME: Need to propagate CSS updates to more objects.
#

class CSS:

    global_css = ObjectContainer('', 'Global CSS')

    @staticmethod
    def rebuild():
        CSS.global_css.am_obj = """
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
        CSS.global_css.am_event()


def refresh_theme():
    app = QApplication.instance()

    # determine the default application style according to the OS
    if sys.platform == "win32":
        if Conf.theme_name == "Light":
            app_style = None
        else:
            app_style = "Fusion"
    elif sys.platform == "darwin":
        if Conf.theme_name == "Light":
            app_style = None
        else:
            app_style = "Fusion"
    elif sys.platform == "linux":
        app_style = "Fusion"
    else:
        app_style = "Fusion"

    if app_style:
        app.setStyle(app_style)

    palette = QPalette()
    palette.setColor(QPalette.Window,          Conf.palette_window)
    palette.setColor(QPalette.WindowText,      Conf.palette_windowtext)
    palette.setColor(QPalette.Base,            Conf.palette_base)
    palette.setColor(QPalette.AlternateBase,   Conf.palette_alternatebase)
    palette.setColor(QPalette.ToolTipBase,     Conf.palette_tooltipbase)
    palette.setColor(QPalette.ToolTipText,     Conf.palette_tooltiptext)
    palette.setColor(QPalette.Text,            Conf.palette_text)
    palette.setColor(QPalette.Button,          Conf.palette_button)
    palette.setColor(QPalette.ButtonText,      Conf.palette_buttontext)
    palette.setColor(QPalette.BrightText,      Conf.palette_brighttext)
    palette.setColor(QPalette.Highlight,       Conf.palette_highlight)
    palette.setColor(QPalette.HighlightedText, Conf.palette_highlightedtext)
    palette.setColor(QPalette.Light,           Conf.palette_light)
    palette.setColor(QPalette.Midlight,        Conf.palette_midlight)
    palette.setColor(QPalette.Dark,            Conf.palette_dark)
    palette.setColor(QPalette.Mid,             Conf.palette_mid)
    palette.setColor(QPalette.Shadow,          Conf.palette_shadow)
    palette.setColor(QPalette.Link,            Conf.palette_link)
    palette.setColor(QPalette.LinkVisited,     Conf.palette_linkvisited)
    palette.setColor(QPalette.Disabled, QPalette.Text,       Conf.palette_disabled_text)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, Conf.palette_disabled_buttontext)
    palette.setColor(QPalette.Disabled, QPalette.WindowText, Conf.palette_disabled_windowtext)
    app.setPalette(palette)
    CSS.rebuild()
    app.setStyleSheet(CSS.global_css.am_obj)

    reset_formats()

    if GlobalInfo.main_window is not None:
        for codeview in GlobalInfo.main_window.workspace.view_manager.views_by_category['pseudocode']:
            codeview.codegen.am_event(already_regenerated=True)

            if codeview._textedit is not None:
                for panel in codeview._textedit.panels:
                    panel.setPalette(palette)
