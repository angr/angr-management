import logging
import os
import sys
from string import Template

from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QApplication

from angrmanagement.config import RES_LOCATION, THEME_LOCATION, Conf
from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.widgets.qccode_highlighter import reset_formats

log = logging.getLogger(__name__)


#
# FIXME: Need to propagate CSS updates to more objects.
#


class CSS:
    """
    Main stylesheet re-load logic.
    """

    global_css = ObjectContainer("", "Global CSS")

    @staticmethod
    def rebuild():
        base_css_path = os.path.join(THEME_LOCATION, "base.css")
        try:
            with open(base_css_path, encoding="utf-8") as f:
                css = f.read()
        except Exception:  # pylint: disable=braod-except
            log.warning("Failed to load base theme at %s", base_css_path)
            css = ""

        theme_path = os.path.join(THEME_LOCATION, Conf.theme_name)
        css_path = os.path.join(theme_path, "theme.css")
        if os.path.exists(css_path):
            try:
                with open(css_path, encoding="utf-8") as f:
                    css += "\n" + f.read()
            except Exception:  # pylint: disable=broad-except
                log.warning("Failed to load theme CSS at %s", css_path)

        theme_resources_path = RES_LOCATION
        if sys.platform == "win32":
            theme_resources_path = theme_resources_path.replace("\\", "/")
            theme_path = theme_path.replace("\\", "/")
        CSS.global_css.am_obj = Template(css).safe_substitute(resources=theme_resources_path, theme=theme_path)
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
    palette.setColor(QPalette.Window, Conf.palette_window)
    palette.setColor(QPalette.WindowText, Conf.palette_windowtext)
    palette.setColor(QPalette.Base, Conf.palette_base)
    palette.setColor(QPalette.AlternateBase, Conf.palette_alternatebase)
    palette.setColor(QPalette.ToolTipBase, Conf.palette_tooltipbase)
    palette.setColor(QPalette.ToolTipText, Conf.palette_tooltiptext)
    palette.setColor(QPalette.PlaceholderText, Conf.palette_placeholdertext)
    palette.setColor(QPalette.Text, Conf.palette_text)
    palette.setColor(QPalette.Button, Conf.palette_button)
    palette.setColor(QPalette.ButtonText, Conf.palette_buttontext)
    palette.setColor(QPalette.BrightText, Conf.palette_brighttext)
    palette.setColor(QPalette.Highlight, Conf.palette_highlight)
    palette.setColor(QPalette.HighlightedText, Conf.palette_highlightedtext)
    palette.setColor(QPalette.Light, Conf.palette_light)
    palette.setColor(QPalette.Midlight, Conf.palette_midlight)
    palette.setColor(QPalette.Dark, Conf.palette_dark)
    palette.setColor(QPalette.Mid, Conf.palette_mid)
    palette.setColor(QPalette.Shadow, Conf.palette_shadow)
    palette.setColor(QPalette.Link, Conf.palette_link)
    palette.setColor(QPalette.LinkVisited, Conf.palette_linkvisited)
    palette.setColor(QPalette.Disabled, QPalette.Text, Conf.palette_disabled_text)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, Conf.palette_disabled_buttontext)
    palette.setColor(QPalette.Disabled, QPalette.WindowText, Conf.palette_disabled_windowtext)
    app.setPalette(palette)
    CSS.rebuild()
    app.setStyleSheet(CSS.global_css.am_obj)

    reset_formats()

    if GlobalInfo.main_window is not None:
        for codeview in GlobalInfo.main_window.workspace.view_manager.views_by_category["pseudocode"]:
            codeview.codegen.am_event(already_regenerated=True)

            if codeview._textedit is not None:
                for panel in codeview._textedit.panels:
                    panel.setPalette(palette)
