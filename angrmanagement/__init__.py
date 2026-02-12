from __future__ import annotations

__version__ = "9.2.200.dev0"


try:
    # make sure qtpy (which is used in PyQodeNG.core) is using PySide6
    import os

    os.environ["QT_API"] = "pyside6"
    import qtpy  # noqa
except ImportError:
    # qtpy is not installed
    pass


def boot(project=None, block=False):
    if block:
        _boot(project)
        # noreturn
    else:
        import queue
        import threading

        response = queue.Queue()
        t = threading.Thread(target=_boot, args=(project, response))
        t.start()
        return response.get()


def _boot(project=None, response=None):
    import glob
    import os

    from PySide6.QtCore import QThread
    from PySide6.QtGui import QFontDatabase, QIcon
    from PySide6.QtWidgets import QApplication

    app = QApplication()
    app.setApplicationDisplayName("angr")
    app.setApplicationName("angr")
    from .consts import FONT_LOCATION, IMG_LOCATION

    icon_location = os.path.join(IMG_LOCATION, "angr.png")
    QApplication.setWindowIcon(QIcon(icon_location))

    from .config import Conf

    Conf.attempt_importing_initial_config()
    from .logic import GlobalInfo
    from .ui.awesome_tooltip_event_filter import QAwesomeTooltipEventFilter
    from .ui.css import refresh_theme  # import .ui after showing the splash screen since it's going to take time
    from .ui.main_window import MainWindow

    refresh_theme()
    for font_file in glob.glob(os.path.join(FONT_LOCATION, "*.ttf")):
        QFontDatabase.addApplicationFont(font_file)
    Conf.init_font_config()
    Conf.connect("ui_default_font", app.setFont, True)

    # install the global tooltip filter
    app.installEventFilter(QAwesomeTooltipEventFilter(app))

    GlobalInfo.gui_thread = QThread.currentThread()
    main_window = MainWindow(app=app)
    if project is not None:
        main_window.workspace.main_instance.project.am_obj = project
        main_window.workspace.main_instance.project.am_event()
        cfg = project.kb.cfgs.get_most_accurate()
        if cfg is not None:
            main_window.workspace.main_instance.cfg.am_obj = cfg
            main_window.workspace.main_instance.cfg.am_event()
    else:
        main_window.show_welcome_dialog()
    if response:
        response.put(main_window.workspace)
    app.exec_()
