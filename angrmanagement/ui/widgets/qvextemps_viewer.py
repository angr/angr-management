
import logging

from PySide.QtGui import QFrame, QLabel, QVBoxLayout, QHBoxLayout, QScrollArea, QSizePolicy
from PySide.QtCore import Qt, QSize

from .qast_viewer import QASTViewer

l = logging.getLogger('ui.widgets.qvextemps_viewer')


class QVEXTempsViewer(QFrame):

    def __init__(self, parent):
        super(QVEXTempsViewer, self).__init__(parent)

        self._state = None

        # widgets
        self._area = None
        self._tmps = { }

        self._init_widgets()

    #
    # Properties
    #

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, v):
        self._state = v

        self._load_tmps()

    #
    # Overridden methods
    #

    def sizeHint(self, *args, **kwargs):
        return QSize(100, 100)

    #
    # Public methods
    #

    def reload(self):

        state = self._state

        if state is None:
            return

        for tmp_id, tmp_value in state.scratch.temps.iteritems():
            print tmp_id, tmp_value, id(self._tmps[tmp_id])
            if state is None:
                self._tmps[tmp_id].ast = None
            else:
                self._tmps[tmp_id].ast = tmp_value

    #
    # Private methods
    #

    def _init_widgets(self):

        area = QScrollArea()
        area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setWidgetResizable(True)

        self._area = area

        base_layout = QVBoxLayout()
        base_layout.addWidget(area)
        self.setLayout(base_layout)

    def _load_tmps(self):

        state = self._state

        layout = QVBoxLayout()


        self._tmps.clear()
        if state is None:
            tmps = { }
        else:
            tmps = state.scratch.temps

        # tmps
        for tmp_id, tmp_value in tmps.iteritems():
            sublayout = QHBoxLayout()

            lbl_tmp_name = QLabel(self)
            lbl_tmp_name.setProperty('class', 'reg_viewer_label')
            lbl_tmp_name.setText("tmp_%d" % tmp_id)
            lbl_tmp_name.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            sublayout.addWidget(lbl_tmp_name)

            sublayout.addSpacing(10)

            tmp_viewer = QASTViewer(tmp_value, parent=self)
            self._tmps[tmp_id] = tmp_viewer
            sublayout.addWidget(tmp_viewer)

            layout.addLayout(sublayout)

        layout.setSpacing(0)
        layout.addStretch(0)
        layout.setContentsMargins(2, 2, 2, 2)

        # the container
        container = QFrame()
        container.setAutoFillBackground(True)
        palette = container.palette()
        palette.setColor(container.backgroundRole(), Qt.white)
        container.setPalette(palette)
        container.setLayout(layout)

        self._area.setWidget(container)
