
from PySide.QtGui import QTreeWidget, QTreeWidgetItem


class QSimulationManagerViewer(QTreeWidget):
    def __init__(self, pg, parent=None):
        super(QSimulationManagerViewer, self).__init__(parent)

        self.setColumnCount(1)
        self.setHeaderHidden(True)

        self._simgr = pg

        self._init_widgets()

    @property
    def simgr(self):
        return self._simgr

    @simgr.setter
    def simgr(self, v):
        self._simgr = v
        self.refresh()

    def refresh(self):
        self._init_widgets()

    def _init_widgets(self):

        self.clear()

        if self._simgr is None:
            return

        for stash_name, stash in self._simgr.stashes.iteritems():

            if not stash and stash_name not in ('active', 'deadended', 'avoided'):
                continue

            item = QTreeWidgetItem(self, [ "%s (%d)" % (stash_name, len(stash)) ])

            for state in stash:
                subitem = QTreeWidgetItem(item, [ str(state) ])
                item.addChild(subitem)

            self.addTopLevelItem(item)

        # errored states
        if self._simgr.errored:
            item = QTreeWidgetItem(self, ["%s (%d)" % ('errored', len(self._simgr.errored))])
            for state in self._simgr.errored:
                subitem = QTreeWidgetItem(item, [str(state)])
                item.addChild(subitem)

            self.addTopLevelItem(item)
