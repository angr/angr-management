
from PySide.QtGui import QTreeWidget, QTreeWidgetItem


class QPathGroupViewer(QTreeWidget):
    def __init__(self, pg, parent=None):
        super(QPathGroupViewer, self).__init__(parent)

        self.setColumnCount(1)
        self.setHeaderHidden(True)

        self._pathgroup = pg

        self._init_widgets()

    @property
    def pathgroup(self):
        return self._pathgroup

    @pathgroup.setter
    def pathgroup(self, v):
        self._pathgroup = v
        self.refresh()

    def refresh(self):
        self._init_widgets()

    def _init_widgets(self):

        self.clear()

        if self._pathgroup is None:
            return

        for stash_name, stash in self._pathgroup.stashes.iteritems():

            if not stash and stash_name not in ('active', 'deadended', 'avoided'):
                continue

            item = QTreeWidgetItem(self, [ "%s (%d)" % (stash_name, len(stash)) ])

            for path in stash:
                subitem = QTreeWidgetItem(item, [ str(path) ])
                item.addChild(subitem)

            self.addTopLevelItem(item)