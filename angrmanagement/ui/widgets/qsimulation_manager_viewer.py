from PySide2.QtWidgets import QTreeWidget, QTreeWidgetItem
from PySide2.QtCore import Qt


class QSimulationManagerViewer(QTreeWidget):
    def __init__(self, simgr, parent=None):
        super(QSimulationManagerViewer, self).__init__(parent)

        self.setColumnCount(1)
        self.setHeaderHidden(True)

        self.simgr = simgr

        self._init_widgets()

        self.simgr.am_subscribe(self.refresh)

    def refresh(self, **kwargs):
        if kwargs.get('src') != 'simgr_viewer':
            self._init_widgets()

    def current_state(self):
        item = self.currentItem()
        if item is None:
            return None
        return item.data(0, 1)

    def select_state(self, state):
        if state is None:
            self.setCurrentItem(None)
        else:
            for i in range(self.topLevelItemCount()):
                item = self.topLevelItem(i)
                for j in range(item.childCount()):
                    subitem = item.child(j)
                    if subitem.data(0, 1) == state:
                        self.setCurrentItem(subitem)
                        break
                else:
                    continue
                break

    def _init_widgets(self):
        self.clear()

        if self.simgr.am_none():
            return

        for stash_name, stash in self.simgr.stashes.items():
            if not stash and stash_name not in ('active', 'deadended', 'avoided'):
                continue

            item = QTreeWidgetItem(self, ["%s (%d)" % (stash_name, len(stash))])
            item.setFlags(item.flags() & ~Qt.ItemIsSelectable)

            for state in stash:
                subitem = QTreeWidgetItem(item, [str(state)])
                subitem.setData(0, 1, state)
                item.addChild(subitem)

            self.addTopLevelItem(item)

        # errored states
        if self.simgr.errored:
            item = QTreeWidgetItem(self, ["%s (%d)" % ('errored', len(self.simgr.errored))])
            item.setFlags(item.flags() & ~Qt.ItemIsSelectable)

            for estate in self.simgr.errored:
                subitem = QTreeWidgetItem(item, [str(estate)])
                subitem.setData(0, 1, estate.state)
                item.addChild(subitem)

            self.addTopLevelItem(item)
