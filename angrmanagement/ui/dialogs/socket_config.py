import base64
import socket

import claripy
from angr.storage.file import SimPacketsStream
from PySide6.QtCore import QAbstractItemModel, QModelIndex, QSize, Qt
from PySide6.QtGui import QColor, QContextMenuEvent, QIntValidator
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLineEdit,
    QMenu,
    QPushButton,
    QStyledItemDelegate,
    QTextEdit,
    QTreeView,
    QVBoxLayout,
)

_socket_families_wanted = ["AF_INET", "AF_INET6", "AF_UNIX", "AF_CAN", "AF_PACKET", "AF_RDS"]

socket_family = {s: getattr(socket, s) for s in _socket_families_wanted if s in dir(socket)}
socket_type = {"SOCK_STREAM": socket.SOCK_STREAM, "SOCK_DGRAM": socket.SOCK_DGRAM, "SOCK_RAW": socket.SOCK_RAW}


class SocketItem:  # pylint: disable=no-self-use, unused-argument
    """
    Socket Item for SocketModel
    """

    def __init__(self, ident=None, parent=None, node_type=None):
        self.parentItem = parent
        self.children = []
        self.ident = ident
        self.recv_pkg = None
        self.node_type = node_type

    def appendChild(self, item):
        self.children.append(item)

    def child(self, row):
        return self.children[row]

    def childCount(self):
        return len(self.children)

    def columnCount(self):
        return 1

    def data(self, column):
        if column == 0:
            if self.node_type in ("Socket", "Accepted"):
                return self.ident
            else:  # self.Node_Type == "Package"
                return self.recv_pkg
        else:
            return None

    def setData(self, column, data):
        if column == 0:
            if self.node_type in ("Socket", "Accepted"):
                self.ident = data
            else:  # self.Node_Type == "Package"
                self.recv_pkg = data
        return True

    def parent(self):
        return self.parentItem

    def row(self):
        if self.parentItem:
            return self.parentItem.children.index(self)

        return 0


class SimPackagePersistentEditor(QStyledItemDelegate):
    """
    Table Cell Editor
    """

    # pylint: disable=no-self-use, unused-argument
    def __init__(self, parent=None, instance=None):
        super().__init__(parent)
        self.instance = instance

    def createEditor(self, widget, option, index):
        editor = QTextEdit(widget)
        return editor

    def setEditorData(self, editor, index):
        value = index.model().data(index, role=Qt.DisplayRole)
        if value:
            editor.setText(str(value))

    def setModelData(self, editor, model, index):
        model.setData(index, editor.toPlainText(), role=Qt.DisplayRole)

    def updateEditorGeometry(self, editor, option, index):
        editor.setGeometry(option.rect)


class SocketModel(QAbstractItemModel):
    """
    Abstract Model with SocketView
    """

    # pylint: disable=no-self-use, unused-argument
    def __init__(self, data=None, parent=None):
        super().__init__(parent)
        self.rootItem = SocketItem()

    def columnCount(self, parent=None):
        if parent is None:
            parent = QModelIndex()
        if parent.isValid():
            return parent.internalPointer().columnCount()
        else:
            return self.rootItem.columnCount()

    def data(self, index, role=None):
        if not index.isValid():
            return None

        if role == Qt.SizeHintRole:
            if index.internalPointer().node_type == "Package":
                return QSize(300, 100)
            else:
                return QSize(300, 20)
        if role == Qt.BackgroundRole:
            if index.internalPointer().node_type == "Package":
                return QColor(226, 237, 253)
            else:
                return Qt.white

        if role != Qt.DisplayRole:
            return None

        item = index.internalPointer()

        return item.data(index.column())

    def setData(self, index, data, role=None):
        if not index.isValid():
            return None

        if role != Qt.DisplayRole:
            return None

        item = index.internalPointer()

        return item.setData(index.column(), data)

    def flags(self, index):
        if not index.isValid():
            return Qt.NoItemFlags
        if index.internalPointer().node_type == "Package":
            return Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsEditable
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable

    def headerData(self, section, orientation, role=None):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return "Socket"

        return None

    def index(self, row, column, parent=None):
        if parent is None:
            parent = QModelIndex()

        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        parentItem = self.rootItem if not parent.isValid() else parent.internalPointer()

        childItem = parentItem.child(row)
        if childItem:
            return self.createIndex(row, column, childItem)
        else:
            return QModelIndex()

    def rowCount(self, parent=None):
        if parent is None:
            parent = QModelIndex()

        if parent.column() > 0:
            return 0

        parentItem = self.rootItem if not parent.isValid() else parent.internalPointer()

        return parentItem.childCount()

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()

        childItem = index.internalPointer()
        parentItem = childItem.parent()

        if parentItem == self.rootItem:
            return QModelIndex()

        return self.createIndex(parentItem.row(), 0, parentItem)

    def add_item(self, ident, parent=None, node_type=None):
        if parent is None:
            parent = QModelIndex()
        self.beginInsertRows(parent, self.rowCount(parent), self.rowCount(parent))
        parentItem = self.rootItem if not parent.isValid() else parent.internalPointer()
        item = SocketItem(ident, parent=parentItem, node_type=node_type)
        parentItem.appendChild(item)
        self.endInsertRows()

    def del_item(self, item):
        parent = item.parent()
        parentItem = self.rootItem if not parent.isValid() else parent.internalPointer()
        self.beginRemoveRows(parent, item.row(), item.row())
        del parentItem.children[item.row()]
        self.endRemoveRows()

    def get_data(self):
        ret = {}
        for socket_info in self.rootItem.children:
            tmp = []
            for child in socket_info.children:
                if child.node_type == "Package":
                    tmp.append(child.recv_pkg)
                elif child.node_type == "Accepted":
                    ret[child.ident] = [p.recv_pkg for p in child.children]
            if tmp:
                ret[socket_info.ident] = tmp
        return ret

    def convert_ident(self, ident):
        return ("socket", socket_family[ident[0]], socket_type[ident[1]], 0, int(ident[2]))

    def convert(self):
        data = self.get_data()
        ret = {}
        for k, v in data.items():
            ident = k.split(", ")
            if ident[0] == "Accept":
                ident = ("accept", self.convert_ident(ident[1:]), int(ident[4]))
            else:
                ident = self.convert_ident(ident)
            content = [claripy.BVV(base64.b64decode(x)) for x in v]
            ret[ident] = (SimPacketsStream("socket read", content=content), SimPacketsStream("socket write"))
        return ret


class SocketView(QTreeView):
    """
    Socket Config Tree View with SocketModel
    """

    def __init__(self):
        super().__init__()
        self.setTextElideMode(Qt.ElideNone)

    def _action_accepted_socket(self):
        current = self.currentIndex()
        if current.parent().isValid():
            current = current.parent()
        ident = "Accept, " + current.internalPointer().ident + (", %d" % (current.internalPointer().childCount() + 1))
        self.model().add_item(ident, current, "Accepted")

    def _action_add_package(self):
        current = self.currentIndex()
        if current.internalPointer().node_type == "Package":
            current = current.parent()
        ident = "Package"
        self.model().add_item(ident, current, "Package")

    def _action_delete(self):
        current = self.currentIndex()
        self.model().del_item(current)

    def contextMenuEvent(self, event: QContextMenuEvent):
        menu = QMenu("", self)
        menu.addAction("Add an accepted socket", self._action_accepted_socket)
        menu.addAction("Add a recv packages", self._action_add_package)
        menu.addAction("Delete", self._action_delete)
        menu.exec_(event.globalPos())


class SocketConfig(QDialog):
    """
    Socket Config Dialog
    """

    family = list(socket_family.keys())
    typ = list(socket_type.keys())

    def __init__(self, socket_config=None, instance=None, parent=None):
        super().__init__(parent)

        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self._instance = instance
        self._editor = SimPackagePersistentEditor(instance=instance)
        self._parent = parent
        self.socket_config: SocketModel
        if socket_config:
            self.socket_config = socket_config
        else:
            self.socket_config = SocketModel()
        self._init_widgets()

    def _init_widgets(self):
        layout = QVBoxLayout()
        self._table = SocketView()
        self._table.setModel(self.socket_config)
        self._table.setItemDelegate(self._editor)

        layout.addWidget(self._table, 0)
        toolbox = QHBoxLayout()
        self._socket_family = QComboBox(self)
        self._socket_family.addItems(["Family"] + self.family)
        self._socket_type = QComboBox(self)
        self._socket_type.addItems(["Type"] + self.typ)
        self._socket_nonce = QLineEdit(self)
        self._socket_nonce.setValidator(QIntValidator(0, 9999, self))
        self._socket_add_button = QPushButton("Add new socket")

        def _add_new_socket():
            family = self._socket_family.currentIndex() - 1
            typ = self._socket_family.currentIndex() - 1
            nonce = self._socket_nonce.text()
            if family < 0 or typ < 0 or not nonce:
                return
            txt = ", ".join([self._socket_family.currentText(), self._socket_type.currentText(), nonce])
            self.socket_config.add_item(txt, node_type="Socket")

        self._socket_add_button.clicked.connect(_add_new_socket)

        toolbox.addWidget(self._socket_family, 0)
        toolbox.addWidget(self._socket_type, 1)
        toolbox.addWidget(self._socket_nonce, 2)
        toolbox.addWidget(self._socket_add_button, 3)
        layout.addLayout(toolbox, 1)
        self.setLayout(layout)

    def closeEvent(self, event):  # pylint: disable=unused-argument
        # print(self.socket_config.get_data())
        self.close()
