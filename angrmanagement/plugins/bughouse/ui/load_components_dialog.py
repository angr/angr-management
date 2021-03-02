from typing import Optional, Dict, List, Tuple, TYPE_CHECKING
import os
import json
import binascii

from PySide2.QtWidgets import QDialog, QLineEdit, QLabel, QHBoxLayout, QVBoxLayout, QPushButton, QProgressBar,\
    QMessageBox, QSizePolicy, QFileDialog

from ....utils.io import isurl, download_url
from ..data.component_tree import ComponentTree, ComponentTreeNode, ComponentFunction

if TYPE_CHECKING:
    from ....ui.workspace import Workspace


class LoadComponentsDialog(QDialog):
    def __init__(self, workspace: 'Workspace', url: Optional[str]=None, parent=None):
        super().__init__(parent)

        self.url_box: QLineEdit = None
        self.ok_btn: QPushButton = None
        self.progressbar: QProgressBar = None

        self.setWindowTitle("Load components...")

        self.workspace = workspace
        self.url = url
        self.tree: ComponentTree = None

        self._init_widgets()

        if self.url is not None:
            self.url_box.setText(self.url)

    #
    # Actions
    #

    def exec_(self) -> int:

        if self.url is not None:
            self.show()
            self._on_ok_clicked()
            if self.tree is not None:
                return 0

        return super().exec_()

    def load_json(self):
        path = self.url_box.text()
        try:
            if isurl(path):
                tree = self._load_json_from_url(path)
            else:
                tree = self._load_json_from_file(path)
            self.tree = tree
            return True
        except (ValueError, TypeError, IOError) as ex:
            QMessageBox.critical(self,
                                 "Loading error",
                                 "Failed to load components information. Please make sure the component file is "
                                 "valid.\nException: %s" % ex,
                                 QMessageBox.Ok)
        return False

    def close_dialog(self):
        self.close()

    #
    # Initialization
    #

    def _init_widgets(self):

        # URL
        url_caption = QLabel(self)
        url_caption.setText("Path or URL:")

        self.url_box = QLineEdit(self)
        self.url_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        btn = QPushButton(self)
        btn.setText("...")
        btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        btn.clicked.connect(self._on_browse_file_btn_clicked)

        url_layout = QHBoxLayout()
        url_layout.addWidget(url_caption)
        url_layout.addWidget(self.url_box)
        url_layout.addWidget(btn)

        # progress bar
        self.progressbar = QProgressBar()
        self.progressbar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # buttons
        self.ok_btn = QPushButton(self)
        self.ok_btn.setText("&Load components")
        self.ok_btn.clicked.connect(self._on_ok_clicked)

        close_btn = QPushButton(self)
        close_btn.setText("&Close")
        close_btn.clicked.connect(self._on_close_clicked)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.ok_btn)
        btn_layout.addWidget(close_btn)

        # overall layout
        layout = QVBoxLayout()
        layout.addLayout(url_layout)
        layout.addWidget(self.progressbar)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    #
    # JSON loading
    #

    def _load_json_from_file(self, path):
        if not os.path.isfile(path):
            raise IOError("File %s does not exist." % path)

        with open(path, "r") as f:
            try:
                data = json.load(f)
            except ValueError as ex:
                raise TypeError("File %s does not contain valid JSON data.\nException: %s." % (path, ex))

        return self._load_json(data)

    def _load_json_from_url(self, url):
        content = download_url(url, parent=self, to_file=False)

        try:
            data = json.loads(content.decode("utf-8"))
        except ValueError as ex:
            raise TypeError("URL %s does not contain valid JSON data.\nException: %s." % (url, ex))
        return self._load_json(data)

    def _load_json(self, data: List[Dict]):

        # ok let's do this
        tree = ComponentTree()
        queue: List[Tuple[Dict, Optional[ComponentTreeNode]]] = [ (child, None) for child in data ]

        for node, parent in queue:
            label = node['label']
            if not label:
                # root?
                if parent is not None:
                    raise TypeError("Found a root node with a parent node.")

                binary = node['binary']
                blob_type = binary.get('blob_type')
                if blob_type != "bin":
                    raise TypeError("Unsupported blob_type \"%s\"." % blob_type)
                file_hash = binary.get('file_hash')
                if self.workspace.instance.project.am_none:
                    raise ValueError("No project has been loaded.")
                sha256 = self.workspace.instance.project.loader.main_object.sha256
                if binascii.unhexlify(file_hash) != sha256:
                    # warn user about it
                    r = QMessageBox.warning(None,
                                            "File hash mismatch",
                                            "The SHA256 hash of the main object is:\n"
                                            "    {main_obj_hash},\n"
                                            "while the ShA256 hash of the given components file is:\n"
                                            "    {hash}.\n"
                                            "Do you want to continue loading the components from the "
                                            "given JSON file?".format(
                                                main_obj_hash=binascii.hexlify(sha256),
                                                hash=file_hash,
                                            ),
                                            QMessageBox.Yes | QMessageBox.No)
                    if r == QMessageBox.No:
                        return False

                root = ComponentTreeNode(name="Root")
                tree.root = root

                for child in node['children']:
                    queue.append((child, root))

            else:
                tree_node = ComponentTreeNode(label)
                tree_node.functions = [ self._load_function(f) for f in node['functions'] ]
                for child in node['children']:
                    queue.append((child, tree_node))
                if parent is None:
                    if tree.root is not None:
                        raise ValueError("Found more than one root in the JSON file.")
                    tree.root = tree_node
                else:
                    parent.components.append(tree_node)

        return tree

    def _load_function(self, func: Dict):
        rebased_addr = func['start']['rebased_addr']
        f_node = ComponentFunction(rebased_addr['mapped_base'],
                                   rebased_addr['virtual_addr'],
                                   symbol_name=func.get('symbol_name', None))
        return f_node

    #
    # Events
    #

    def _on_ok_clicked(self):
        if self.load_json():
            self.close_dialog()

    def _on_close_clicked(self):
        self.close_dialog()

    def _on_browse_file_btn_clicked(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open a components JSON file", "",
                                                   "All files (*);;JSON file (*.json)",
                                                   )
        if file_path is not None:
            self.url_box.setText(file_path)
