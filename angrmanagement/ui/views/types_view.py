from PySide2.QtWidgets import QScrollArea, QWidget, QVBoxLayout, QFrame, QHBoxLayout, QPushButton, QMessageBox, QLabel

from angr.sim_type import TypeRef, ALL_TYPES

from .view import BaseView
from ..widgets.qtypedef import QCTypeDef
from ..dialogs.type_editor import CTypeEditor


class TypesView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('types', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Types'

        self._layout = None  # type: QVBoxLayout
        self._init_widgets()
        #self.reload()

    def _init_widgets(self):
        outer_layout = QVBoxLayout()
        scroll_area = QScrollArea()
        scroll_contents = QWidget()
        self._layout = QVBoxLayout()

        status_bar = QFrame()
        status_layout = QHBoxLayout()
        status_bar.setLayout(status_layout)

        new_btn = QPushButton("Add Types", self)
        new_btn.clicked.connect(self._on_new_type)
        status_layout.addWidget(new_btn)

        self._layout.addWidget(QLabel("Hello world", scroll_contents))

        scroll_area.setWidgetResizable(True)
        scroll_contents.setLayout(self._layout)
        scroll_area.setWidget(scroll_contents)
        outer_layout.addWidget(scroll_area)
        outer_layout.addWidget(status_bar)
        self.setLayout(outer_layout)


    def reload(self):
        for child in list(self._layout.parent().children()):
            if type(child) in (QLabel, QCTypeDef):
                self._layout.takeAt(0)
                self._layout.removeWidget(child)
                child.deleteLater()

        for ty in self.workspace.instance.kb.types.iter_own():
            widget = QCTypeDef(self._layout.parent(), ty, self.workspace.instance.kb.types)
            self._layout.addWidget(widget)



    def _on_new_type(self):
        dialog = CTypeEditor(
            None,
            self.workspace.instance.project.arch,
            multiline=True,
            allow_multiple=True,
            predefined_types=self.workspace.instance.kb.types
        )
        dialog.exec_()

        for name, ty in dialog.result:
            if name.startswith('struct '):
                name = name[7:]
            elif name.startswith('union '):
                name = name[6:]
            if name in self.workspace.instance.kb.types:
                if name in ALL_TYPES:
                    QMessageBox.warning(None, "Redefined builtin", f'Type {name} is a builtin and cannot be redefined')
                else:
                    self.workspace.instance.kb.types[name].type = ty
            else:
                new_ref = TypeRef(name, ty)
                self.workspace.instance.kb.types[name] = new_ref

        self.reload()
