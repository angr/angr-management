import random

from PySide2.QtWidgets import QScrollArea, QWidget, QVBoxLayout, QFrame, QHBoxLayout, QPushButton, QMessageBox

from angr.sim_type import TypeRef, ALL_TYPES, SimStruct, SimUnion

from .view import BaseView
from ..widgets.qtypedef import QCTypeDef
from ..dialogs.type_editor import CTypeEditor

FRUITS = [
    'mango',
    'cherry',
    'banana',
    'papaya',
    'apple',
    'kiwi',
    'pineapple',
    'coconut',
    'peach',
    'honeydew',
    'cucumber',
    'pumpkin',
    'cantaloupe',
    'strawberry',
    'watermelon',
    'nectarine',
    'orange',
]

class TypesView(BaseView):
    """
    The view that lets you modify project.kb.types. Creates a QTypeDef for each type.
    """
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('types', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = 'Types'

        self._layout = None  # type: QVBoxLayout
        self._init_widgets()

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


        scroll_area.setWidgetResizable(True)
        scroll_contents.setLayout(self._layout)
        scroll_area.setWidget(scroll_contents)
        outer_layout.addWidget(scroll_area)
        outer_layout.addWidget(status_bar)
        self.setLayout(outer_layout)


    def reload(self):
        for child in list(self._layout.parent().children()):
            if type(child) is QCTypeDef:
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
            if name is None and type(ty) in (SimStruct, SimUnion) and ty.name != '<anon>':
                name = ty.name
            if name is None:
                for fruit in FRUITS:
                    if fruit not in self.workspace.instance.kb.types:
                        name = fruit
                        break
                else:
                    name = f'type_{random.randint(0x10000000, 0x100000000):x}'
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
