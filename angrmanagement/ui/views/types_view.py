from typing import TYPE_CHECKING

from angr.sim_type import ALL_TYPES, SimStruct, SimUnion, TypeRef
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QMessageBox, QPushButton, QScrollArea, QVBoxLayout, QWidget

from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.ui.dialogs.type_editor import CTypeEditor
from angrmanagement.ui.widgets.qtypedef import QCTypeDef

from .view import BaseView

if TYPE_CHECKING:
    from angr.knowledge_plugins.types import TypesStore
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal


class TypesView(BaseView):
    """
    The view that lets you modify project.kb.types. Creates a QTypeDef for each type.
    """

    FUNCTION_SPECIFIC_VIEW = True

    def __init__(self, workspace, instance, default_docking_position, *args, **kwargs):
        super().__init__("types", workspace, instance, default_docking_position, *args, **kwargs)

        self.base_caption = "Types"

        self._function = ObjectContainer(None, "Current function")
        self._function.am_subscribe(self.reload)

        self._layout: QVBoxLayout = None
        self._caption_label: QLabel = None
        self._init_widgets()

        # display global types by default
        self.reload()

    #
    # Properties
    #

    @property
    def function(self) -> ObjectContainer:
        return self._function

    @function.setter
    def function(self, v):
        self._function.am_obj = v
        self._function.am_event()

    @property
    def current_typestore(self) -> "TypesStore":
        if self._function.am_none:
            return self.instance.kb.types
        var_manager: VariableManagerInternal = self.instance.pseudocode_variable_kb.variables[self._function.addr]
        return var_manager.types

    #
    # Other methods
    #

    def _init_widgets(self):
        outer_layout = QVBoxLayout()
        scroll_area = QScrollArea()
        scroll_contents = QWidget()
        self._layout = QVBoxLayout()

        self._caption_label = QLabel()
        outer_layout.addWidget(self._caption_label)

        status_bar = QFrame()
        status_layout = QHBoxLayout()
        status_bar.setLayout(status_layout)

        new_btn = QPushButton("Add types", self)
        new_btn.clicked.connect(self._on_new_type)
        status_layout.addWidget(new_btn)

        global_btn = QPushButton("Persistent types", self)
        global_btn.clicked.connect(self._on_persistent_types_clicked)
        status_layout.addWidget(global_btn)

        scroll_area.setWidgetResizable(True)
        scroll_contents.setLayout(self._layout)
        scroll_area.setWidget(scroll_contents)
        outer_layout.addWidget(scroll_area)
        outer_layout.addWidget(status_bar)
        self.setLayout(outer_layout)

        # add a stretch to layout so elements are top-aligned
        self._layout.addStretch()
        # background color
        # TODO: Support dark mode
        # scroll_contents.setStyleSheet("background-color: white;")

    def reload(self):
        for child in list(self._layout.parent().children()):
            if type(child) is QCTypeDef:
                self._layout.takeAt(0)
                self._layout.removeWidget(child)
                child.deleteLater()

        # update the display
        if self.function.am_none:
            self._caption_label.setText("Persistent (global) variable types")
        else:
            txt = f"Temporary (local) variable types for function {self.function.addr:#x}"
            self._caption_label.setText(txt)

        # Load persistent types or function-specific types from types store
        types_store = self.current_typestore
        for ty in types_store.iter_own():
            widget = QCTypeDef(self._layout.parent(), ty, types_store)
            self._layout.insertWidget(self._layout.count() - 1, widget)

    def _on_new_type(self):
        dialog = CTypeEditor(
            None,
            self.instance.project.arch,
            multiline=True,
            allow_multiple=True,
            predefined_types=self.instance.kb.types,
        )
        dialog.exec_()

        types_store = self.current_typestore

        for name, ty in dialog.result:
            if name is None and type(ty) in (SimStruct, SimUnion) and ty.name != "<anon>":
                name = ty.name
            if name is None:
                name = types_store.unique_type_name()
            if name.startswith("struct "):
                name = name[7:]
            elif name.startswith("union "):
                name = name[6:]
            if name in types_store:
                if name in ALL_TYPES:
                    QMessageBox.warning(None, "Redefined builtin", f"Type {name} is a builtin and cannot be redefined")
                else:
                    types_store[name].type = ty
            else:
                new_ref = TypeRef(name, ty)
                types_store[name] = new_ref

        # reload
        self.reload()

    def _on_persistent_types_clicked(self):
        self.function = None
