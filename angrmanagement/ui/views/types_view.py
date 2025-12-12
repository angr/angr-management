from __future__ import annotations

from typing import TYPE_CHECKING

from angr.sim_type import ALL_TYPES, SimStruct, SimUnion, TypeRef
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget

from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.ui.dialogs.type_editor import CTypeEditor
from angrmanagement.ui.widgets.qtypedef import QCTypeDef

from .view import FunctionView

if TYPE_CHECKING:
    from angr.knowledge_plugins.types import TypesStore
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class TypesView(FunctionView):
    """
    The view that lets you modify project.kb.types. Creates a QTypeDef for each type.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("types", workspace, default_docking_position, instance)

        self.base_caption = "Types"

        self._function = ObjectContainer(None, "Current function")
        self._function.am_subscribe(self.reload)

        self._layout: QVBoxLayout
        self._caption_label: QLabel
        self._init_widgets()
        self.typedefs: list[QCTypeDef] = []

        # display global types by default
        self.reload()

    #
    # Properties
    #

    @property
    def current_typestore(self) -> TypesStore:
        if self._function.am_none:
            assert self.instance.kb is not None
            return self.instance.kb.types
        assert self.instance.pseudocode_variable_kb is not None
        var_manager: VariableManagerInternal = self.instance.pseudocode_variable_kb.variables[self._function.addr]
        return var_manager.types

    #
    # Other methods
    #

    def _init_widgets(self) -> None:
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

    def reload(self) -> None:
        for child in list(self._layout.parent().children()):
            if type(child) is QCTypeDef:
                self._layout.takeAt(0)
                self._layout.removeWidget(child)
                child.deleteLater()
        self.typedefs.clear()

        if self.instance.project.am_none:
            self._caption_label.setText("Types View")
            return

        # update the display
        assert self.function is not None
        if self.function.am_none:
            self._caption_label.setText("Persistent (global) variable types")
        else:
            txt = f"Temporary (local) variable types for function {self.function.addr:#x}"
            self._caption_label.setText(txt)

        # Load persistent types or function-specific types from types store
        types_store = self.current_typestore
        already_repped = {
            f"struct {ty.name}" if isinstance(ty.type, SimStruct) else f"union {ty.name}"
            for ty in types_store.iter_own()
            if isinstance(ty, TypeRef) and isinstance(ty.type, (SimStruct, SimUnion))
        }
        for ty in types_store.iter_own():
            if ty.name in already_repped:
                continue
            widget = QCTypeDef(self._layout.parent(), ty, types_store, self)
            self._layout.insertWidget(self._layout.count() - 1, widget)
            self.typedefs.append(widget)

    def _on_new_type(self) -> None:
        assert self.instance.kb is not None
        dialog = CTypeEditor(
            None,
            self.instance.project.arch,
            multiline=True,
            predefined_types=self.instance.kb.types,
        )
        dialog.exec_()

        types_store = self.current_typestore

        for name, ty in dialog.main_result + dialog.side_result:
            if name in ALL_TYPES:
                continue
            if name is None and isinstance(ty, (SimStruct, SimUnion)) and ty.name != "<anon>":
                name = ty.name
            if name is None:
                name = types_store.unique_type_name()
            else:
                name = name.removeprefix("struct ").removeprefix("union ")

            new_ty = ty.type if isinstance(ty, TypeRef) else ty
            new_ref = ty if isinstance(ty, TypeRef) else TypeRef(name, ty).with_arch(self.instance.project.arch)
            if name in types_store:
                new_ref = types_store[name]
                new_ref.type = new_ty
            else:
                types_store[name] = new_ref

            sname = f"struct {name}"
            if isinstance(new_ty, SimStruct):
                if sname in types_store:
                    types_store[sname].type = new_ty
                else:
                    types_store[sname] = TypeRef(sname, new_ty).with_arch(self.instance.project.arch)
            elif sname in types_store:
                types_store.pop(sname)

            uname = f"union {name}"
            if isinstance(new_ty, SimUnion):
                if uname in types_store:
                    types_store[uname].type = new_ty
                else:
                    types_store[uname] = TypeRef(uname, new_ty).with_arch(self.instance.project.arch)
            elif uname in types_store:
                types_store.pop(uname)

        # reload
        self.reload()

    def _on_persistent_types_clicked(self) -> None:
        self.function = None
