"""
The types view without a toolkit.

:func:`parse_types` reads C type definitions as the Qt type editor does, :func:`add_types` stores what it read in a
type store with the ``struct``/``union`` aliases the Qt view keeps, :func:`typedef_lines` gives the text of a type with
the offset of each member, and :func:`edit_typedef` and :func:`edit_field` apply an edited type or member.
:class:`TypesPresenter` is the view: the type store it shows (the project's, or a function's local types), its type
definitions, and adding and editing them through the frontend's type editor.
"""

from __future__ import annotations

import contextlib
import importlib
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

import pycparser.c_parser
from angr import sim_type
from angr.sim_type import ALL_TYPES, SimStruct, SimTypeBottom, SimUnion, TypeRef

from angrmanagement.logic import GlobalInfo

from .base import FunctionPresenter, project_of
from .keymap import Binding, Keymap

if TYPE_CHECKING:
    from collections.abc import Callable

    from angr.knowledge_plugins.types import TypesStore

    from angrmanagement.data.instance import Instance

# compatibility for pycparser 2.18 and 3.0: 3.0 has no plyparser
PycParseErrorCls: tuple[type[Exception], ...] = ()
with contextlib.suppress(ImportError):
    PycParseErrorCls += (importlib.import_module("pycparser.plyparser").ParseError,)

PycParseErrorCls += (pycparser.c_parser.ParseError,)
#: What reading C types raises for text the editor refuses: a parse error, or a type defined twice ("Redefining
#: body of struct b"), which the Qt editor let through as an exception.
_REFUSED = (*PycParseErrorCls, ValueError)

#: A type the editor read: its name (None, despite the annotation the Qt editor gave it, when it has none) and the type.
NamedType = tuple[str, sim_type.SimType]


@dataclass
class ParsedTypes:
    """
    What the type editor read: ``main`` (the types entered; empty when the text does not parse, or when it must hold
    one type and holds several), ``side`` (types defined along the way), and why the text was refused.
    """

    main: list[NamedType] = field(default_factory=list)
    side: list[NamedType] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.main)


def parse_types(text: str, arch, predefined_types=None, editing_single: str | None = None) -> ParsedTypes:
    """Read ``text`` as C type definitions or one declaration, as the Qt type editor does on every change."""
    result = None
    side_result = None
    error = ""
    try:
        side_typedefs: dict[str, Any] = {}
        defs, typedefs = sim_type.parse_file(
            text, predefined_types=predefined_types, arch=arch, side_effect_types=side_typedefs
        )
        result = list(typedefs.items()) + list(defs.items())
        side_result = [(name, ty) for name, ty in side_typedefs.items() if name not in typedefs and name not in defs]
    except PycParseErrorCls as ex:
        error = str(ex)
    except ValueError as ex:
        # a type defined twice: refused, since reading it as one type below would keep the first and drop the rest
        return ParsedTypes(error=str(ex))

    # hack. idk why our pycparser config will accept `typedef int` as the same as `int`
    if result is None and not text.strip().startswith("typedef"):
        try:
            side_typedefs = {}
            ty, name = sim_type.parse_type_with_name(
                text, predefined_types=predefined_types, arch=arch, side_effect_types=side_typedefs
            )
            result = [(name, ty)]
            side_result = [(name2, ty) for name2, ty in side_typedefs.items() if name2 != name]
        except _REFUSED as ex:
            error = str(ex)

    if not result:
        return ParsedTypes(error=error or "No type")
    if editing_single and len(result) != 1:
        return ParsedTypes(error=f"One type only: this defines {len(result)}")
    assert side_result is not None
    return ParsedTypes(result, side_result)


def stript(s: str) -> str:
    return s.removeprefix("struct ").removeprefix("union ")


def add_types(types_store: TypesStore, arch, parsed: ParsedTypes) -> None:
    """
    Store the types the editor read, each under its name (or a new one), with a ``struct``/``union`` alias for a
    struct or union, as the Qt view's "Add types" does. A type of that name is replaced.
    """
    for name, ty in parsed.main + parsed.side:
        if name in ALL_TYPES:
            continue
        if name is None and isinstance(ty, (SimStruct, SimUnion)) and ty.name != "<anon>":
            name = ty.name
        name = types_store.unique_type_name() if name is None else stript(name)

        new_ty = ty.type if isinstance(ty, TypeRef) else ty
        new_ref = ty if isinstance(ty, TypeRef) else TypeRef(name, ty).with_arch(arch)
        if name in types_store:
            new_ref = cast("TypeRef", types_store[name])
            new_ref.type = new_ty
        else:
            types_store[name] = new_ref

        sname = f"struct {name}"
        if isinstance(new_ty, SimStruct):
            if sname in types_store:
                cast("TypeRef", types_store[sname]).type = new_ty
            else:
                types_store[sname] = TypeRef(sname, new_ty).with_arch(arch)
        elif sname in types_store:
            types_store.pop(sname)

        uname = f"union {name}"
        if isinstance(new_ty, SimUnion):
            if uname in types_store:
                cast("TypeRef", types_store[uname]).type = new_ty
            else:
                types_store[uname] = TypeRef(uname, new_ty).with_arch(arch)
        elif uname in types_store:
            types_store.pop(uname)


def own_typedefs(types_store: TypesStore) -> list[TypeRef]:
    """The types the store defines itself, without the ``struct``/``union`` aliases of its structs and unions."""
    already_repped = {
        f"struct {ty.name}" if isinstance(ty.type, SimStruct) else f"union {ty.name}"
        for ty in types_store.iter_own()
        if isinstance(ty, TypeRef) and isinstance(ty.type, (SimStruct, SimUnion))
    }
    return [ty for ty in cast("list[TypeRef]", list(types_store.iter_own())) if ty.name not in already_repped]


def typedef_text(ty: TypeRef) -> str:
    """The C text of a type definition, as the type editor shows it to edit."""
    return f"typedef {ty.type.c_repr(name=ty.name, full=1)};"


def typedef_lines(ty: TypeRef) -> list[str]:
    """
    The lines the types view shows for ``ty``: each line of its C text after the offset of what it declares, in hex
    (the size of the type on the first and the last line of a struct).
    """
    arch = ty._arch  # pylint: disable=protected-access
    if arch is None:
        raise TypeError("Must provide SimTypes with arches to QTypeDef")

    lines = typedef_text(ty).split("\n")
    fields = None
    offsets = None
    for i, line in enumerate(lines):
        type_size = ty.size if not isinstance(ty.type, SimTypeBottom) else 0
        if i == 0:
            prefix = f"{type_size // arch.byte_width:08x}"
        elif isinstance(ty.type, SimUnion):
            prefix = "00000000"
        elif isinstance(ty.type, SimStruct):
            fieldno = i - 1
            if fields is None:
                fields = list(ty.type.fields)
                offsets = ty.type.offsets
            assert offsets is not None
            if fieldno < len(fields):
                prefix = f"{offsets[fields[fieldno]]:08x}"
            else:
                prefix = f"{type_size // arch.byte_width:08x}"
        else:
            raise TypeError(f"I don't know why a {type(ty.type)} renders with more than one line")

        lines[i] = f"{prefix}  {line}"
    return lines


def edit_typedef(all_types: TypesStore, ty: TypeRef, parsed: ParsedTypes) -> str | None:
    """
    Make ``ty`` the type the editor read, renamed if the editor gave it another name. Returns a warning when that name
    is taken (the type changes, the name does not).
    """
    if not parsed.main:
        return None
    warning = None
    name, new_ty = parsed.main[0]
    if name is not None and stript(name) != stript(ty.name):
        if name in all_types:
            warning = f"The name {name} is already taken."
        else:
            # TODO handle the struct/union aliases properly
            all_types.rename(ty.name, stript(name))
    ty.type = new_ty
    return warning


def _fields_of(ty) -> OrderedDict:
    if isinstance(ty, sim_type.SimStruct):
        fields = ty.fields
    elif isinstance(ty, sim_type.SimUnion):
        fields = ty.members
    else:
        raise TypeError(f"Can't edit a field of a {type(ty)}")
    if type(fields) is not OrderedDict:
        raise TypeError(f"Struct or union's fields are of type {type(fields)} - that's bad")
    return fields


def field_number(ty, field_spec: int | str) -> int:
    """The index of a member of a struct or union, named or numbered; IndexError or KeyError when there is none."""
    fields = _fields_of(ty)
    fields_list = list(fields.items())
    if isinstance(field_spec, int):
        if not 0 <= field_spec < len(fields):
            raise IndexError(field_spec)
        return field_spec
    if isinstance(field_spec, str):
        try:
            return [i for i, (name, _) in enumerate(fields_list) if name == field_spec][0]
        except IndexError:
            raise KeyError(field_spec) from None
    raise TypeError(f"Field specifier is a {type(field_spec)} - that's bad")


def field_text(ty, fieldno: int) -> tuple[str, str]:
    """The name of member ``fieldno`` and its declaration, as the member editor shows it."""
    name, subty = list(_fields_of(ty).items())[fieldno]
    return name, subty.c_repr(name=name)


def set_field(ty, fieldno: int, parsed: ParsedTypes) -> tuple[bool, str | None]:
    """
    Make member ``fieldno`` of the struct or union ``ty`` the declaration the editor read. Returns whether it changed
    and a warning when the new name is taken (the type changes, the name does not).
    """
    if not parsed.main:
        return False, None
    fields = _fields_of(ty)
    fields_list = list(fields.items())
    name, _subty = fields_list[fieldno]
    name2, subty = parsed.main[0]
    warning = None
    if name2 is not None:
        if name != name2 and name2 in fields:
            warning = f"The name {name2} is already used"
        else:
            name = name2
    fields_list[fieldno] = (name, subty)

    if isinstance(ty, sim_type.SimStruct):
        ty.fields = OrderedDict(fields_list)
    else:
        ty.members = OrderedDict(fields_list)
    return True, warning


def types_keymap() -> Keymap:
    """The types view's keys; the Qt view has none, its buttons and a double click do these."""
    return Keymap(
        "types",
        [
            Binding("Return", "edit_line", "Edit the type or the member on the line (a double click)"),
            Binding("A", "add_types", "Add types"),
            Binding("P", "show_persistent_types", "Show the persistent (global) types"),
        ],
    )


class TypesPresenter(FunctionPresenter):
    """
    The types view: the project's types, or a function's local types once a function is set. The frontend sets
    :attr:`type_editor`, which asks for C types: ``type_editor(title, text, multiline, editing_single, predefined,
    then)`` calls ``then`` with the :class:`ParsedTypes`, or None when cancelled.
    """

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "types", instance, default_docking_position)
        self.base_caption = "Types"
        self.typedefs: list[TypeRef] = []
        self.function.am_subscribe(self.reload)
        #: called after the type definitions changed
        self.on_reloaded: Callable[[], None] | None = None
        #: the frontend's type editor; without one nothing is asked
        self.type_editor: Callable[..., None] = self._no_type_editor

    @property
    def keymap(self) -> Keymap:
        return types_keymap()

    @property
    def current_typestore(self) -> TypesStore:
        kb = self.instance.kb
        assert kb is not None
        if self.function.am_none:
            return kb.types
        return kb.dec_variables[self.function.addr].types

    @property
    def arch(self):
        project = project_of(self.instance)
        return project.arch if project is not None else None

    def caption_text(self) -> str:
        if self.instance.project.am_none:
            return "Types View"
        if self.function.am_none:
            return "Persistent (global) variable types"
        return f"Temporary (local) variable types for function {self.function.addr:#x}"

    def reload(self, **_kwargs) -> None:
        self.typedefs = [] if self.instance.project.am_none else own_typedefs(self.current_typestore)
        if self.on_reloaded is not None:
            self.on_reloaded()

    def lines(self) -> list[tuple[int, int, str]]:
        """Every line shown: (type index, line of the type, text), with an empty line (-1, -1, "") between types."""
        out: list[tuple[int, int, str]] = []
        for idx, ty in enumerate(self.typedefs):
            if idx:
                out.append((-1, -1, ""))
            out.extend((idx, row, text) for row, text in enumerate(typedef_lines(ty)))
        return out

    def show_persistent_types(self) -> None:
        self.function = None

    def _ask(self, title: str, text: str, multiline: bool, editing_single: str | None, then) -> None:
        kb = self.instance.kb
        if kb is not None:
            self.type_editor(title, text, multiline, editing_single, kb.types, then)

    def _no_type_editor(self, *_args) -> None:
        """A frontend that has not given its type editor asks nothing."""

    def add_types(self) -> None:
        """Ask for C type definitions and add them to the type store shown."""
        if self.instance.project.am_none:
            return

        def then(parsed: ParsedTypes | None) -> None:
            if parsed is not None and parsed.ok:
                add_types(self.current_typestore, self.arch, parsed)
                self.reload()

        self._ask("Type editor", "", True, None, then)

    def edit_line(self, type_index: int, row: int) -> None:
        """
        Edit what line ``row`` of type ``type_index`` declares: a member of a struct or union, or (on its first line,
        or for a type without members) the whole type.
        """
        if not 0 <= type_index < len(self.typedefs):
            return
        ty = self.typedefs[type_index]
        if row != 0:
            try:
                fieldno = field_number(ty.type, row - 1)
            except (IndexError, TypeError):
                pass
            else:
                self.edit_member(ty, fieldno)
                return

        def then(parsed: ParsedTypes | None) -> None:
            if parsed is None or not parsed.ok:
                return
            warning = edit_typedef(self.current_typestore, ty, parsed)
            if warning is not None:
                GlobalInfo.ui_services.message("warning", "Duplicate type name", warning)
            self.reload()

        self._ask("Type editor", typedef_text(ty), True, ty.name, then)

    def edit_member(self, ty: TypeRef, fieldno: int) -> None:
        name, text = field_text(ty.type, fieldno)

        def then(parsed: ParsedTypes | None) -> None:
            if parsed is None or not parsed.ok:
                return
            changed, warning = set_field(ty.type, fieldno, parsed)
            if warning is not None:
                GlobalInfo.ui_services.message("warning", "Duplicate field name", warning)
            if changed:
                self.reload()

        self._ask("Type editor", text, False, name, then)


__all__ = [
    "ParsedTypes",
    "PycParseErrorCls",
    "TypesPresenter",
    "add_types",
    "edit_typedef",
    "field_number",
    "field_text",
    "own_typedefs",
    "parse_types",
    "set_field",
    "typedef_lines",
    "typedef_text",
    "types_keymap",
]
