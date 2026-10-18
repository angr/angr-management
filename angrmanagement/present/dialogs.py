"""
The small dialogs, as forms both frontends can show, and the rules the Qt dialogs check with.

Each ``*_form`` function builds the :class:`~angrmanagement.present.forms.Form` of one Qt dialog: the same fields,
the same status line and the same rule for when OK may be pressed. The rules are plain functions
(:func:`address_of_text`, :func:`label_name`, :func:`assemble_patch`, :func:`hook_templates`, ...) that the Qt dialogs
call too, so the two frontends accept the same input.
"""

from __future__ import annotations

import ast
import base64
import contextlib
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Any

from archinfo import ArchError

from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.data.load_options import key_to_hex

from .forms import Form, FormAction, FormCheck, FormField, valid_status

if TYPE_CHECKING:
    from collections.abc import Callable

    from angr.knowledge_plugins.functions import Function

    from angrmanagement.data.instance import Instance

try:
    import keystone
except ImportError:  # pragma: no cover - keystone is a dependency of angr's patching
    keystone = None


#
# Addresses and labels
#


def address_of_text(instance: Instance, text: str) -> int | None:
    """
    The address the user typed into an address box: a hexadecimal number (with or without 0x), the name of a
    function, or a label, tried in that order. QAddressInput and the terminal's Jump to screen both accept this.
    """
    text = text.strip()
    with contextlib.suppress(ValueError):
        return int(text, 16)
    if instance.project.am_none or not text:
        return None
    kb = instance.project.kb
    func = kb.functions.function(name=text, create=False)
    if func is not None:
        return func.addr
    for addr, name in kb.labels.items():
        if name == text:
            return addr
    return None


def label_name(text: str) -> str | None:
    """A label name from what the user typed, stripped; None if it has a space inside. Empty means the default."""
    if not text or (text and " " not in text.strip()):
        return text.strip()
    return None


def jump_to_form(instance: Instance) -> Form:
    """The Jump to address dialog: an address box that says whether what is typed is an address."""
    return Form(
        "Jump to address",
        [FormField("address", "Address")],
        check=lambda values: valid_status(address_of_text(instance, values["address"]) is not None),
    )


def rename_label_target(kb, label_addr: int) -> tuple[str, str]:
    """What a label rename renames at ``label_addr``: ``("function", name)`` or ``("label", current label)``."""
    if kb.functions.contains_addr(label_addr):
        return "function", kb.functions.get_by_addr(label_addr).name
    return "label", kb.labels.get(label_addr, "")


def rename_label_form(label_addr: int, text: str) -> Form:
    """The Rename Label dialog: the new name, which may not have spaces in it."""
    return Form(
        f"Rename Label at {label_addr:#08x}",
        [FormField("name", "New name", value=text)],
        check=lambda values: valid_status(label_name(values["name"]) is not None),
    )


def set_comment_form(text: str) -> Form:
    """The Set Comment dialog: several lines; Ctrl+Enter accepts."""
    return Form("Set Comment", [FormField("comment", "Comment text", "multiline", text)])


#
# Encryption keys
#


class EncKeyFormat(IntEnum):
    """
    The format that an encryption key is entered in.
    """

    BASE64 = 0
    BYTESTRING = 1
    ASCII = 2
    HEX = 3


def parse_hex_key(txt: str) -> bytes | None:
    """A hexadecimal key, with an optional 0x prefix and whitespace, ':' or '-' between the digits; None if not one."""
    digits = txt.strip()
    if digits[:2].lower() == "0x":
        digits = digits[2:]
    for separator in " \t:-":
        digits = digits.replace(separator, "")
    if not digits or len(digits) % 2 != 0:
        return None
    try:
        return bytes.fromhex(digits)
    except ValueError:
        return None


def parse_encryption_key(txt: str, key_format: EncKeyFormat | None = None) -> bytes | None:
    """
    The key the user typed, in ``key_format``, or with None the first of hex, Base64, a Python byte string and ASCII
    that reads it; None if it reads as none of them.
    """
    if not txt:
        return None
    # parse it as a hexadecimal string. this is attempted before base64 because hex-shaped text is also valid
    # base64 more often than not, and it is far likelier to have been meant as hex.
    if key_format is None or key_format == EncKeyFormat.HEX:
        key = parse_hex_key(txt)
        if key is not None:
            return key
        if key_format == EncKeyFormat.HEX:
            return None
    if key_format is None or key_format == EncKeyFormat.BASE64:
        try:
            return base64.b64decode(txt, validate=True)
        except (ValueError, TypeError):
            pass
        if key_format == EncKeyFormat.BASE64:
            return None
    # parse it as a Python byte string. accept both a complete literal and the escaped content of one.
    if key_format is None or key_format == EncKeyFormat.BYTESTRING:
        candidates = [txt] if txt.startswith(('b"', "b'")) else []
        candidates.append(f'b"{txt}"')
        for candidate in candidates:
            try:
                key = ast.literal_eval(candidate)
            except (SyntaxError, ValueError, MemoryError, RecursionError):
                continue
            if isinstance(key, bytes):
                return key
        if key_format == EncKeyFormat.BYTESTRING:
            return None
    if key_format is None or key_format == EncKeyFormat.ASCII:
        try:
            return txt.encode("ascii")
        except UnicodeEncodeError:
            pass
    return None


ENCKEY_FORMAT_CHOICES = [
    ("Auto-detect", None),
    ("Hex", EncKeyFormat.HEX),
    ("Base64", EncKeyFormat.BASE64),
    ("Python byte string", EncKeyFormat.BYTESTRING),
    ("ASCII", EncKeyFormat.ASCII),
]


def encryption_key_form(prompt: str = "", initial_text: str = "", title: str = "Set an encryption key") -> Form:
    """The Set an encryption key dialog: the key's format, the key, and the bytes it reads as."""

    def check(values: dict[str, Any]) -> FormCheck:
        key = parse_encryption_key(values["key"], values["format"])
        if key is None:
            return FormCheck(False, "Invalid", {"as_bytes": "Key in byte string: ", "as_hex": "Key in bytes: "})
        return FormCheck(
            True, "Valid", {"as_bytes": f"Key in byte string: {key!r}", "as_hex": f"Key in hex: {key_to_hex(key)}"}
        )

    return Form(
        title,
        [
            FormField("format", "Key format", "radio", None, ENCKEY_FORMAT_CHOICES),
            FormField("key", "Encryption key", value=initial_text),
            FormField("as_bytes", "", "label", "Key in byte string: "),
            FormField("as_hex", "", "label", "Key in bytes: "),
        ],
        text=(prompt + "\n" if prompt else "")
        + "Please provide an encryption key (in the form of a hexadecimal string, a Base64-encoded string, a Python "
        "byte string, or an ASCII string):",
        check=check,
    )


def key_of_form(values: dict[str, Any] | None) -> bytes | None:
    """The key an encryption key form was accepted with, or None."""
    return None if values is None else parse_encryption_key(values["key"], values["format"])


#
# Breakpoints
#

BREAKPOINT_TYPE_CHOICES = [
    ("Execute", BreakpointType.Execute),
    ("Write", BreakpointType.Write),
    ("Read", BreakpointType.Read),
]


def breakpoint_size(text: str) -> int | None:
    """The size the Edit Breakpoint dialog reads: a number in any base Python accepts; None if it is not one."""
    try:
        return int(text, 0)
    except ValueError:
        return None


def breakpoint_form(bp: Breakpoint, instance: Instance) -> Form:
    """The Edit Breakpoint dialog: what to break on, the address, the size and a comment."""
    return Form(
        "Edit Breakpoint",
        [
            FormField("type", "Break on:", "radio", bp.type, BREAKPOINT_TYPE_CHOICES),
            FormField("addr", "Address:", value=f"{bp.addr:#x}"),
            FormField("size", "Size:", value=f"{bp.size:#x}"),
            FormField("comment", "Comment:", value=bp.comment),
        ],
        check=lambda values: valid_status(
            address_of_text(instance, values["addr"]) is not None and bool(breakpoint_size(values["size"]))
        ),
    )


def apply_breakpoint(bp: Breakpoint, values: dict[str, Any], instance: Instance) -> None:
    """Change ``bp`` to what the breakpoint form says."""
    bp.type = values["type"]
    addr = address_of_text(instance, values["addr"])
    size = breakpoint_size(values["size"])
    if addr is not None:
        bp.addr = addr
    if size:
        bp.size = size
    bp.comment = values["comment"]


#
# Patches
#


@dataclass
class AssembledPatch:
    """What assembling a patch gave: the bytes, the status line, and whether the patch can be made."""

    new_bytes: bytes
    message: str
    ok: bool


class PatchAssembler:
    """
    The Assemble Patch dialog's logic: the instruction at ``addr``, its bytes, and assembling text in its place with
    keystone, padded with NOPs to the original size if asked.
    """

    def __init__(self, instance: Instance, addr: int) -> None:
        self.instance = instance
        self.addr = addr
        block = instance.project.factory.block(addr)
        insn = block.disassembly.insns[0]
        self.original_bytes: bytes = block.bytes[: insn.size]
        self.initial_text = insn.mnemonic + (" " + insn.op_str if insn.op_str else "")
        #: whether keystone can assemble for this architecture, and if not, why (it may not say)
        self.can_assemble = False
        self.unavailable = ""
        if keystone is None:
            self.unavailable = "Keystone not installed"
        else:
            try:
                self.can_assemble = instance.project.arch.keystone is not None
            except ArchError as e:
                self.unavailable = str(e)

    def assemble(self, text: str, pad: bool) -> AssembledPatch:
        """Assemble ``text`` at the address, as the dialog does on every keystroke."""
        if not self.can_assemble:
            return AssembledPatch(self.original_bytes, self.unavailable, False)
        message = ""
        try:
            ks = self.instance.project.arch.keystone
            new_bytes = (ks.asm(text, self.addr, as_bytes=True)[0] or b"") if text else b""
            delta = len(self.original_bytes) - len(new_bytes)
            if delta > 0:
                if pad:
                    nop = self.instance.project.arch.nop_instruction
                    new_bytes += (delta // len(nop)) * nop
                    if len(self.original_bytes) - len(new_bytes):
                        message = "Warning: Unable to completely pad remainder"
                else:
                    message = "Warning: Patch is shorter than original instruction"
            elif delta < 0:
                message = "Warning: Patch exceeds original instruction length"
        except Exception as ks_error:  # pylint:disable=broad-exception-caught
            # keystone.KsError, which unavailable() has made sure can be raised
            if keystone is None or not isinstance(ks_error, keystone.KsError):
                raise
            return AssembledPatch(b"", "Error: " + ks_error.message, False)
        return AssembledPatch(new_bytes, message, len(new_bytes) > 0)

    def apply(self, new_bytes: bytes) -> None:
        """Put ``new_bytes`` at the address in place of any patch there, unless they are the original bytes."""
        from angr.knowledge_plugins.patches import Patch  # pylint:disable=import-outside-toplevel

        if new_bytes == self.original_bytes:
            return
        pm = self.instance.project.kb.patches
        patches: Any = self.instance.patches
        existing = pm.get_patch(self.addr)
        if existing:
            patches.remove_patch(existing.addr)
            patches.am_event(removed={existing})
        patch = Patch(self.addr, new_bytes)
        pm.add_patch_obj(patch)
        patches.am_event(added={patch})

    def form(self) -> Form:
        """The Assemble Patch dialog: the assembly, the bytes it makes, and whether to pad."""

        def check(values: dict[str, Any]) -> FormCheck:
            result = self.assemble(values["asm"], values["pad"])
            return FormCheck(result.ok, result.message, {"bytes": result.new_bytes.hex(" ")})

        return Form(
            f"Assemble Patch at {self.addr:#x}",
            [
                FormField("asm", "Assembly:", value=self.initial_text, readonly=not self.can_assemble),
                FormField("bytes", "Bytes:", "label", self.original_bytes.hex(" ")),
                FormField("pad", "", "bool", True, description="Pad to original instruction size"),
            ],
            check=check,
        )


#
# Hooks
#


def hook_templates(addr: int) -> dict[str, str]:
    """The hook dialog's presets for a hook at ``addr``, by name."""
    a = hex(addr)
    return {
        "base": f"""\
@project.hook(addr={a}, length=0)
def hook(state):
    ...""",
        "assertion": f"""\
@project.hook(addr={a}, length=0)
def assertion(state):
    state.add_constraints(
        ...
    )""",
        "disable unicorn": f"""\
@project.hook(addr={a}, length=0)
def disable_unicorn(state):
    state.options.discard("UNICORN")
    state.options.discard("UNICORN_HANDLE_TRANSMIT_SYSCALL")
    state.options.discard("UNICORN_SYM_REGS_SUPPORT")
    state.options.discard("UNICORN_TRACK_BBL_ADDRS")
    state.options.discard("UNICORN_TRACK_STACK_POINTERS")
""",
        "enable unicorn": f"""\
@project.hook(addr={a}, length=0)
def enable_unicorn(state):
    state.options.add("UNICORN")
    state.options.add("UNICORN_HANDLE_TRANSMIT_SYSCALL")
    state.options.add("UNICORN_SYM_REGS_SUPPORT")
    state.options.add("UNICORN_TRACK_BBL_ADDRS")
    state.options.add("UNICORN_TRACK_STACK_POINTERS")
""",
    }


def hook_form(addr: int) -> Form:
    """The Change hook dialog: pick a preset, edit the code, and OK appends it to the console."""
    templates = hook_templates(addr)
    names = sorted(templates)

    def on_change(key: str, values: dict[str, Any]) -> dict[str, Any] | None:
        if key == "preset" and values["preset"] in templates:
            return {"code": templates[values["preset"]]}
        return None

    return Form(
        "Change hook",
        [
            FormField("preset", "Presets:", "radio", None, [(name, name) for name in names]),
            FormField("code", "", "code", ""),
        ],
        text=f"Hook at address {hex(addr)}:",
        ok_text="Append to Console",
        on_change=on_change,
    )


#
# Function documentation, information and dependencies
#


def library_docs() -> Any:
    """The library documentation, loaded from ``library_docs_root`` the first time it is needed in a frontend that did
    not load it at start (the Qt main window does)."""
    from angrmanagement.config import Conf  # pylint:disable=import-outside-toplevel
    from angrmanagement.data.library_docs import LibraryDocs  # pylint:disable=import-outside-toplevel
    from angrmanagement.logic import GlobalInfo  # pylint:disable=import-outside-toplevel

    if GlobalInfo.library_docs is None:
        docs = LibraryDocs()
        if Conf.library_docs_root:
            docs.load_func_docs(Conf.library_docs_root)
        GlobalInfo.library_docs = docs
    return GlobalInfo.library_docs


def func_doc_target(insn: Any) -> tuple[int, str, tuple[str, str, str]] | None:
    """
    What the function documentation dialog shows for a call instruction (an InsnNode or a QInstruction): the
    target's address, the callee's name as the operand shows it, and (doc, url, type) from the library docs; None
    when the instruction is not a call with one target.
    """
    if insn is None or getattr(insn.insn, "type", None) != "call" or insn.out_branch is None:
        return None
    targets = insn.out_branch.targets
    if len(targets) != 1:
        return None
    target = next(iter(targets))
    operand = insn.get_operand(0)
    name = operand.text if operand is not None else ""
    doc_tuple = library_docs().get_docstring_for_func_name(name)
    if doc_tuple is None:
        doc_tuple = (f"Cannot find local documentation for function {name}.", "http://", "<>")
    return target, name, doc_tuple


def func_doc_form(addr: int, name: str, doc_tuple: tuple[str, str, str]) -> Form:
    """The Function Documentation dialog: which function, its type, the documentation and its URL."""
    doc, url, ftype = (part.strip() for part in doc_tuple)
    return Form(
        "Function Documentation",
        [
            FormField("type", "", "label", f"Type: {ftype}"),
            FormField("doc", "", "multiline", doc, readonly=True),
            FormField("url", "", "link", url),
        ],
        text=f"Function at address {hex(addr)}: {name}",
        ok_text="Close",
    )


def function_info_rows(function: Function) -> list[tuple[str, Any]]:
    """The Function dialog's rows: text facts, then the flags shown as check boxes."""
    prototype = function.prototype.c_repr(full=True).replace("()", function.name, 1) + ";" if function.prototype else ""
    return [
        ("Name", function.name),
        ("Address", f"{function.addr:x}"),
        ("Binary", f"{function.binary}"),
        ("Offset", f"{function.offset:x}"),
        (
            "Calling Convention",
            "<Unknown>" if function.calling_convention is None else f"{function.calling_convention}",
        ),
        ("Tags", ", ".join(function.tags)),
        ("Cyclomatic Complexity", str(function.cyclomatic_complexity)),
        ("C Prototype", prototype),
        ("Alignment", function.is_alignment),
        ("PLT", function.is_plt),
        ("SimProcedure", function.is_simprocedure),
        ("Returning", function.returning),
        ("Prototype Guessed", function.is_prototype_guessed),
        ("Variadic", function.prototype is not None and function.prototype.variadic),
    ]


def function_info_form(function: Function, actions: list[tuple[str, Callable[[], Any]]]) -> Form:
    """The Function dialog: what is known about the function, read-only, and its actions (each closes it)."""

    def run(action: Callable[[], Any]) -> Callable[[dict[str, Any]], bool]:
        def go(_values: dict[str, Any]) -> bool:
            action()
            return True

        return go

    fields = [
        FormField(f"row{idx}", label, "bool" if isinstance(value, bool) else "label", value, readonly=True)
        for idx, (label, value) in enumerate(function_info_rows(function))
    ]
    return Form(
        f"Function {function.name}",
        fields,
        ok_text="Close",
        actions=[FormAction(caption, run(action)) for caption, action in actions],
    )


def function_actions(workspace, function: Function, show_xrefs: Callable[[], Any]) -> list[tuple[str, Callable]]:
    """The Function dialog's four actions: decompile, disassemble, the cross-references and the strings."""

    def show_strings() -> None:
        workspace.show_strings_view()
        view = workspace.view_manager.first_view_in_category("strings")
        select = getattr(view, "select_function", None)
        if select is not None:
            select(function)

    return [
        ("&Decompile", lambda: workspace.decompile_function(function)),
        ("Dis&assemble", lambda: workspace.jump_to(function.addr)),
        ("Show &Xrefs", show_xrefs),
        ("Show &Strings", show_strings),
    ]


def depends_on_form(function: Function | None) -> Form:
    """The Depends On dialog: where to look and which argument of the function to track."""
    from angr.knowledge_plugins.key_definitions.constants import (  # pylint:disable=import-outside-toplevel
        OP_AFTER,
        OP_BEFORE,
    )

    from angrmanagement.utils.func import function_prototype_str  # pylint:disable=import-outside-toplevel

    def check(values: dict[str, Any]) -> FormCheck:
        try:
            int(values["arg"])
        except ValueError:
            return FormCheck(
                False, f'The given function argument index "{values["arg"]}" is unsupported. Only integers are allowed.'
            )
        return FormCheck(True)

    return Form(
        "Depends on",
        [
            FormField("instruction", "Instruction", "label", "TODO"),
            FormField("function", "Function", "label", function_prototype_str(function) if function else "TODO"),
            FormField(
                "location",
                "Location",
                "radio",
                OP_BEFORE,
                [("Before the instruction", OP_BEFORE), ("After the instruction", OP_AFTER)],
            ),
            FormField("atom", "Target atom", "radio", "arg", [("Function argument", "arg")]),
            FormField("arg", "Argument index", value="0"),
        ],
        check=check,
    )


__all__ = [
    "BREAKPOINT_TYPE_CHOICES",
    "ENCKEY_FORMAT_CHOICES",
    "EncKeyFormat",
    "encryption_key_form",
    "key_of_form",
    "parse_encryption_key",
    "parse_hex_key",
    "AssembledPatch",
    "PatchAssembler",
    "address_of_text",
    "apply_breakpoint",
    "breakpoint_form",
    "breakpoint_size",
    "depends_on_form",
    "func_doc_form",
    "func_doc_target",
    "function_actions",
    "function_info_form",
    "function_info_rows",
    "hook_form",
    "hook_templates",
    "jump_to_form",
    "label_name",
    "rename_label_form",
    "rename_label_target",
    "set_comment_form",
]
