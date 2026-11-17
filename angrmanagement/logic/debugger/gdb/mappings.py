from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from .mi import RuntimeErrorBase


@dataclass(frozen=True)
class LoadSegment:
    """An ELF PT_LOAD segment in linked address coordinates."""

    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int


@dataclass(frozen=True)
class MemoryMapping:
    """One actual kernel mapping, including its backing-file identity."""

    start: int
    end: int
    permissions: str
    offset: int
    device: str
    inode: int
    path: str

    def as_dict(self) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "permissions": self.permissions,
            "offset": self.offset,
        }


def elf_load_segments(path: str) -> list[LoadSegment]:
    """Read the ELF program headers needed for relocation, without loading target code."""
    with open(path, "rb") as stream:
        header = stream.read(64)
        if len(header) < 52 or header[:4] != b"\x7fELF" or header[4] not in (1, 2) or header[5] not in (1, 2):
            raise RuntimeErrorBase(f"Runtime relocation currently requires ELF: {path}")
        endian = "<" if header[5] == 1 else ">"
        if header[4] == 2:
            if len(header) != 64:
                raise RuntimeErrorBase("Truncated ELF header")
            phoff = struct.unpack_from(endian + "Q", header, 32)[0]
            phentsize, phnum = struct.unpack_from(endian + "HH", header, 54)
            fmt = endian + "IIQQQQQQ"
        else:
            phoff = struct.unpack_from(endian + "I", header, 28)[0]
            phentsize, phnum = struct.unpack_from(endian + "HH", header, 42)
            fmt = endian + "IIIIIIII"
        size = struct.calcsize(fmt)
        file_size = os.fstat(stream.fileno()).st_size
        if phentsize < size or phnum == 0xFFFF or phoff + phentsize * phnum > file_size:
            raise RuntimeErrorBase("Invalid or unsupported ELF program header table")
        segments = []
        for index in range(phnum):
            stream.seek(phoff + index * phentsize)
            fields = struct.unpack(fmt, stream.read(size))
            if fields[0] != 1:
                continue
            if header[4] == 2:
                _, flags, offset, vaddr, _, filesz, memsz, _ = fields
            else:
                _, offset, vaddr, _, filesz, memsz, flags, _ = fields
            segments.append(LoadSegment(offset, vaddr, filesz, memsz, flags))
        if not segments:
            raise RuntimeErrorBase("ELF has no loadable segments")
        return segments


def elf_build_id(path: str) -> tuple[str | None, int | None]:
    """Return the GNU build ID as hex and its linked address, if present in PT_NOTE."""
    with open(path, "rb") as stream:
        header = stream.read(64)
        if len(header) < 52 or header[:4] != b"\x7fELF" or header[4] not in (1, 2) or header[5] not in (1, 2):
            raise RuntimeErrorBase("Cannot read an ELF build ID from this file")
        endian = "<" if header[5] == 1 else ">"
        if header[4] == 2:
            if len(header) != 64:
                raise RuntimeErrorBase("Truncated ELF header")
            phoff = struct.unpack_from(endian + "Q", header, 32)[0]
            phentsize, phnum = struct.unpack_from(endian + "HH", header, 54)
            fmt = endian + "IIQQQQQQ"
        else:
            phoff = struct.unpack_from(endian + "I", header, 28)[0]
            phentsize, phnum = struct.unpack_from(endian + "HH", header, 42)
            fmt = endian + "IIIIIIII"
        size = struct.calcsize(fmt)
        file_size = os.fstat(stream.fileno()).st_size
        if phentsize < size or phnum == 0xFFFF or phoff + phentsize * phnum > file_size:
            raise RuntimeErrorBase("Invalid ELF program header table")
        for index in range(phnum):
            stream.seek(phoff + index * phentsize)
            fields = struct.unpack(fmt, stream.read(size))
            if fields[0] != 4:
                continue
            offset, vaddr, filesz = (
                (fields[2], fields[3], fields[5]) if header[4] == 2 else (fields[1], fields[2], fields[4])
            )
            if filesz > 16 * 1024 * 1024 or offset + filesz > file_size:
                raise RuntimeErrorBase("Invalid ELF note segment")
            stream.seek(offset)
            notes = stream.read(filesz)
            cursor = 0
            while cursor + 12 <= len(notes):
                namesz, descsz, kind = struct.unpack_from(endian + "III", notes, cursor)
                name_start = cursor + 12
                desc_start = name_start + (namesz + 3) // 4 * 4
                next_note = desc_start + (descsz + 3) // 4 * 4
                if next_note > len(notes):
                    raise RuntimeErrorBase("Truncated ELF note")
                if kind == 3 and notes[name_start : name_start + namesz].rstrip(b"\0") == b"GNU":
                    return notes[desc_start : desc_start + descsz].hex(), vaddr + desc_start
                cursor = next_note
    return None, None


def parse_proc_maps(text: str) -> list[MemoryMapping]:
    mappings = []
    pattern = re.compile(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+(\S+)\s+(\d+)\s*(.*)$")
    for line in text.splitlines():
        match = pattern.match(line)
        if match is None:
            raise RuntimeErrorBase(f"Cannot parse process mapping: {line[:120]}")
        start, end, permissions, offset, device, inode, path = match.groups()
        path = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), path)
        mappings.append(
            MemoryMapping(int(start, 16), int(end, 16), permissions, int(offset, 16), device, int(inode), path)
        )
    return mappings


def load_bias(mappings: list[MemoryMapping], segments: list[LoadSegment], page_size: int = 4096) -> int:
    """Match file offsets to PT_LOAD addresses, including split RELRO and nonzero image bases."""
    candidates: set[int] | None = None
    for mapping in mappings:
        possible = set()
        for segment in segments:
            file_start = segment.offset // page_size * page_size
            file_end = (segment.offset + segment.filesz + page_size - 1) // page_size * page_size
            if not file_start <= mapping.offset < file_end:
                continue
            if "x" in mapping.permissions and not segment.flags & 1:
                continue
            if "w" in mapping.permissions and not segment.flags & 2:
                continue
            linked_start = segment.vaddr // page_size * page_size + mapping.offset - file_start
            possible.add(mapping.start - linked_start)
        if not possible:
            raise RuntimeErrorBase("A mapped file range does not match an ELF load segment")
        candidates = possible if candidates is None else candidates & possible
    if not candidates or len(candidates) != 1:
        raise RuntimeErrorBase("The module load bias is ambiguous or inconsistent with its ELF program headers")
    return candidates.pop()


def local_modules(pid: int, generation: int) -> tuple[list[dict], list[dict]]:
    """Inspect the target process, checking device/inode identity before trusting local ELF headers."""
    try:
        mappings = parse_proc_maps(Path(f"/proc/{pid}/maps").read_text(encoding="utf-8", errors="surrogateescape"))
    except OSError as exc:
        raise RuntimeErrorBase(f"Cannot read process mappings for PID {pid}: {exc}") from exc
    groups: dict[tuple[str, str, int], list[MemoryMapping]] = {}
    for mapping in mappings:
        if mapping.inode and mapping.path.startswith("/"):
            groups.setdefault((mapping.path, mapping.device, mapping.inode), []).append(mapping)
    page_size = os.sysconf("SC_PAGE_SIZE")
    modules = []
    for (path, device, inode), ranges in groups.items():
        module = {
            "id": f"{generation}:{device}:{inode}",
            "path": path,
            "start": min(item.start for item in ranges),
            "end": max(item.end for item in ranges),
            "load_bias": None,
            "linked_base": None,
            "ranges": [item.as_dict() for item in ranges],
            "error": None,
            "build_id": None,
            "build_id_vaddr": None,
        }
        try:
            # A replaced/deleted file at the same pathname is not the running image.
            stat = os.stat(path)
            major, minor = (int(part, 16) for part in device.split(":"))
            if stat.st_ino != inode or os.major(stat.st_dev) != major or os.minor(stat.st_dev) != minor:
                raise RuntimeErrorBase("The file on disk is not the mapped module (device/inode mismatch)")
            segments = elf_load_segments(path)
            module["build_id"], module["build_id_vaddr"] = elf_build_id(path)
            bias = load_bias(ranges, segments, page_size)
            linked_base = min(segment.vaddr // page_size * page_size for segment in segments)
            module["load_bias"] = bias
            module["linked_base"] = linked_base
            module["start"] = bias + linked_base
            # Anonymous tails contain zero-filled .bss; include only actual mappings overlapping PT_LOAD.
            for mapping in mappings:
                if mapping.path or mapping.inode:
                    continue
                for segment in segments:
                    start = max(mapping.start, bias + segment.vaddr)
                    end = min(mapping.end, bias + segment.vaddr + segment.memsz)
                    if start < end:
                        tail = mapping.as_dict()
                        tail.update(start=start, end=end)
                        module["ranges"].append(tail)
            module["end"] = max(item["end"] for item in module["ranges"])
        except (OSError, ValueError, struct.error, RuntimeErrorBase) as exc:
            module["error"] = str(exc)
        modules.append(module)
    return modules, [dict(item.as_dict(), path=item.path) for item in mappings]


def select_module(modules: list[dict], executable: str | None, module_id: str | None) -> dict:
    if module_id is None:
        if not executable:
            raise RuntimeErrorBase("No executable selected; choose a module explicitly")
        wanted = os.path.realpath(executable)
        matches = [module for module in modules if os.path.realpath(module["path"]) == wanted]
    else:
        matches = [
            module
            for module in modules
            if module_id == module["id"] or os.path.realpath(module_id) == os.path.realpath(module["path"])
        ]
    if len(matches) != 1:
        raise RuntimeErrorBase("Module mapping is unavailable or ambiguous; refresh and select an exact module")
    module = matches[0]
    if module["load_bias"] is None or module["linked_base"] is None:
        raise RuntimeErrorBase(module["error"] or "Module relocation is unavailable")
    return module


def static_to_runtime(module: dict, address: int, static_base: int) -> int:
    runtime = module["load_bias"] + module["linked_base"] + address - static_base
    if not any(region["start"] <= runtime < region["end"] for region in module["ranges"]):
        raise RuntimeErrorBase("The analysis address does not belong to a mapped range in this module")
    return runtime


def runtime_to_static(module: dict, address: int, static_base: int) -> int:
    if not any(region["start"] <= address < region["end"] for region in module["ranges"]):
        raise RuntimeErrorBase("The runtime address does not belong to a mapped range in this module")
    return static_base + address - module["load_bias"] - module["linked_base"]
