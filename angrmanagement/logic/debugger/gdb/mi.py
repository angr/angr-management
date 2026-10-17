from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

_l = logging.getLogger(__name__)


class RuntimeErrorBase(Exception):
    """A debugger failure that can be shown directly to the user."""


class MIError(RuntimeErrorBase):
    """GDB rejected a command or its transport failed."""


@dataclass
class MIRecord:
    """One parsed result, asynchronous notification, or stream record."""

    kind: str
    cls: str = ""
    results: dict[str, Any] = field(default_factory=dict)
    text: str = ""
    token: int | None = None


class _Parser:
    """Recursive MI value reader with an explicit input cursor."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def peek(self) -> str:
        return self.text[self.pos : self.pos + 1]

    def string(self) -> str:
        if self.peek() != '"':
            raise ValueError("Expected an MI string")
        self.pos += 1
        out = bytearray()
        escapes = {"a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r"}
        while self.pos < len(self.text):
            char = self.text[self.pos]
            self.pos += 1
            if char == '"':
                return out.decode("utf-8", errors="replace")
            if char == "\\":
                if self.pos >= len(self.text):
                    break
                char = self.text[self.pos]
                self.pos += 1
                if char in "01234567":
                    digits = char
                    while len(digits) < 3 and self.peek() and self.peek() in "01234567":
                        digits += self.peek()
                        self.pos += 1
                    out.append(int(digits, 8))
                    continue
                if char == "x":
                    digits = ""
                    while self.peek() and self.peek() in "0123456789abcdefABCDEF":
                        digits += self.peek()
                        self.pos += 1
                    if not digits:
                        raise ValueError("Invalid hexadecimal escape")
                    value = int(digits, 16)
                    if value > 255:
                        raise ValueError("MI byte escape is out of range")
                    out.append(value)
                    continue
                char = escapes.get(char, char)
            out.extend(char.encode("utf-8"))
        raise ValueError("Unterminated MI string")

    def result(self) -> tuple[str, Any]:
        start = self.pos
        while self.peek() and self.peek() not in "=,}]":
            self.pos += 1
        name = self.text[start : self.pos]
        if not name or self.peek() != "=":
            raise ValueError("Expected an MI result")
        self.pos += 1
        return name, self.value()

    def value(self):
        char = self.peek()
        if char == '"':
            return self.string()
        if char == "{":
            self.pos += 1
            # GDB encodes breakpoint command lists as script={"cmd",...},
            # a value-tuple extension to the documented result-tuple grammar.
            if self.peek() in ('"', "[", "{"):
                items = []
                while self.peek() and self.peek() != "}":
                    items.append(self.value())
                    if self.peek() != ",":
                        break
                    self.pos += 1
                if self.peek() != "}":
                    raise ValueError("Unterminated MI value tuple")
                self.pos += 1
                return items
            result = self.results("}")
            if self.peek() != "}":
                raise ValueError("Unterminated MI tuple")
            self.pos += 1
            return result
        if char == "[":
            self.pos += 1
            values = []
            while self.peek() and self.peek() != "]":
                if self.peek() in '"{[':
                    values.append(self.value())
                else:
                    name, value = self.result()
                    values.append({name: value})
                if self.peek() != ",":
                    break
                self.pos += 1
            if self.peek() != "]":
                raise ValueError("Unterminated MI list")
            self.pos += 1
            return values
        raise ValueError(f"Invalid MI value at {self.pos}")

    def results(self, end: str = "") -> dict[str, Any]:
        values = {}
        while self.peek() and self.peek() != end:
            name, value = self.result()
            # Some MI commands (e.g. -break-list) repeat a result name. Preserve all entries.
            if name in values:
                prior = values[name]
                values[name] = [*prior, value] if isinstance(prior, list) else [prior, value]
            else:
                values[name] = value
            if self.peek() != ",":
                break
            self.pos += 1
        return values


def parse_record(line: str) -> MIRecord | None:
    """Parse MI2 without confusing nested tuples, escaped strings, or async tokens."""
    line = line.rstrip("\r\n")
    if not line or line.strip() == "(gdb)":
        return None
    match = re.match(r"(\d*)([\^*+=~@&])(.*)", line)
    if match is None:
        return MIRecord("@", text=line + "\n")
    token_text, kind, rest = match.groups()
    token = int(token_text) if token_text else None
    parser = _Parser(rest)
    if kind in "~@&":
        value = parser.string()
        if parser.pos != len(rest):
            raise ValueError("Trailing data in MI stream record")
        return MIRecord(kind, text=value, token=token)
    cls, separator, tail = rest.partition(",")
    parser = _Parser(tail)
    values = parser.results() if separator else {}
    if parser.pos != len(tail):
        raise ValueError("Trailing data in MI result record")
    return MIRecord(kind, cls, values, token=token)


def quote(value: str) -> str:
    """MI strings use C escaping; JSON's ASCII escapes are compatible for command text."""
    # Do not emit JSON's \u escapes: GDB interprets them literally rather than as Unicode.
    return json.dumps(value, ensure_ascii=False)


@dataclass
class _Pending:
    """A token-correlated reply and console output waiting for its caller."""

    done: threading.Event = field(default_factory=threading.Event)
    record: MIRecord | None = None
    error: str | None = None
    streams: list[str] = field(default_factory=list)
    stream_size: int = 0


class MITransport:
    """One GDB process, serial command replies, and an independent asynchronous event reader.

    Listener callbacks run on reader threads and must not send commands. A timeout closes
    the transport because a late mutation reply cannot safely be treated as a failed mutation.
    """

    def __init__(self, executable: str, callback: Callable[[MIRecord], None], timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._callback = callback
        self._serial = threading.RLock()
        self._lock = threading.Lock()
        self._pending: dict[int, _Pending] = {}
        self._token = 0
        self._closed = False
        try:
            # The process spans commands; close() owns its readers and reaping.
            self.process = subprocess.Popen(  # pylint:disable=consider-using-with
                [executable, "--quiet", "--nx", "--interpreter=mi2"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                start_new_session=True,
            )
        except OSError as exc:
            raise MIError(f"Cannot start GDB ({executable}): {exc}") from exc
        self._reader = threading.Thread(target=self._read, name="gdb-mi-reader", daemon=True)
        self._stderr = threading.Thread(target=self._read_stderr, name="gdb-mi-stderr", daemon=True)
        self._reader.start()
        self._stderr.start()

    def _notify(self, record: MIRecord) -> None:
        try:
            self._callback(record)
        except Exception:  # pylint:disable=broad-exception-caught
            _l.exception("GDB event listener failed")

    def _read(self) -> None:
        assert self.process.stdout is not None
        try:
            while line := self.process.stdout.readline(1024 * 1024):
                try:
                    record = parse_record(line)
                except (ValueError, RecursionError) as exc:
                    self._notify(MIRecord("&", text=f"Malformed GDB output: {exc}\n"))
                    continue
                if record is None:
                    continue
                with self._lock:
                    pending = (
                        self._pending.get(record.token) if record.kind == "^" and record.token is not None else None
                    )
                    if pending is not None:
                        pending.record = record
                    if record.kind in "~@&":
                        for waiter in self._pending.values():
                            if waiter.stream_size < 1024 * 1024:
                                waiter.streams.append(record.text)
                                waiter.stream_size += len(record.text)
                self._notify(record)
                if pending is not None:
                    pending.done.set()
        finally:
            self._fail_pending("GDB disconnected")
            self._notify(MIRecord("=", "transport-closed"))

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        while line := self.process.stderr.readline(32768):
            self._notify(MIRecord("&", text=line))

    def _fail_pending(self, message: str) -> None:
        with self._lock:
            for pending in self._pending.values():
                pending.error = message
                pending.done.set()

    def command(self, command: str, timeout: float | None = None) -> tuple[dict[str, Any], str]:
        if "\n" in command or "\r" in command:
            raise MIError("MI commands must be one line; quote command arguments")
        with self._serial:
            with self._lock:
                if self._closed or self.process.poll() is not None:
                    raise MIError("GDB is not connected")
                self._token += 1
                token = self._token
                pending = _Pending()
                self._pending[token] = pending
            try:
                assert self.process.stdin is not None
                try:
                    self.process.stdin.write(f"{token}{command}\n")
                    self.process.stdin.flush()
                except (OSError, ValueError) as exc:
                    raise MIError(f"GDB command could not be sent: {exc}") from exc
                if not pending.done.wait(self.timeout if timeout is None else timeout):
                    self.close()
                    raise MIError(f"GDB command timed out; debugger disconnected: {command.split()[0]}")
                if pending.error is not None:
                    raise MIError(pending.error)
                assert pending.record is not None
                if pending.record.cls == "error":
                    raise MIError(str(pending.record.results.get("msg", "GDB rejected the command")))
                return pending.record.results, "".join(pending.streams)
            finally:
                with self._lock:
                    self._pending.pop(token, None)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._fail_pending("GDB disconnected")
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2.0)
        for thread in (self._reader, self._stderr):
            if thread is not threading.current_thread():
                thread.join(timeout=2.0)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()
