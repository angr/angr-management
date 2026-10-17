from __future__ import annotations

import copy
import logging
import os
import re
import tempfile
import threading
import time
from collections import deque
from contextlib import suppress
from typing import TYPE_CHECKING

from . import mappings
from .mi import MIError, MIRecord, MITransport, RuntimeErrorBase, quote
from .terminal import InferiorTerminal

if TYPE_CHECKING:
    from collections.abc import Callable, Collection
    from typing import Any

_l = logging.getLogger(__name__)


def _frame(raw: dict) -> dict:
    result = dict(raw)
    for key in ("addr", "level", "line"):
        if key in result:
            try:
                result[key] = int(result[key], 0) if key == "addr" else int(result[key])
            except (TypeError, ValueError):
                result[key] = None
    return result


def _single_line(value: str, description: str) -> str:
    if not value.strip() or any(char in value for char in "\r\n\x00"):
        raise RuntimeErrorBase(f"{description} must be nonempty and contain no line breaks or NUL characters")
    return value


def _quote_argument(value: str) -> str:
    if not isinstance(value, str) or any(char in value for char in "\r\n\x00"):
        raise RuntimeErrorBase("Launch arguments must be strings without CR, LF, or NUL characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RuntimeErrorBase("Launch arguments must be valid UTF-8 text") from exc
    # -exec-arguments retains C control escapes literally, unlike ordinary MI
    # arguments. Quote only its delimiters and preserve the remaining bytes.
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _command_word(word: str) -> str:
    # Explicit GDB aliases take precedence over command-name abbreviations.
    return {
        "r": "run",
        "c": "continue",
        "fg": "continue",
        "s": "step",
        "n": "next",
        "si": "stepi",
        "ni": "nexti",
        "u": "until",
        "q": "quit",
        "j": "jump",
        "f": "frame",
        "d": "delete",
        "b": "break",
        "i": "info",
        "p": "print",
        "rc": "reverse-continue",
        "rs": "reverse-step",
        "rsi": "reverse-stepi",
        "rn": "reverse-next",
        "rni": "reverse-nexti",
        "rf": "reverse-finish",
    }.get(word.rstrip("&"), word.rstrip("&"))


class GDBRuntime:
    """A live process session shared by the GUI and MCP.

    Commands are synchronous and may block; GUI consumers submit them to a worker.
    Callbacks run on the thread emitting each event and must only enqueue work.
    Inspection snapshots are copies and remain safe to read while the target runs.
    """

    def __init__(self, gdb_path: str = "gdb", timeout: float = 10.0, history_limit: int = 1000) -> None:
        if history_limit < 1 or timeout <= 0:
            raise ValueError("History limit and timeout must be positive")
        self.gdb_path = gdb_path
        self.timeout = timeout
        self._history_limit = history_limit
        self._lock = threading.RLock()
        self._commands = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._listeners: list[Callable[[str, dict], None]] = []
        self._transport: MITransport | None = None
        self._terminal: InferiorTerminal | None = None
        self._state = "disconnected"
        self._pid: int | None = None
        self._executable: str | None = None
        self._mode: str | None = None
        self._generation = 0
        self._stop_reason: str | None = None
        self._frame: dict = {}
        self._threads: list[dict] = []
        self._frames: list[dict] = []
        self._registers: list[dict] = []
        self._register_names: list[str] = []
        self._modules: list[dict] = []
        self._memory_maps: list[dict] = []
        self._breakpoints: list[dict] = []
        self._rules: dict[str, dict] = {}
        self._rule_counter = 0
        self._events: deque[dict] = deque(maxlen=history_limit)
        self._output: deque[dict] = deque(maxlen=history_limit)
        self._sample_buffer = ""
        self._mapping_error: str | None = None
        self._selected_thread: str | None = None
        self._architecture: str | None = None
        self._stale_breakpoints: set[str] = set()
        self._pending_stop: int | None = None
        self._stop_sequence = 0
        self._probe_wakeup = threading.Event()
        self._probe_shutdown = threading.Event()
        self._probe_thread: threading.Thread | None = None

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def configure_gdb(self, path: str) -> None:
        with self._commands:
            if self._transport is not None:
                raise RuntimeErrorBase("Disconnect the current session before changing the GDB executable")
            self.gdb_path = _single_line(path, "GDB executable")

    def subscribe(self, callback: Callable[[str, dict], None]) -> Callable[[], None]:
        with self._lock:
            self._listeners.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._listeners:
                    self._listeners.remove(callback)

        return unsubscribe

    def _emit(self, event: str, payload: dict) -> None:
        with self._lock:
            callbacks = list(self._listeners)
        for callback in callbacks:
            try:
                callback(event, copy.deepcopy(payload))
            except Exception:  # pylint:disable=broad-exception-caught
                _l.exception("Runtime event listener failed")

    def _event(self, kind: str, **data) -> None:
        item = {"time": time.time(), "kind": kind, **data}
        with self._lock:
            self._events.append(item)
        self._emit("sample" if kind == "sample" else "changed", item)

    def _set_state(self, state: str, **details) -> None:
        with self._condition:
            changed = self._state != state
            self._state = state
            self._condition.notify_all()
        if changed or details:
            self._emit("state", {"state": state, **details})

    def _receive(self, record: MIRecord) -> None:
        if record.kind in "~@&":
            self._stream(record.kind, record.text)
            return
        if record.kind == "=" and record.cls == "thread-group-started":
            with self._lock:
                self._generation += 1
                self._pid = int(record.results["pid"])
                self._modules = []
                self._memory_maps = []
                self._frame = {}
                self._frames = []
                self._registers = []
                self._register_names = []
                self._architecture = None
                self._threads = []
                for rule in self._rules.values():
                    self._stale_breakpoints.add(rule["breakpoint"])
                    rule["enabled"] = False
                    rule["stale"] = True
                    rule["error"] = "Target restarted outside the runtime controls; recreate this rule"
            self._event("process", pid=self._pid, generation=self._generation)
        elif record.kind == "=" and record.cls == "thread-group-exited":
            with self._lock:
                self._pid = None
                self._modules = []
                self._memory_maps = []
            self._set_state("exited", exit_code=record.results.get("exit-code"))
        elif record.kind in ("*", "^") and record.cls == "running":
            with self._lock:
                self._pending_stop = None
            self._set_state("running")
        elif record.kind == "*" and record.cls == "stopped":
            if not record.results:
                # GDB emits a bare stop before running silent breakpoint command
                # lists. It is not a user-visible pause unless the list stays stopped.
                with self._lock:
                    self._stop_sequence += 1
                    self._pending_stop = self._stop_sequence
                self._probe_wakeup.set()
                return
            reason = record.results.get("reason", "stopped")
            with self._lock:
                self._pending_stop = None
                self._stop_reason = reason
                self._frame = _frame(record.results.get("frame", {}))
                self._selected_thread = record.results.get("thread-id")
                if reason.startswith("exited"):
                    self._pid = None
                    self._modules = []
                    self._memory_maps = []
            self._set_state("exited" if reason.startswith("exited") else "stopped", reason=reason)
            self._event("stop", reason=reason, frame=self._frame, details=record.results)
        elif record.kind == "=" and record.cls == "transport-closed":
            self._set_state("disconnected")
        elif record.kind == "=" and record.cls.startswith(("breakpoint-", "library-", "thread-")):
            self._emit("changed", {"kind": record.cls, **record.results})

    def _probe_stops(self) -> None:
        """Confirm silent stops off the reader thread, without flickering the UI on every hook hit."""
        while not self._probe_shutdown.is_set():
            self._probe_wakeup.wait()
            self._probe_wakeup.clear()
            if self._probe_shutdown.wait(0.02):
                return
            with self._lock:
                sequence = self._pending_stop
                transport = self._transport
            if sequence is None or transport is None:
                continue
            try:
                # Do not take the session command lock: launch/interrupt can be
                # waiting for this stop while holding it. Transport serialization
                # still prevents interleaved MI replies and console capture.
                result, _ = transport.command("-thread-info")
            except RuntimeErrorBase:
                continue
            with self._lock:
                if self._pending_stop != sequence or self._transport is not transport:
                    continue
                self._pending_stop = None
                threads = result.get("threads", [])
                if not threads or any(thread.get("state") == "running" for thread in threads):
                    continue
                selected = result.get("current-thread-id")
                thread = next((item for item in threads if item["id"] == selected), threads[0])
                self._frame = _frame(thread.get("frame", {}))
                self._selected_thread = selected
                self._stop_reason = "hook-stopped"
            self._set_state("stopped", reason="hook-stopped")

    def _stream(self, channel: str, text: str) -> None:
        if channel != "~":
            item = {"time": time.time(), "channel": channel, "text": text[:32768]}
            with self._lock:
                if channel == "&" and self._sample_buffer:
                    match = re.search(r"@@AM_RULE_(r\d+)_BEGIN@@", self._sample_buffer)
                    if match is not None and (rule := self._rules.get(match[1])) is not None:
                        rule["error"] = text.strip()[:1024]
                    self._sample_buffer = ""
                self._output.append(item)
            self._emit("output", item)
            return
        # A single GDB `output` may arrive in several MI console records. Delimiters
        # collect samples across records without parsing their GDB types.
        with self._lock:
            self._sample_buffer += text
            pending = self._sample_buffer
            while True:
                match = re.search(r"@@AM_RULE_(r\d+)_BEGIN@@", pending)
                if match is None:
                    break
                end_marker = f"@@AM_RULE_{match[1]}_END@@"
                end = pending.find(end_marker, match.end())
                next_sample = re.search(r"@@AM_RULE_(r\d+)_BEGIN@@", pending[match.end() :])
                if next_sample is not None and (end == -1 or match.end() + next_sample.start() < end):
                    if (rule := self._rules.get(match[1])) is not None:
                        rule["error"] = "The previous hook sample did not finish"
                    pending = pending[match.end() + next_sample.start() :]
                    continue
                if end == -1:
                    self._sample_buffer = pending[-65536:]
                    return
                value = pending[match.end() : end].strip()
                rule = self._rules.get(match[1])
                if rule is not None:
                    sample = {"time": time.time(), "value": value[:16384]}
                    rule["last_value"] = sample["value"]
                    rule["error"] = None
                    rule["samples"].append(sample)
                    del rule["samples"][: -min(200, self._history_limit)]
                    self._event("sample", rule_id=rule["id"], label=rule["label"], value=sample["value"])
                pending = pending[: match.start()] + pending[end + len(end_marker) :]
            # Partial markers are possible across stream records, but ordinary output
            # should be delivered immediately. Only retain a plausible marker prefix.
            prefix = pending.rfind("@@AM_")
            if prefix == -1:
                marker = "@@AM_"
                for size in range(min(len(marker) - 1, len(pending)), 0, -1):
                    if pending.endswith(marker[:size]):
                        prefix = len(pending) - size
                        break
            if prefix >= 0:
                self._sample_buffer = pending[prefix:][-65536:]
                pending = pending[:prefix]
            else:
                self._sample_buffer = ""
            if pending.strip():
                item = {"time": time.time(), "channel": channel, "text": pending[:32768]}
                self._output.append(item)
            else:
                item = None
        if item is not None:
            self._emit("output", item)

    def _command(self, command: str, timeout: float | None = None) -> dict:
        if self._transport is None:
            raise RuntimeErrorBase("No GDB session; launch or attach first")
        return self._transport.command(command, timeout)[0]

    def _require_stopped(self) -> None:
        if self.state != "stopped":
            raise RuntimeErrorBase("Pause the target before inspecting or changing its state")

    def checked(
        self,
        operation: Callable[[], Any],
        generation: int,
        pc: int | None = None,
        *,
        states: Collection[str] = ("stopped",),
        thread_id: str | None = None,
        frame_level: int | None = None,
    ) -> Any:
        """Check captured session context and apply an operation under the command lock.

        A dialog can outlive a restart or frame selection made through MCP. Callers
        may also require the exact selected thread, frame and PC.
        """
        with self._commands:
            if generation != self._generation:
                raise RuntimeErrorBase("The target session changed; select the variable again")
            if self.state not in states:
                raise RuntimeErrorBase("The target state changed; reopen the dialog and try again")
            if thread_id is not None:
                actual_thread = self._command("-thread-info").get("current-thread-id")
                if actual_thread != str(thread_id):
                    raise RuntimeErrorBase("The selected thread changed; select the variable again")
            if pc is not None or frame_level is not None:
                actual = _frame(self._command("-stack-info-frame").get("frame", {}))
                if frame_level is not None and actual.get("level") != frame_level:
                    raise RuntimeErrorBase("The selected stack frame changed; select the variable again")
                if pc is not None and actual.get("addr") != pc:
                    raise RuntimeErrorBase("The selected frame moved; select the variable at its current instruction")
            return operation()

    def _start(self, mode: str, executable: str | None) -> None:
        if self.state in ("running", "stopped"):
            raise RuntimeErrorBase("Stop or detach the active target before starting another session")
        self.close()
        with self._lock:
            self._generation += 1
            self._pid = None
            self._executable = os.path.realpath(executable) if executable else None
            self._mode = mode
            self._stop_reason = None
            self._frame = {}
            self._frames = []
            self._threads = []
            self._registers = []
            self._register_names = []
            self._modules = []
            self._memory_maps = []
            self._breakpoints = []
            self._rules = {}
            self._sample_buffer = ""
            self._mapping_error = None
            self._architecture = None
            self._stale_breakpoints.clear()
            self._pending_stop = None
        self._transport = MITransport(self.gdb_path, self._receive, self.timeout)
        self._probe_shutdown.clear()
        self._probe_thread = threading.Thread(target=self._probe_stops, name="gdb-stop-verifier", daemon=True)
        self._probe_thread.start()
        try:
            self._command("-gdb-set pagination off")
            self._command("-gdb-set confirm off")
            self._command("-gdb-set mi-async on")
            self._command("-gdb-set breakpoint pending on")
            # Keep GDB from disabling ASLR; relocation must use the actual mappings.
            self._command("-gdb-set disable-randomization off")
            self._command("-gdb-set startup-with-shell off")
            if executable:
                self._command(f"-file-exec-and-symbols {quote(os.path.abspath(executable))}")
            self._set_state("ready")
        except RuntimeErrorBase:
            self.close()
            raise

    def launch(
        self,
        executable: str,
        args: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        stop_at_entry: bool = True,
    ) -> dict:
        arguments = " ".join(_quote_argument(arg) for arg in (args or []))
        with self._commands:
            self._start("launch", executable)
            try:
                self._terminal = InferiorTerminal(lambda text: self._stream("@", text))
                self._command(f"-inferior-tty-set {quote(self._terminal.path)}")
                if cwd:
                    self._command(f"-environment-cd {quote(os.path.abspath(cwd))}")
                if args:
                    self._command("-exec-arguments " + arguments)
                for key, value in (env or {}).items():
                    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                        raise RuntimeErrorBase(f"Invalid environment variable name: {key}")
                    if any(char in value for char in "\r\n\x00"):
                        raise RuntimeErrorBase("Environment values must not contain line breaks or NUL")
                    # -gdb-set passes its remainder directly to GDB's CLI parser;
                    # unlike MI commands, quoting KEY=VALUE changes the variable name.
                    self._command(f"-gdb-set environment {key}={value}")
                if stop_at_entry:
                    # starti also works for stripped executables and stops before constructors.
                    self._execute_console("starti", require_stopped=False)
                    self.wait_for_stop()
                    return self.refresh()
                self._command("-exec-run")
                return self.snapshot()
            except RuntimeErrorBase:
                self.close()
                raise

    def attach(self, pid: int, executable: str | None = None) -> dict:
        if pid < 1:
            raise RuntimeErrorBase("PID must be a positive integer")
        with self._commands:
            if executable is None:
                with suppress(OSError):
                    executable = os.readlink(f"/proc/{pid}/exe")
            self._start("attach", executable)
            try:
                self._command(f"-target-attach {pid}")
                self.wait_for_stop()
                return self.refresh()
            except RuntimeErrorBase:
                self.close()
                raise

    def connect_remote(self, endpoint: str, executable: str | None = None) -> dict:
        endpoint = _single_line(endpoint, "Remote endpoint")
        if not re.fullmatch(r"[A-Za-z0-9_.:\[\]/-]+", endpoint):
            raise RuntimeErrorBase("Use a host:port or device path for the remote endpoint")
        with self._commands:
            self._start("remote", executable)
            try:
                self._command(f"-target-select remote {endpoint}")
                self.wait_for_stop()
                return self.refresh()
            except RuntimeErrorBase:
                self.close()
                raise

    def wait_for_stop(self, timeout: float | None = None) -> dict:
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        with self._condition:
            while self._state not in ("stopped", "exited", "disconnected", "error"):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeErrorBase("Timed out waiting for the target to stop")
                self._condition.wait(remaining)
            if self._state in ("disconnected", "error"):
                raise RuntimeErrorBase("Debugger disconnected while waiting for the target")
        return self.snapshot()

    def _resume(self, command: str) -> dict:
        with self._commands:
            self._require_stopped()
            self._remove_stale_breakpoints()
            # Mark the old stop consumed before sending. A caller can immediately
            # wait_for_stop without racing the reader's ^running notification.
            self._set_state("running")
            try:
                self._command(command)
            except RuntimeErrorBase:
                if self.state == "running":
                    self._set_state("stopped")
                raise
            return self.snapshot()

    def continue_execution(self) -> dict:
        return self._resume("-exec-continue --all")

    def step_instruction(self) -> dict:
        return self._resume("-exec-step-instruction")

    def next_instruction(self) -> dict:
        return self._resume("-exec-next-instruction")

    def step_source(self) -> dict:
        return self._resume("-exec-step")

    def next_source(self) -> dict:
        return self._resume("-exec-next")

    def finish(self) -> dict:
        return self._resume("-exec-finish")

    def interrupt(self) -> dict:
        with self._commands:
            if self.state != "running":
                raise RuntimeErrorBase("The target is not running")
            self._command("-exec-interrupt --all")
            self.wait_for_stop()
            return self.refresh()

    def detach(self) -> dict:
        with self._commands:
            if self.state == "running":
                self.interrupt()
            self._require_stopped()
            keeper = None
            if self._terminal is not None:
                if self._pid is None:
                    raise RuntimeErrorBase("Cannot preserve the target terminal without a local process ID")
                keeper = self._terminal.prepare_detach(self._pid)
            try:
                self._command("-target-detach")
            except BaseException:
                if keeper is not None:
                    InferiorTerminal.cancel_detach(keeper)
                raise
            if self._terminal is not None and keeper is not None:
                self._terminal.finish_detach(keeper)
                self._terminal = None
            self._set_state("ready")
            with self._lock:
                self._pid = None
                self._modules = []
                self._memory_maps = []
                self._rules = {}
                self._breakpoints = []
            self._event("detached")
            return self.snapshot()

    def stop(self) -> dict:
        with self._commands:
            if self.state == "running":
                self.interrupt()
            self._require_stopped()
            self._execute_console("kill")
            self._set_state("exited")
            return self.snapshot()

    def close(self) -> None:
        with self._commands:
            transport = self._transport
            if transport is None:
                return
            try:
                if self._mode in ("attach", "remote") and self.state in ("running", "stopped"):
                    self.detach()
                transport.command("-gdb-exit", timeout=2)
            except RuntimeErrorBase:
                pass
            finally:
                self._probe_shutdown.set()
                self._probe_wakeup.set()
                transport.close()
                self._transport = None
                if self._probe_thread is not None:
                    self._probe_thread.join(timeout=2)
                    self._probe_thread = None
                if self._terminal is not None:
                    self._terminal.close()
                    self._terminal = None
                with self._lock:
                    self._pid = None
                    self._modules = []
                    self._memory_maps = []
                self._set_state("disconnected")

    def send_input(self, text: str) -> None:
        """Send UTF-8 input to a launched target's PTY, including control characters if requested."""
        with self._commands:
            if self._terminal is None or self.state not in ("running", "stopped"):
                raise RuntimeErrorBase("This session has no active target terminal")
            self._terminal.write(text)

    def evaluate(self, expression: str) -> str:
        with self._commands:
            self._require_stopped()
            expression = _single_line(expression, "Expression")
            return self._command(f"-data-evaluate-expression {quote(expression)}")["value"]

    def read_memory(self, address: int, size: int) -> bytes:
        if address < 0 or not 1 <= size <= 1024 * 1024:
            raise RuntimeErrorBase("Read size must be 1..1048576 bytes and address nonnegative")
        with self._commands:
            self._require_stopped()
            result = self._command(f"-data-read-memory-bytes 0x{address:x} {size}")
            chunks = sorted(result.get("memory", []), key=lambda chunk: int(chunk["begin"], 0))
            data = bytearray()
            expected = address
            for chunk in chunks:
                if int(chunk["begin"], 0) != expected:
                    raise RuntimeErrorBase("GDB returned a partial or noncontiguous memory read")
                content = bytes.fromhex(chunk["contents"])
                data.extend(content)
                expected += len(content)
            if len(data) != size:
                raise RuntimeErrorBase("GDB returned fewer bytes than requested")
            return bytes(data)

    def write_memory(self, address: int, data: bytes) -> None:
        if address < 0 or not 1 <= len(data) <= 1024 * 1024:
            raise RuntimeErrorBase("Write size must be 1..1048576 bytes and address nonnegative")
        with self._commands:
            self._require_stopped()
            self._command(f"-data-write-memory-bytes 0x{address:x} {data.hex()}")
            self._event("memory-write", address=address, size=len(data))

    def write_register(self, name: str, value: str) -> None:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise RuntimeErrorBase("Invalid register name")
        with self._commands:
            self._require_stopped()
            if name not in self._register_names:
                raise RuntimeErrorBase(f"Unknown target register: {name}")
            self.evaluate(f"${name} = ({_single_line(value, 'Register value')})")
            self._event("register-write", name=name)

    @staticmethod
    def _validate_user_commands(commands: str) -> None:
        lifecycle = {
            "run",
            "r",
            "start",
            "starti",
            "attach",
            "detach",
            "disconnect",
            "kill",
            "target",
            "file",
            "exec-file",
            "symbol-file",
            "add-symbol-file",
            "remove-symbol-file",
            "quit",
            "q",
            "exit",
        }
        for line in commands.splitlines():
            words = line.strip().split()
            if not words:
                continue
            word = _command_word(words[0])
            target_change = any(command.startswith(word) for command in lifecycle)
            architecture_change = (
                word == "set"
                and len(words) > 1
                and any(command.startswith(words[1]) for command in ("architecture", "processor", "endian"))
            )
            if target_change or architecture_change:
                raise RuntimeErrorBase(
                    "Use the Launch / Attach / Remote / Stop controls for target lifecycle changes; "
                    "console lifecycle commands would invalidate runtime address rules"
                )

    def execute_console(self, command: str) -> str:
        self._validate_user_commands(command)
        return self._execute_console(command)

    def _execute_console(self, command: str, require_stopped: bool = True) -> str:
        with self._commands:
            if require_stopped:
                self._require_stopped()
            if not command.strip() or "\x00" in command:
                raise RuntimeErrorBase("GDB command must be nonempty and contain no NUL")
            if self._transport is None:
                raise RuntimeErrorBase("No GDB session")
            if "\n" not in command:
                return self._transport.command(f"-interpreter-exec console {quote(command)}")[1]
            # `source` preserves GDB block syntax (commands/define/python/if/end),
            # unlike issuing one -interpreter-exec for each line.
            with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", encoding="utf-8") as script:
                script.write(command + "\n")
                script.flush()
                return self._transport.command(f"-interpreter-exec console {quote('source ' + script.name)}")[1]

    def _remove_stale_breakpoints(self) -> None:
        with self._lock:
            numbers = list(self._stale_breakpoints)
        for number in numbers:
            # A custom script may already have removed it; deleting only known
            # managed numbers cannot affect unrelated user breakpoints.
            with suppress(MIError):
                self._command(f"-break-delete {number}")
        with self._lock:
            self._stale_breakpoints.difference_update(numbers)

    def select_thread(self, thread_id: str | int) -> dict:
        if not str(thread_id).isdigit():
            raise RuntimeErrorBase("Invalid thread identifier")
        with self._commands:
            self._require_stopped()
            self._command(f"-thread-select {thread_id}")
            self._selected_thread = str(thread_id)
            return self.refresh()

    def select_frame(self, level: int) -> dict:
        if level < 0:
            raise RuntimeErrorBase("Frame level must be nonnegative")
        with self._commands:
            self._require_stopped()
            self._command(f"-stack-select-frame {level}")
            return self.refresh()

    def _refresh_modules(self) -> None:
        if self._mode != "remote" and self._pid is not None:
            try:
                modules, maps = mappings.local_modules(self._pid, self._generation)
                for module in modules:
                    if module["load_bias"] is None or not module["build_id"]:
                        continue
                    try:
                        actual = self.read_memory(
                            module["load_bias"] + module["build_id_vaddr"], len(module["build_id"]) // 2
                        ).hex()
                        if actual != module["build_id"]:
                            raise RuntimeErrorBase("The mapped build ID does not match the module file on disk")
                    except RuntimeErrorBase as exc:
                        module["error"] = str(exc)
                        module["load_bias"] = None
                with self._lock:
                    self._modules = modules
                    self._memory_maps = maps
                    self._mapping_error = None
                return
            except RuntimeErrorBase as exc:
                with self._lock:
                    self._mapping_error = str(exc)
        else:
            with self._lock:
                self._mapping_error = (
                    "Remote module relocation is unavailable: local /proc does not describe the remote target. "
                    "Use runtime addresses or GDB symbol expressions."
                )
        # MI's library ranges remain useful to display, but cannot establish the main
        # image's PT_LOAD bias. Do not silently turn them into a guessed relocation.
        try:
            result = self._command("-file-list-shared-libraries")
            modules = []
            for library in result.get("shared-libraries", []):
                regions = [
                    {"start": int(region["from"], 0), "end": int(region["to"], 0), "permissions": "", "offset": None}
                    for region in library.get("ranges", [])
                ]
                modules.append(
                    {
                        "id": library.get("id", library.get("target-name", "")),
                        "path": library.get("target-name", library.get("host-name", "")),
                        "start": min((region["start"] for region in regions), default=0),
                        "end": max((region["end"] for region in regions), default=0),
                        "load_bias": None,
                        "linked_base": None,
                        "ranges": regions,
                        "error": self._mapping_error,
                    }
                )
            with self._lock:
                self._modules = modules
        except MIError:
            with self._lock:
                self._modules = []

    def refresh(self) -> dict:
        with self._commands:
            self._require_stopped()
            self._remove_stale_breakpoints()
            thread_info = self._command("-thread-info")
            frames = self._command("-stack-list-frames 0 63").get("stack", [])
            frame = self._command("-stack-info-frame").get("frame", {})
            if not self._register_names:
                self._register_names = self._command("-data-list-register-names").get("register-names", [])
            values = self._command("-data-list-register-values x").get("register-values", [])
            registers = []
            for item in values:
                index = int(item["number"])
                name = self._register_names[index] if index < len(self._register_names) else ""
                if name:
                    registers.append({"number": index, "name": name, "value": item["value"]})
            breakpoints = self._command("-break-list").get("BreakpointTable", {}).get("body", [])
            with self._lock:
                self._threads = thread_info.get("threads", [])
                self._selected_thread = thread_info.get("current-thread-id", self._selected_thread)
                self._frames = [_frame(item.get("frame", item)) for item in frames]
                self._frame = _frame(frame)
                self._architecture = frame.get("arch", self._architecture)
                self._registers = registers
                self._breakpoints = [item.get("bkpt", item) for item in breakpoints]
                by_number = {item["number"]: item for item in self._breakpoints}
                for rule in self._rules.values():
                    bp_info = by_number.get(rule["breakpoint"])
                    if bp_info is None:
                        rule["enabled"] = False
                        rule["stale"] = True
                        rule["error"] = "The hook's breakpoint was removed in GDB"
                    else:
                        rule["active"] = rule["enabled"] and bp_info.get("enabled", "y") == "y"
            self._refresh_modules()
            result = self.snapshot()
            return result

    def snapshot(self, refresh: bool = False) -> dict:
        if refresh:
            return self.refresh()
        with self._lock:
            stopped = self._state == "stopped"
            result = {
                "state": self._state,
                "pid": self._pid,
                "executable": self._executable,
                "gdb_path": self.gdb_path,
                "mode": self._mode,
                "generation": self._generation,
                "stop_reason": self._stop_reason,
                "frame": self._frame,
                "architecture": self._architecture,
                "selected_thread": self._selected_thread,
                "threads": self._threads,
                "frames": self._frames,
                "registers": self._registers,
                "modules": self._modules,
                "memory_maps": self._memory_maps,
                "mapping_error": self._mapping_error,
                "breakpoints": self._breakpoints,
                "rules": list(self._rules.values()),
                "events": list(self._events),
                "output": list(self._output),
                "capabilities": {
                    "inspect": stopped,
                    "mutate": stopped,
                    "resume": stopped,
                    "interrupt": self._state == "running",
                    "reverse": False,
                    "relocate": any(module["load_bias"] is not None for module in self._modules),
                    "hooks": stopped,
                    "input": self._terminal is not None and self._state in ("running", "stopped"),
                },
            }
            return copy.deepcopy(result)

    def static_to_runtime(self, address: int, static_base: int, module_id: str | None = None) -> int:
        with self._lock:
            module = mappings.select_module(self._modules, self._executable, module_id)
            return mappings.static_to_runtime(module, address, static_base)

    def runtime_to_static(self, address: int, static_base: int, module_id: str | None = None) -> int:
        with self._lock:
            module = mappings.select_module(self._modules, self._executable, module_id)
            return mappings.runtime_to_static(module, address, static_base)

    def add_breakpoint(
        self,
        location: str | int,
        kind: str = "execute",
        condition: str | None = None,
        temporary: bool = False,
        *,
        _managed: bool = False,
    ) -> dict:
        with self._commands:
            self._require_stopped()
            text = f"*0x{location:x}" if isinstance(location, int) else _single_line(location, "Breakpoint location")
            if kind == "execute":
                flags = "-f " + ("-t " if temporary else "")
                if condition:
                    flags += "-c " + quote(_single_line(condition, "Breakpoint condition")) + " "
                result = self._command(f"-break-insert {flags}{quote(text)}")
            elif kind in ("write", "read", "access"):
                if temporary:
                    raise RuntimeErrorBase("Temporary data watchpoints are not supported")
                option = {"write": "", "read": "-r ", "access": "-a "}[kind]
                result = self._command(f"-break-watch {option}{quote(text)}")
            else:
                raise RuntimeErrorBase(f"Unknown breakpoint kind: {kind}")
            bp_info = next((result[key] for key in ("bkpt", "wpt", "hw-awpt", "hw-rwpt") if key in result), None)
            if bp_info is None:
                raise RuntimeErrorBase("GDB did not return a breakpoint identifier")
            bp_info["kind"] = kind
            bp_info.setdefault("enabled", "y")
            try:
                # Managed rules are checked after aliases have been grouped and
                # their enabled state is known, while the inferior is stopped.
                if not _managed:
                    self._assert_no_conflicts(bp_info, managed=False)
            except RuntimeErrorBase:
                self._command(f"-break-delete {bp_info['number']}")
                raise
            if kind != "execute" and condition:
                try:
                    self._command(f"-break-condition {bp_info['number']} {quote(condition)}")
                except RuntimeErrorBase:
                    self.remove_breakpoint(bp_info["number"])
                    raise
            with self._lock:
                self._breakpoints = [bp for bp in self._breakpoints if bp["number"] != bp_info["number"]]
                self._breakpoints.append(bp_info)
            self._event("breakpoint-added", breakpoint=bp_info)
            return copy.deepcopy(bp_info)

    @staticmethod
    def _breakpoint_number(number: str | int) -> str:
        text = str(number)
        if not re.fullmatch(r"\d+(?:\.\d+)?", text):
            raise RuntimeErrorBase("Invalid breakpoint number")
        return text

    def remove_breakpoint(self, number: str | int, *, _managed: bool = False) -> None:
        number = self._breakpoint_number(number)
        with self._commands:
            self._require_stopped()
            if not _managed and any(rule["breakpoint"] == number for rule in self._rules.values()):
                raise RuntimeErrorBase("This breakpoint belongs to runtime rules; edit or remove its entries in Rules")
            self._command(f"-break-delete {number}")
            with self._lock:
                self._breakpoints = [bp for bp in self._breakpoints if bp["number"] != number]
                for rule in self._rules.values():
                    if rule["breakpoint"] == number:
                        rule["stale"] = True
                        rule["enabled"] = False
                        rule["error"] = "The hook's breakpoint was removed in GDB"
            self._event("breakpoint-removed", number=number)

    def enable_breakpoint(self, number: str | int, enabled: bool = True) -> None:
        number = self._breakpoint_number(number)
        with self._commands:
            self._require_stopped()
            if any(rule["breakpoint"] == number for rule in self._rules.values()):
                raise RuntimeErrorBase(
                    "This breakpoint belongs to runtime rules; enable or disable its entries in Rules"
                )
            if enabled:
                entries = self._list_breakpoints()
                selected = next((bp for bp in entries if bp["number"] == number), None)
                if selected is not None:
                    managed = any(rule["breakpoint"] == number for rule in self._rules.values())
                    self._assert_no_conflicts(selected, managed=managed, entries=entries)
            self._command(f"-break-{'enable' if enabled else 'disable'} {number}")
            with self._lock:
                for bp in self._breakpoints:
                    if bp["number"] == number:
                        bp["enabled"] = "y" if enabled else "n"
            self._event("breakpoint-enabled", number=number, enabled=enabled)

    def _list_breakpoints(self) -> list[dict]:
        entries = self._command("-break-list").get("BreakpointTable", {}).get("body", [])
        result = [entry.get("bkpt", entry) for entry in entries]
        with self._lock:
            self._breakpoints = copy.deepcopy(result)
        return result

    @staticmethod
    def _same_site(first: dict, second: dict) -> bool:
        def addresses(entry):
            result = set()
            for location in [entry, *entry.get("locations", [])]:
                address = location.get("addr", "")
                if isinstance(address, str) and address.startswith("0x"):
                    result.add(int(address, 16))
            return result

        left, right = addresses(first), addresses(second)
        if left and right:
            return bool(left & right)
        # Pending locations have no numeric address. Compare their original
        # expressions, never the literal <PENDING> placeholder.
        left_expr = first.get("original-location", first.get("exp", first.get("what")))
        right_expr = second.get("original-location", second.get("exp", second.get("what")))
        return bool(left_expr and right_expr and left_expr == right_expr)

    def _assert_no_conflicts(self, candidate: dict, *, managed: bool, entries: list[dict] | None = None) -> None:
        entries = self._list_breakpoints() if entries is None else entries
        with self._lock:
            owned = {rule["breakpoint"] for rule in self._rules.values()}
        for existing in entries:
            if existing["number"] == candidate["number"] or existing.get("enabled", "y") != "y":
                continue
            existing_managed = existing["number"] in owned
            if not managed and not existing_managed:
                continue
            if any(
                bp.get("kind") in ("write", "read", "access") or "watchpoint" in bp.get("type", "")
                for bp in (candidate, existing)
            ):
                # Even disjoint data ranges can fire at one instruction, alongside
                # an execution breakpoint. GDB can continue from the first list
                # without running the others; textual/address aliases cannot prove safety.
                raise RuntimeErrorBase(
                    f"Breakpoint {existing['number']} cannot share an enabled session with this runtime rule: "
                    "data watchpoints can fire together with other stops, and auto-continue could hide a stop "
                    "or skip a rule. Disable the other breakpoint/rule, or use one identical trigger expression "
                    "for all data rules."
                )
            if existing_managed == managed:
                continue
            if self._same_site(candidate, existing):
                raise RuntimeErrorBase(
                    f"Breakpoint {existing['number']} uses this hook location. Disable the conflicting "
                    "stopping breakpoint or runtime rule first; auto-continue would hide the requested stop."
                )

    @staticmethod
    def _has_resume(commands: list[str] | str | None) -> bool:
        if isinstance(commands, str):
            commands = commands.splitlines()
        resume = {
            "continue",
            "c",
            "step",
            "s",
            "next",
            "n",
            "stepi",
            "si",
            "nexti",
            "ni",
            "finish",
            "until",
            "u",
            "advance",
            "jump",
            "signal",
            "step-instruction",
            "next-instruction",
            "reverse-continue",
            "reverse-step",
            "reverse-next",
            "reverse-stepi",
            "reverse-nexti",
            "reverse-finish",
        }
        return any(
            any(command.startswith(_command_word(line.strip().split(maxsplit=1)[0])) for command in resume)
            for line in (commands or [])
            if line.strip()
        )

    @staticmethod
    def preview_rule(
        expression: str,
        mode: str = "monitor",
        value: str | None = None,
        commands: list[str] | str | None = None,
        rule_id: str = "preview",
    ) -> list[str]:
        expression = _single_line(expression, "Rule expression")
        if mode not in ("monitor", "clamp", "custom"):
            raise RuntimeErrorBase(f"Unknown rule mode: {mode}")
        lines = ["silent"]
        if mode == "clamp":
            if value is None:
                raise RuntimeErrorBase("A clamp requires a value")
            lines.append(f"set variable ({expression}) = ({_single_line(str(value), 'Clamp value')})")
        sample = [
            f'printf "@@AM_RULE_{rule_id}_BEGIN@@"',
            f"output /r ({expression})",
            f'printf "@@AM_RULE_{rule_id}_END@@\\n"',
        ]
        if mode == "custom":
            if isinstance(commands, str):
                commands = commands.splitlines()
            if not commands:
                raise RuntimeErrorBase("A custom hook needs GDB command lines")
            for command in commands:
                if "\n" in command or "\r" in command or "\x00" in command:
                    raise RuntimeErrorBase("Each hook command must be one line")
            GDBRuntime._validate_user_commands("\n".join(commands))
            lines.extend(sample + commands if GDBRuntime._has_resume(commands) else commands + sample)
        else:
            lines += sample
        if not GDBRuntime._has_resume(lines):
            lines.append("continue")
        return lines

    def _install_group(self, rules: list[dict]) -> list[dict]:
        """One GDB command list per physical stop, so every enabled rule runs."""
        active = [rule for rule in rules if rule["enabled"]]
        explicit_resume = any(self._has_resume(rule["commands"]) for rule in active if rule["mode"] == "custom")
        if len(active) > 1 and explicit_resume:
            raise RuntimeErrorBase(
                "Hooks sharing a trigger must omit execution-resume commands; "
                "a single continue is generated after all rules"
            )
        lines = ["silent"]
        for rule in active:
            actions = self.preview_rule(rule["expression"], rule["mode"], rule["value"], rule["commands"], rule["id"])[
                1:
            ]
            if not self._has_resume(rule["commands"]) or rule["mode"] != "custom":
                actions = actions[:-1]  # drop this rule's generated continue
            lines.extend(actions)
        if not explicit_resume:
            lines.append("continue")
        number = rules[0]["breakpoint"]
        entries = self._list_breakpoints()
        bp_info = next((bp for bp in entries if bp["number"] == number), None)
        if bp_info is None:
            raise RuntimeErrorBase("The shared hook breakpoint was removed; recreate the rule")
        if active:
            self._assert_no_conflicts(bp_info, managed=True, entries=entries)
        self._command(f"-break-commands {number} " + " ".join(quote(line) for line in lines))
        self._command(f"-break-{'enable' if active else 'disable'} {number}")
        script = "commands " + number + "\n" + "\n".join(lines) + "\nend"
        for rule in rules:
            rule["generated_script"] = script
            rule["shared_rule_ids"] = [entry["id"] for entry in rules]
            rule["active"] = rule["enabled"]
        return rules

    def _store_group(self, rules: list[dict]) -> None:
        with self._lock:
            for rule in rules:
                self._rules[rule["id"]] = copy.deepcopy(rule)

    def _group(self, number: str) -> list[dict]:
        with self._lock:
            return [copy.deepcopy(rule) for rule in self._rules.values() if rule["breakpoint"] == number]

    def add_rule(
        self,
        label: str,
        expression: str,
        mode: str = "monitor",
        value: str | None = None,
        trigger: str | None = None,
        commands: list[str] | str | None = None,
        enabled: bool = True,
    ) -> dict:
        with self._commands:
            self._require_stopped()
            if len(label) > 256:
                raise RuntimeErrorBase("Rule label must be at most 256 characters")
            self._rule_counter += 1
            rule_id = f"r{self._rule_counter}"
            self.preview_rule(expression, mode, value, commands, rule_id)
            with self._lock:
                match = next(
                    (
                        rule
                        for rule in self._rules.values()
                        if rule["trigger"] == trigger
                        and (trigger is not None or rule["expression"] == expression)
                        and not rule["stale"]
                    ),
                    None,
                )
            created = match is None
            if match is not None:
                number = match["breakpoint"]
            else:
                new_bp = self.add_breakpoint(
                    trigger or expression, kind="execute" if trigger else "write", _managed=True
                )
                number = new_bp["number"]
                # Different spellings (symbol / *runtime-address) can share one
                # instruction. Merge single-location sites only; multi-location
                # hooks must use the identical-trigger path above.
                entries = self._list_breakpoints()
                with self._lock:
                    owned = {rule["breakpoint"] for rule in self._rules.values() if not rule["stale"]}
                for existing in entries:
                    if existing["number"] not in owned or not self._same_site(new_bp, existing):
                        continue
                    self._command(f"-break-delete {number}")
                    if new_bp.get("locations") or existing.get("locations"):
                        raise RuntimeErrorBase("Overlapping multi-location hooks need one identical trigger expression")
                    number = existing["number"]
                    created = False
                    break
            previous = self._group(number)
            rule = {
                "id": rule_id,
                "label": label or expression,
                "expression": expression,
                "mode": mode,
                "value": value,
                "trigger": trigger,
                "commands": copy.deepcopy(commands),
                "generated_script": "",
                "breakpoint": number,
                "enabled": enabled,
                "samples": [],
                "last_value": None,
                "error": None,
                "stale": False,
            }
            try:
                group = self._install_group([*previous, rule])
            except RuntimeErrorBase:
                if created:
                    self.remove_breakpoint(number)
                elif previous:
                    with suppress(RuntimeErrorBase):
                        self._install_group(previous)
                raise
            self._store_group(group)
            self._event("rule-added", rule_id=rule_id, label=rule["label"])
            return copy.deepcopy(rule)

    def update_rule(
        self,
        rule_id: str,
        enabled: bool | None = None,
        value: str | None = None,
        commands: list[str] | str | None = None,
    ) -> dict:
        with self._commands:
            self._require_stopped()
            with self._lock:
                if rule_id not in self._rules:
                    raise RuntimeErrorBase(f"Unknown rule: {rule_id}")
                number = self._rules[rule_id]["breakpoint"]
            previous = self._group(number)
            group = copy.deepcopy(previous)
            rule = next(entry for entry in group if entry["id"] == rule_id)
            if rule["stale"]:
                raise RuntimeErrorBase("This hook is stale or failed; remove it and select its location again")
            if value is not None:
                if rule["mode"] != "clamp":
                    raise RuntimeErrorBase("Only clamp rules have an editable value")
                rule["value"] = value
            if commands is not None:
                if rule["mode"] != "custom":
                    raise RuntimeErrorBase("Only custom hooks have editable GDB commands")
                rule["commands"] = commands
            if enabled is not None:
                rule["enabled"] = enabled
            try:
                self._install_group(group)
            except RuntimeErrorBase:
                with suppress(RuntimeErrorBase):
                    self._install_group(previous)
                raise
            self._store_group(group)
            self._event("rule-updated", rule_id=rule_id)
            return copy.deepcopy(rule)

    def remove_rule(self, rule_id: str) -> None:
        with self._commands:
            self._require_stopped()
            with self._lock:
                if rule_id not in self._rules:
                    raise RuntimeErrorBase(f"Unknown rule: {rule_id}")
                rule = self._rules[rule_id]
            remaining = [entry for entry in self._group(rule["breakpoint"]) if entry["id"] != rule_id]
            if rule["stale"]:
                self._remove_stale_breakpoints()
            elif remaining:
                self._store_group(self._install_group(remaining))
            else:
                self.remove_breakpoint(rule["breakpoint"], _managed=True)
            with self._lock:
                del self._rules[rule_id]
            self._event("rule-removed", rule_id=rule_id)
