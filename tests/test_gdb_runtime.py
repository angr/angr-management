from __future__ import annotations

import os
import platform
import queue
import select
import shutil
import subprocess
import sys
import threading
import time
import unittest
from contextlib import suppress
from pathlib import Path

from angrmanagement.logic.debugger.gdb import GDBRuntime, RuntimeErrorBase, _terminal_keeper
from angrmanagement.logic.debugger.gdb.mappings import (
    LoadSegment,
    MemoryMapping,
    elf_build_id,
    elf_load_segments,
    load_bias,
    parse_proc_maps,
    runtime_to_static,
    select_module,
    static_to_runtime,
)
from angrmanagement.logic.debugger.gdb.mi import MIError, MIRecord, MITransport, parse_record, quote

BINARIES = Path(os.environ.get("ANGR_REPOS_ROOT", Path(__file__).resolve().parents[2])) / "binaries"
FIXTURES = BINARIES / "tests" / "x86_64" / "runtime_2048"
GDB = shutil.which("gdb")
GDBSERVER = shutil.which("gdbserver")


def _record(text: str) -> MIRecord:
    record = parse_record(text)
    assert record is not None
    return record


def _terminate(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            stream.close()


class TestMIParsing(unittest.TestCase):
    """Decode MI records without losing nested or escaped values."""

    def test_nested_records_and_named_lists(self):
        record = _record('14^done,stack=[frame={level="0",addr="0x123",args=[{name="x",value="a,b"}]}]')
        self.assertEqual(record.token, 14)
        self.assertEqual(record.results["stack"][0]["frame"]["args"][0]["value"], "a,b")
        self.assertEqual(_record('*stopped,reason="breakpoint-hit"').cls, "stopped")
        self.assertEqual(_record('=thread-group-started,id="i1",pid="42"').results["pid"], "42")

    def test_c_escapes_unicode_and_literal_target_output(self):
        self.assertEqual(_record(r'~"line\n\t\"quote\"\\\303\251"').text, 'line\n\t"quote"\\é')
        self.assertEqual(_record('~"héllo"').text, "héllo")
        self.assertEqual(_record("inferior output").text, "inferior output\n")
        self.assertEqual(_record('7^done,value="\\x41"').results["value"], "A")
        self.assertIsNone(parse_record("(gdb) "))
        self.assertIsNone(parse_record(""))
        self.assertEqual(quote('é"\n'), '"é\\"\\n"')

    def test_malformed_records_do_not_look_successful(self):
        for text in ('1^done,x="unterminated', '1^done,x={a="b"', '1^done,x=["a"', '~"ok"garbage'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_record(text)

    def test_duplicate_result_keys_are_preserved(self):
        record = _record('1^done,bkpt={number="1"},bkpt={number="2"}')
        self.assertEqual([item["number"] for item in record.results["bkpt"]], ["1", "2"])
        scripted = _record(r'1^done,bkpt={number="1",script={"silent","printf \"sample\\n\"","continue"}}')
        self.assertEqual(scripted.results["bkpt"]["script"], ["silent", 'printf "sample\\n"', "continue"])


@unittest.skipUnless(hasattr(os, "pidfd_open"), "Terminal keeper requires Linux pidfds")
class TestTerminalKeeper(unittest.TestCase):
    """Exercise PTY hangup/reopen independently of any particular inferior."""

    def test_slave_reopen_resumes_output_and_target_exit_wakes_idle_keeper(self):
        master, slave = os.openpty()
        pidfd = None
        target = keeper = None
        try:
            path = os.ttyname(slave)
            os.set_blocking(master, False)
            os.set_blocking(slave, False)
            target = subprocess.Popen(  # pylint:disable=consider-using-with
                [sys.executable, "-P", "-c", "import sys; sys.stdin.buffer.read()"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            pidfd = os.pidfd_open(target.pid)
            keeper = subprocess.Popen(  # pylint:disable=consider-using-with
                [sys.executable, "-P", _terminal_keeper.__file__, str(master), str(pidfd)],
                pass_fds=(master, pidfd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert keeper.stdout is not None
            self.assertTrue(select.select([keeper.stdout], [], [], 5)[0], "Keeper did not acknowledge startup")
            self.assertEqual(os.read(keeper.stdout.fileno(), 1), b"R")

            def write_output(descriptor: int):
                data = b"x" * (256 * 1024)
                deadline = time.monotonic() + 3
                while data:
                    remaining = deadline - time.monotonic()
                    self.assertGreater(remaining, 0, "Keeper stopped draining target output")
                    self.assertTrue(select.select([], [descriptor], [], remaining)[1], "PTY output remained blocked")
                    with suppress(BlockingIOError):
                        data = data[os.write(descriptor, data) :]

            write_output(slave)  # Positive control before the hangup.
            os.close(slave)
            slave = None
            stat = Path(f"/proc/{keeper.pid}/stat")
            before = sum(int(value) for value in stat.read_text(encoding="ascii").split()[13:15])
            time.sleep(0.5)
            after = sum(int(value) for value in stat.read_text(encoding="ascii").split()[13:15])
            self.assertLess(after - before, os.sysconf("SC_CLK_TCK") // 5 + 1, "Idle keeper is spinning")
            slave = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            write_output(slave)
            os.close(slave)
            slave = None
            target.terminate()
            target.wait(timeout=5)
            self.assertEqual(keeper.wait(timeout=2), 0)
        finally:
            for process in (target, keeper):
                if process is not None:
                    _terminate(process)
            for descriptor in (master, slave, pidfd):
                if descriptor is not None:
                    os.close(descriptor)


class TestRuntimeMappings(unittest.TestCase):
    """Relocate mapped ELF segments and reject ambiguous module identities."""

    def test_proc_maps_paths_spaces_and_permissions(self):
        regions = parse_proc_maps("7f000-81000 r-xp 00002000 08:01 33 /a\\040game\n81000-82000 rw-p 0 00:00 0\n")
        self.assertEqual(regions[0].path, "/a game")
        self.assertEqual(regions[0].offset, 0x2000)
        self.assertEqual(regions[1].path, "")
        with self.assertRaises(RuntimeErrorBase):
            parse_proc_maps("not a process map")

    def test_nonzero_linked_base_and_relro_split(self):
        segments = [LoadSegment(0, 0x400000, 0x1000, 0x1000, 4), LoadSegment(0x1D00, 0x402D00, 0x700, 0x900, 6)]
        regions = [
            MemoryMapping(0x700000, 0x701000, "r--p", 0, "00:01", 1, "/game"),
            MemoryMapping(0x702000, 0x703000, "r--p", 0x1000, "00:01", 1, "/game"),
            MemoryMapping(0x703000, 0x704000, "rw-p", 0x2000, "00:01", 1, "/game"),
        ]
        self.assertEqual(load_bias(regions, segments), 0x300000)
        module = {
            "id": "id",
            "path": "/game",
            "load_bias": 0x300000,
            "linked_base": 0x400000,
            "ranges": [region.as_dict() for region in regions],
        }
        self.assertEqual(static_to_runtime(module, 0x400040, 0x400000), 0x700040)
        self.assertEqual(runtime_to_static(module, 0x703040, 0x400000), 0x403040)
        self.assertEqual(select_module([module], "/game", None), module)
        with self.assertRaises(RuntimeErrorBase):
            static_to_runtime(module, 0x401040, 0x400000)
        with self.assertRaises(RuntimeErrorBase):
            select_module([module, module], "/game", None)

    def test_conflicting_or_ambiguous_load_bias_is_rejected(self):
        regions = [MemoryMapping(0x7000, 0x8000, "r--p", 0, "00:01", 1, "/game")]
        with self.assertRaises(RuntimeErrorBase):
            load_bias(regions, [LoadSegment(0, 0x1000, 4096, 4096, 4), LoadSegment(0, 0x2000, 4096, 4096, 4)])
        with self.assertRaises(RuntimeErrorBase):
            load_bias(regions, [LoadSegment(0x4000, 0x4000, 4096, 4096, 4)])

    def test_real_fixture_program_headers_and_build_ids(self):
        for name in ("2048.pie", "2048.nonpie", "2048.stripped"):
            with self.subTest(name=name):
                segments = elf_load_segments(str(FIXTURES / name))
                self.assertGreater(len(segments), 1)
                build_id, address = elf_build_id(str(FIXTURES / name))
                self.assertTrue(build_id)
                assert address is not None
                self.assertGreater(address, 0)
        self.assertEqual(elf_build_id(str(FIXTURES / "2048.pie")), elf_build_id(str(FIXTURES / "2048.stripped")))


class TestRuleGeneration(unittest.TestCase):
    """Check generated GDB hook commands and bounded sample history."""

    def test_monitor_clamp_and_custom_commands(self):
        monitor = GDBRuntime.preview_rule("player.position.x", rule_id="r3")
        self.assertIn("output /r (player.position.x)", monitor)
        self.assertEqual(monitor[-1], "continue")
        clamp = GDBRuntime.preview_rule("*(unsigned int*)0x1234", "clamp", "2048")
        self.assertIn("set variable (*(unsigned int*)0x1234) = (2048)", clamp)
        custom = GDBRuntime.preview_rule("score", "custom", commands=["set $x = 1", "continue"])
        self.assertEqual(custom.count("continue"), 1)
        with self.assertRaises(RuntimeErrorBase):
            GDBRuntime.preview_rule("score", "clamp")
        with self.assertRaises(RuntimeErrorBase):
            GDBRuntime.preview_rule("score\nquit")

    def test_bounded_samples_and_snapshot_isolation(self):
        runtime = GDBRuntime(history_limit=2)
        runtime._rules["r1"] = {"id": "r1", "label": "Health", "samples": [], "last_value": None}
        for value in ("1.25", "0x123 <object>", "{x = 3, y = 4}"):
            runtime._stream("~", "@@AM_RULE_r1_BEGIN@@")
            runtime._stream("~", value)
            runtime._stream("~", "@@AM_RULE_r1_END@@\n")
        first = runtime.snapshot()
        self.assertEqual(len(first["rules"][0]["samples"]), 2)
        self.assertEqual(first["rules"][0]["last_value"], "{x = 3, y = 4}")
        self.assertEqual(len(first["events"]), 2)
        first["rules"].clear()
        self.assertEqual(len(runtime.snapshot()["rules"]), 1)
        # Inferior output cannot impersonate a GDB hook sample.
        runtime._stream("@", "@@AM_RULE_r1_BEGIN@@fake@@AM_RULE_r1_END@@")
        self.assertEqual(runtime.snapshot()["rules"][0]["last_value"], "{x = 3, y = 4}")
        runtime._stream("~", "@@AM")
        runtime._stream("~", "_RULE_r1_BEGIN@@")
        runtime._stream("&", "Cannot access memory\n")
        self.assertIn("Cannot access memory", runtime.snapshot()["rules"][0]["error"])
        runtime._stream("~", "@@AM_RULE_r1_BEGIN@@1.5@@AM_RULE_r1_END@@")
        self.assertEqual(runtime.snapshot()["rules"][0]["last_value"], "1.5")
        self.assertIsNone(runtime.snapshot()["rules"][0]["error"])

    def test_disconnected_operations_fail_clearly(self):
        runtime = GDBRuntime()
        for operation in (
            lambda: runtime.evaluate("1"),
            lambda: runtime.read_memory(0, 4),
            lambda: runtime.add_breakpoint("main"),
            runtime.interrupt,
            lambda: runtime.send_input("x"),
            lambda: runtime.checked(lambda: 1, generation=1),
        ):
            with self.assertRaises(RuntimeErrorBase):
                operation()

    def test_console_lifecycle_rejected_and_process_events_invalidate_bindings(self):
        runtime = GDBRuntime()
        for command in (
            "run",
            "r",
            "file other",
            "fil other",
            "attach 123",
            "att 123",
            "target remote localhost:123",
            "tar remote localhost:123",
            "set architecture arm",
            "set arch arm",
            "set processor arm",
            "symbol-f",
            "exec-f other",
        ):
            with self.subTest(command=command), self.assertRaisesRegex(RuntimeErrorBase, "lifecycle"):
                runtime.execute_console(command)
        with self.assertRaisesRegex(RuntimeErrorBase, "lifecycle"):
            GDBRuntime.preview_rule("score", "custom", commands=["run"])
        for command in ("s", "f 0", "d 1", "print 1"):
            GDBRuntime._validate_user_commands(command)
        generation = runtime.snapshot()["generation"]
        self.assertEqual(runtime.checked(lambda: 42, generation, states={"disconnected"}), 42)
        runtime._receive(MIRecord("=", "thread-group-started", {"pid": "123"}))
        with self.assertRaisesRegex(RuntimeErrorBase, "session changed"):
            runtime.checked(lambda: 42, generation, states={"disconnected"})


@unittest.skipUnless(GDB, "GDB is needed for live MI integration")
class TestMITransport(unittest.TestCase):
    """Exercise correlation and failure cleanup against a real GDB process."""

    def test_tokens_console_output_and_gdb_errors(self):
        records = []
        assert GDB is not None
        transport = MITransport(GDB, records.append)
        self.addCleanup(transport.close)
        self.assertEqual(transport.command('-data-evaluate-expression "2+3"')[0]["value"], "5")
        _, output = transport.command('-interpreter-exec console "echo hello\\n"')
        self.assertIn("hello", output)
        with self.assertRaises(MIError):
            transport.command("-not-a-real-command")
        self.assertGreaterEqual(len({record.token for record in records if record.token}), 3)
        transport.close()
        with self.assertRaises(MIError):
            transport.command("-gdb-version")

    def test_timeout_disconnects_and_closes_process(self):
        assert GDB is not None
        transport = MITransport(GDB, lambda _record: None, timeout=0.1)
        self.addCleanup(transport.close)
        with self.assertRaisesRegex(MIError, "timed out"):
            transport.command('-interpreter-exec console "python import time; time.sleep(10)"')
        self.assertIsNotNone(transport.process.poll())

    def test_eof_wakes_pending_command(self):
        assert GDB is not None
        transport = MITransport(GDB, lambda _record: None)
        self.addCleanup(transport.close)
        errors = []

        def pending():
            try:
                transport.command('-interpreter-exec console "python import time; time.sleep(10)"')
            except MIError as exc:
                errors.append(exc)

        thread = threading.Thread(target=pending)
        thread.start()
        deadline = time.monotonic() + 5
        while not transport._pending and time.monotonic() < deadline:
            time.sleep(0.01)
        transport.process.kill()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertTrue(errors)


@unittest.skipUnless(
    GDB and platform.system() == "Linux" and platform.machine().lower() in ("x86_64", "amd64"),
    "Live fixtures require GDB on Linux x86-64",
)
class TestLiveGDBRuntime(unittest.TestCase):
    """Exercise live inferior control, inspection, mappings, and trainer rules."""

    def setUp(self):
        assert GDB is not None
        self.runtime = GDBRuntime(GDB, timeout=20)
        self.addCleanup(self.runtime.close)

    def launch_slide(self, name="2048.pie"):
        snapshot = self.runtime.launch(str(FIXTURES / name), ["test"])
        self.assertEqual(snapshot["state"], "stopped")
        self.assertIsNotNone(snapshot["pid"])
        stopping_bp = self.runtime.add_breakpoint("slideArray")
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        snapshot = self.runtime.refresh()
        self.assertEqual(snapshot["frame"]["func"], "slideArray")
        return snapshot, stopping_bp

    def test_pie_nonpie_stripped_mapping_and_build_identity(self):
        for name in ("2048.pie", "2048.nonpie", "2048.stripped"):
            with self.subTest(name=name):
                snapshot = self.runtime.launch(str(FIXTURES / name), ["test"])
                module = select_module(snapshot["modules"], str(FIXTURES / name), None)
                static_base = 0x400000  # CLE's usual rebased analysis address for PIE.
                location = self.runtime.static_to_runtime(static_base + 0x100, static_base)
                self.assertEqual(self.runtime.runtime_to_static(location, static_base), static_base + 0x100)
                self.assertEqual(self.runtime.read_memory(module["start"], 4), b"\x7fELF")
                self.assertEqual(module["build_id"], elf_build_id(str(FIXTURES / name))[0])
                self.assertTrue(snapshot["capabilities"]["relocate"])
                self.runtime.stop()
                with self.assertRaises(RuntimeErrorBase):
                    self.runtime.static_to_runtime(static_base, static_base)

    def test_launch_arguments_cwd_and_environment_are_literal(self):
        self.runtime.launch(
            str(FIXTURES / "2048.pie"),
            ["a b", "$(literal)", 'a"b'],
            cwd=str(FIXTURES),
            env={"AM_RUNTIME_TEST": 'a b"c', "AM_RUNTIME_EMPTY": ""},
        )
        self.runtime.add_breakpoint("main")
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.evaluate("argc"), "4")
        self.assertIn('"a b"', self.runtime.evaluate("argv[1]"))
        self.assertIn("$(literal)", self.runtime.evaluate("argv[2]"))
        self.assertIn(r"a\"b", self.runtime.evaluate("argv[3]"))
        self.assertIn('AM_RUNTIME_TEST = a b"c', self.runtime.execute_console("show environment AM_RUNTIME_TEST"))
        self.assertIn(str(FIXTURES), self.runtime.execute_console("pwd"))

    def test_launch_argument_bytes_and_rejection_before_session_mutation(self):
        arguments = ["\t", "\x01", "\a", "\x1b", "\x7f", r"\t", 'a"b', "a b", "é", "", "'quoted'"]
        self.runtime.launch(str(FIXTURES / "2048.pie"), arguments)
        self.runtime.add_breakpoint("main", temporary=True)
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertEqual(int(self.runtime.evaluate("argc")), len(arguments) + 1)
        for index, argument in enumerate(arguments, 1):
            with self.subTest(argument=argument):
                address = int(self.runtime.evaluate(f"(unsigned long)argv[{index}]"), 0)
                expected = argument.encode("utf-8") + b"\0"
                self.assertEqual(self.runtime.read_memory(address, len(expected)), expected)
        self.runtime.stop()
        original = self.runtime.snapshot()
        for argument in ("\n", "\r", "\0", "\ud800"):
            with self.subTest(argument=repr(argument)), self.assertRaisesRegex(RuntimeErrorBase, "argument"):
                self.runtime.launch(str(FIXTURES / "2048.pie"), [argument])
            self.assertEqual(self.runtime.snapshot()["generation"], original["generation"])
            self.assertEqual(self.runtime.state, "exited")

    def test_watchpoint_continuation_conflicts_fail_closed(self):
        _, stopping = self.launch_slide()
        self.runtime.remove_breakpoint(stopping["number"])
        score = int(self.runtime.evaluate("(unsigned long)score"), 0)
        expression = f"*(unsigned int*)0x{score:x}"
        alias = f"*(unsigned int *)(0x{score:x})"
        rule = self.runtime.add_rule("Score", expression)
        for location, kind in (
            (alias, "write"),
            (f"*(unsigned char*)0x{score + 1:x}", "write"),
            ("*array", "write"),
            ("slideArray", "execute"),
        ):
            with self.subTest(location=location), self.assertRaisesRegex(RuntimeErrorBase, "auto-continue"):
                self.runtime.add_breakpoint(location, kind=kind)
        with self.assertRaisesRegex(RuntimeErrorBase, "auto-continue"):
            self.runtime.add_rule("Alias", alias)
        with self.assertRaisesRegex(RuntimeErrorBase, "auto-continue"):
            self.runtime.add_rule("Execution", "*score", trigger="slideArray")
        # One physical command list can run multiple rules for the exact same trigger.
        second = self.runtime.add_rule("Second", expression)
        self.assertEqual(rule["breakpoint"], second["breakpoint"])
        self.runtime.update_rule(rule["id"], enabled=False)
        self.runtime.update_rule(second["id"], enabled=False)
        watch = self.runtime.add_breakpoint(alias, kind="write")
        with self.assertRaisesRegex(RuntimeErrorBase, "auto-continue"):
            self.runtime.update_rule(rule["id"], enabled=True)
        self.runtime.enable_breakpoint(watch["number"], False)
        self.runtime.update_rule(rule["id"], enabled=True)
        with self.assertRaisesRegex(RuntimeErrorBase, "auto-continue"):
            self.runtime.enable_breakpoint(watch["number"])
        self.runtime.update_rule(second["id"], enabled=True)
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        rules = self.runtime.snapshot()["rules"]
        self.assertTrue(rules[0]["samples"])
        self.assertEqual([s["value"] for s in rules[0]["samples"]], [s["value"] for s in rules[1]["samples"]])
        self.assertEqual(self.runtime.state, "exited")

        _, stopping = self.launch_slide()
        self.runtime.remove_breakpoint(stopping["number"])
        score = int(self.runtime.evaluate("(unsigned long)score"), 0)
        expression = f"*(unsigned int*)0x{score:x}"
        self.runtime.add_breakpoint(expression, kind="write")
        with self.assertRaisesRegex(RuntimeErrorBase, "auto-continue"):
            self.runtime.add_rule("Score alias", f"*(unsigned int *)(0x{score:x})")
        with self.assertRaisesRegex(RuntimeErrorBase, "auto-continue"):
            self.runtime.add_rule("Execution", "*score", trigger="slideArray")
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.snapshot()["stop_reason"], "watchpoint-trigger")

    def test_inspection_memory_registers_threads_frames_and_generation(self):
        snapshot, _ = self.launch_slide()
        score = int(self.runtime.evaluate("(unsigned long)score"), 0)
        self.assertEqual(self.runtime.read_memory(score, 4), b"\0" * 4)
        self.runtime.write_memory(score, (128).to_bytes(4, "little"))
        self.assertEqual(self.runtime.evaluate("*score"), "128")
        self.runtime.write_memory(score, b"\0" * 4)
        self.assertTrue(snapshot["threads"])
        self.assertGreater(len(snapshot["frames"]), 1)
        self.assertTrue(any(register["name"] == "rip" for register in snapshot["registers"]))
        original = self.runtime.evaluate("$rax")
        self.runtime.write_register("rax", "123")
        self.assertEqual(self.runtime.evaluate("$rax"), "123")
        self.runtime.write_register("rax", original)
        self.runtime.select_thread(snapshot["threads"][0]["id"])
        self.assertEqual(self.runtime.select_frame(1)["frame"]["func"], "testSucceed")
        self.runtime.select_frame(0)
        generation = snapshot["generation"]
        pc = self.runtime.refresh()["frame"]["addr"]
        self.assertEqual(self.runtime.checked(lambda: self.runtime.evaluate("*score"), generation, pc), "0")
        self.assertEqual(
            self.runtime.checked(lambda: 42, generation, pc, thread_id=snapshot["selected_thread"], frame_level=0), 42
        )
        with self.assertRaisesRegex(RuntimeErrorBase, "stack frame changed"):
            self.runtime.checked(lambda: None, generation, pc, frame_level=1)
        with self.assertRaisesRegex(RuntimeErrorBase, "thread changed"):
            self.runtime.checked(lambda: None, generation, pc, thread_id="999999")
        with self.assertRaisesRegex(RuntimeErrorBase, "frame moved"):
            self.runtime.checked(lambda: None, generation, pc + 1)
        with self.assertRaisesRegex(RuntimeErrorBase, "session changed"):
            self.runtime.checked(lambda: None, generation + 1)
        with self.assertRaises(RuntimeErrorBase):
            self.runtime.read_memory(1, 4)

    def test_stepping_finish_breakpoint_enable_condition_and_removal(self):
        _, stopping_bp = self.launch_slide()
        self.runtime.enable_breakpoint(stopping_bp["number"], False)
        self.runtime.step_instruction()
        self.runtime.wait_for_stop()
        self.runtime.next_instruction()
        self.runtime.wait_for_stop()
        self.runtime.step_source()
        self.runtime.wait_for_stop()
        self.runtime.next_source()
        self.runtime.wait_for_stop()
        self.runtime.finish()
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.refresh()["frame"]["func"], "testSucceed")
        self.runtime.enable_breakpoint(stopping_bp["number"])
        self.runtime.remove_breakpoint(stopping_bp["number"])
        self.assertEqual(self.runtime.refresh()["breakpoints"], [])
        conditional = self.runtime.add_breakpoint("slideArray", condition="*score == 0", temporary=True)
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.refresh()["frame"]["func"], "slideArray")
        self.assertFalse(any(bp["number"] == conditional["number"] for bp in self.runtime.snapshot()["breakpoints"]))

    def test_read_and_access_watchpoints(self):
        _, stopping_bp = self.launch_slide()
        self.runtime.remove_breakpoint(stopping_bp["number"])
        array = int(self.runtime.evaluate("(unsigned long)array"), 0)
        write_watchpoint = self.runtime.add_breakpoint(f"*(unsigned char*)0x{array:x}", kind="write")
        self.assertEqual(write_watchpoint["enabled"], "y")
        self.runtime.remove_breakpoint(write_watchpoint["number"])
        for kind in ("read", "access"):
            watchpoint = self.runtime.add_breakpoint(f"*(unsigned char*)0x{array:x}", kind=kind)
            self.assertEqual(watchpoint["enabled"], "y")
            self.runtime.enable_breakpoint(watchpoint["number"], False)
            self.assertEqual(self.runtime.refresh()["breakpoints"][0]["enabled"], "n")
            self.runtime.enable_breakpoint(watchpoint["number"])
            self.runtime.continue_execution()
            self.runtime.wait_for_stop()
            self.assertIn("watchpoint", self.runtime.snapshot()["stop_reason"])
            self.runtime.remove_breakpoint(watchpoint["number"])

    def test_monitor_execution_hook_samples_and_script_preview(self):
        _, stopping_bp = self.launch_slide()
        self.runtime.remove_breakpoint(stopping_bp["number"])
        rule = self.runtime.add_rule("Score", "*score", trigger="slideArray")
        self.assertIn("output /r (*score)", rule["generated_script"])
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.state, "exited")
        rules = self.runtime.snapshot()["rules"]
        self.assertEqual(len(rules[0]["samples"]), 12)  # first invocation was already paused at entry
        self.assertTrue(all(sample["value"] == "0" for sample in rules[0]["samples"]))

    def test_custom_silent_stop_is_confirmed_and_hook_error_is_visible(self):
        _, stopping_bp = self.launch_slide()
        self.runtime.remove_breakpoint(stopping_bp["number"])
        # An explicit continue in an untaken branch intentionally leaves GDB
        # stopped. MI emits only *stopped without a reason for a silent hook.
        rule = self.runtime.add_rule(
            "Pause condition",
            "*score",
            mode="custom",
            trigger="slideArray",
            commands="if 0\ncontinue\nend",
        )
        self.runtime.continue_execution()
        stopped = self.runtime.wait_for_stop()
        self.assertEqual(stopped["state"], "stopped")
        self.assertEqual(stopped["stop_reason"], "hook-stopped")
        self.assertEqual(self.runtime.evaluate("*score"), "0")
        self.runtime.remove_rule(rule["id"])
        self.runtime.add_rule("Bad expression", "*(int*)0x1", trigger="slideArray")
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertIn("Cannot access memory", self.runtime.snapshot()["rules"][0]["error"])

    def test_clamp_update_disable_remove_and_custom_hook(self):
        _, stopping_bp = self.launch_slide()
        score = int(self.runtime.evaluate("(unsigned long)score"), 0)
        expression = f"*(unsigned int*)0x{score:x}"
        rule = self.runtime.add_rule("Freeze score", expression, "clamp", "2048", trigger="2048.c:395", enabled=False)
        self.assertFalse(rule["enabled"])
        self.runtime.remove_breakpoint(stopping_bp["number"])
        updated = self.runtime.update_rule(rule["id"], enabled=True, value="4096")
        self.assertIn("4096", updated["generated_script"])
        # A raw address has no lexical lifetime. Stop while score is still live,
        # then remove the clamp before this stack slot can be reused on return.
        after = self.runtime.add_breakpoint("2048.c:399", condition="score == 4096")
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.evaluate(expression), "4096")
        samples = self.runtime.snapshot()["rules"][0]["samples"]
        self.assertTrue(samples)
        self.assertTrue(all(sample["value"] == "4096" for sample in samples))
        self.runtime.remove_rule(rule["id"])
        self.runtime.remove_breakpoint(after["number"])
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.state, "exited")
        # Starting a new session clears concrete-address rules.
        _, stopping_bp = self.launch_slide()
        self.assertEqual(self.runtime.snapshot()["rules"], [])
        self.runtime.remove_breakpoint(stopping_bp["number"])
        self.runtime.evaluate("$seen = 0")
        rule = self.runtime.add_rule(
            "Custom", "*score", "custom", trigger="slideArray", commands="set $seen = 17\ndisable $bpnum"
        )
        edited = self.runtime.update_rule(rule["id"], commands=f"set $seen = 19\ndisable {rule['breakpoint']}")
        self.assertIn("set $seen = 19", edited["generated_script"])
        self.runtime.add_breakpoint("2048.c:395", condition="$seen == 19")
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.evaluate("$seen"), "19")
        self.runtime.update_rule(rule["id"], enabled=False)
        self.runtime.remove_rule(rule["id"])
        self.assertEqual(self.runtime.snapshot()["rules"], [])
        self.runtime.execute_console("set $one = 11\nset $two = 22")
        self.assertEqual(self.runtime.evaluate("$one + $two"), "33")

    def test_shared_trigger_runs_all_rules_and_rejects_stopping_conflicts(self):
        snapshot, stopping_bp = self.launch_slide()
        with self.assertRaisesRegex(RuntimeErrorBase, "auto-continue"):
            self.runtime.add_rule("First", "*score", trigger="slideArray")
        self.runtime.enable_breakpoint(stopping_bp["number"], False)
        first = self.runtime.add_rule("First", "*score", trigger="slideArray")
        second = self.runtime.add_rule("Second", "array[0]", trigger=f"*0x{snapshot['frame']['addr']:x}")
        clamp = self.runtime.add_rule("Clamp", "*score", mode="clamp", value="0", trigger="slideArray")
        self.runtime.evaluate("$hits = 0")
        custom = self.runtime.add_rule(
            "Custom", "*score", mode="custom", trigger="slideArray", commands="set $hits += 1"
        )
        self.assertEqual({rule["breakpoint"] for rule in (first, second, clamp, custom)}, {first["breakpoint"]})
        with self.assertRaisesRegex(RuntimeErrorBase, "auto-continue"):
            self.runtime.add_breakpoint("slideArray")
        with self.assertRaisesRegex(RuntimeErrorBase, "auto-continue"):
            self.runtime.enable_breakpoint(stopping_bp["number"])
        with self.assertRaisesRegex(RuntimeErrorBase, "entries in Rules"):
            self.runtime.enable_breakpoint(first["breakpoint"], False)
        with self.assertRaisesRegex(RuntimeErrorBase, "entries in Rules"):
            self.runtime.remove_breakpoint(first["breakpoint"])
        for command in ("continue", "cont", "fg", "c&", "fin", "j", "rc", "stepi", "signal 0"):
            with self.subTest(command=command), self.assertRaisesRegex(RuntimeErrorBase, "omit execution-resume"):
                self.runtime.update_rule(custom["id"], commands=command)
        self.runtime.update_rule(second["id"], enabled=False)
        self.assertFalse(
            next(rule for rule in self.runtime.refresh()["rules"] if rule["id"] == second["id"])["enabled"]
        )
        self.runtime.update_rule(second["id"], enabled=True)
        final_print = self.runtime.add_breakpoint("printf")
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.evaluate("$hits"), "12")
        for rule in self.runtime.snapshot()["rules"]:
            self.assertEqual(len(rule["samples"]), 12)
        self.runtime.remove_rule(second["id"])
        self.assertTrue(any(bp["number"] == first["breakpoint"] for bp in self.runtime.refresh()["breakpoints"]))
        self.runtime.remove_breakpoint(final_print["number"])
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.state, "exited")

    def test_terminal_input_pause_running_gates_and_clean_stop(self):
        output_ready = threading.Event()

        def received(event, payload):
            if event == "output" and payload["channel"] == "@":
                output_ready.set()

        self.addCleanup(self.runtime.subscribe(received))
        snapshot = self.runtime.launch(str(FIXTURES / "2048.pie"), stop_at_entry=False)
        self.assertIn(snapshot["state"], ("ready", "running"))
        deadline = time.monotonic() + 5
        while self.runtime.state != "running" and time.monotonic() < deadline:
            time.sleep(0.01)
        with self.assertRaisesRegex(RuntimeErrorBase, "Pause"):
            self.runtime.evaluate("1")
        stopped = self.runtime.interrupt()
        self.assertEqual(stopped["state"], "stopped")
        self.assertTrue(stopped["capabilities"]["input"])
        self.runtime.continue_execution()
        self.runtime.send_input("qy")
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.state, "exited")
        # PTY output and GDB exit arrive on independent reader threads.
        self.assertTrue(output_ready.wait(timeout=2), "Target output was not delivered")
        self.assertTrue(any(item["channel"] == "@" for item in self.runtime.snapshot()["output"]))

    def test_attach_detach_leaves_the_target_alive(self):
        # Set ptrace opt-in inside a separate interpreter, then exec the fixed
        # fixture. preexec_fn could deadlock in this multithreaded test process.
        launcher = """import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
if libc.prctl(0x59616D61, ctypes.c_ulong(-1).value, 0, 0, 0):
    raise OSError(ctypes.get_errno(), "PR_SET_PTRACER_ANY failed")
os.execv(sys.argv[1], [sys.argv[1]])
"""
        # unittest cleanup also runs when an assertion fails before attach.
        process = subprocess.Popen(  # pylint: disable=consider-using-with
            [sys.executable, "-P", "-c", launcher, str(FIXTURES / "2048.pie")],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(_terminate, process)
        executable = Path(f"/proc/{process.pid}/exe")
        deadline = time.monotonic() + 5
        while process.poll() is None and executable.resolve() != (FIXTURES / "2048.pie").resolve():
            self.assertLess(time.monotonic(), deadline, "ptrace launcher did not exec the fixture")
            time.sleep(0.01)
        self.assertIsNone(process.poll(), "ptrace launcher exited before attach")
        snapshot = self.runtime.attach(process.pid, str(FIXTURES / "2048.pie"))
        self.assertEqual(snapshot["pid"], process.pid)
        self.assertEqual(snapshot["state"], "stopped")
        self.runtime.detach()
        self.runtime.close()
        self.assertIsNone(process.poll())
        process.kill()
        process.wait(timeout=5)

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Detached terminal ownership requires Linux pidfds")
    def test_local_detach_survives_close_reconnect_and_application_exit(self):
        helper = Path(__file__).with_name("gdb_detach_lifecycle.py")
        for mode in ("close", "reconnect", "exit", "stop"):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    [sys.executable, "-P", str(helper), str(FIXTURES / "2048.pie"), mode],
                    capture_output=True,
                    text=True,
                    timeout=40,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(GDBSERVER, "gdbserver is needed for remote integration")
    def test_remote_control_without_guessing_host_relocation(self):
        assert GDBSERVER is not None
        # Cleanup reaps the server and closes pipes even if connection fails.
        process = subprocess.Popen(  # pylint: disable=consider-using-with
            [GDBSERVER, "--once", "127.0.0.1:0", str(FIXTURES / "2048.pie"), "test"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(_terminate, process)
        lines = queue.Queue()
        error_stream = process.stderr
        assert error_stream is not None

        def reader():
            for line in error_stream:
                lines.put(line)

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        port = None
        while time.monotonic() < deadline:
            line = lines.get(timeout=max(0.1, deadline - time.monotonic()))
            if "Listening on port " in line:
                port = int(line.rsplit(" ", 1)[1])
                break
        self.assertIsNotNone(port)
        snapshot = self.runtime.connect_remote(f"127.0.0.1:{port}", str(FIXTURES / "2048.pie"))
        self.assertEqual(snapshot["state"], "stopped")
        self.assertIn("Remote module relocation", snapshot["mapping_error"])
        with self.assertRaises(RuntimeErrorBase):
            self.runtime.static_to_runtime(0x400100, 0x400000)
        self.runtime.add_breakpoint("slideArray")
        self.runtime.continue_execution()
        self.runtime.wait_for_stop()
        self.assertEqual(self.runtime.refresh()["frame"]["func"], "slideArray")
        self.runtime.stop()
        process.wait(timeout=10)
        thread.join(timeout=5)
        error_stream.close()
