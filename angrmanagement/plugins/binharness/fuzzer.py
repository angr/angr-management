from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import binharness

if TYPE_CHECKING:
    from pathlib import Path

log = logging.getLogger(name=__name__)
log.setLevel(logging.DEBUG)


class FuzzerExecutor(binharness.InjectableExecutor):
    process: binharness.Process
    base_addr: int = 0xAAAAAAAA0000

    def __init__(self, fuzzer_binary: Path):
        super().__init__(fuzzer_binary)

    def _run_target(self, target: binharness.Target) -> binharness.Process:
        """Run a target in an environment."""
        self.workdir = self.environment.get_tempdir() / ("fuzz-work-" + binharness.util.generate_random_suffix())
        log.debug(self.env_path)
        log.debug(self.workdir)
        self.environment.run_command("/bin/mkdir", self.workdir)
        self.environment.run_command("/bin/mkdir", self.workdir / "input")
        self.environment.run_command("/bin/mkdir", self.workdir / "output")
        self.environment.run_command("/bin/mkdir", self.workdir / "solution")
        self.environment.run_command("/bin/mkdir", self.workdir / "events")
        with self.environment.open_file(self.workdir / "input" / "1", "wb") as f:
            f.write(b"Hello, world!")
        self.process = self.environment.run_command(
            self.env_path,
            "--input",
            self.workdir / "input",
            "--output",
            self.workdir / "output",
            "--solution",
            self.workdir / "solution",
            "--bitmap",
            self.workdir / "bitmap",
            "--events",
            self.workdir / "events",
            "--",
            target.main_binary,
            *target.args,
            env=target.env,
        )
        return self.process

    def get_outputs_list(self):
        a = self.environment.run_command("/bin/ls", self.workdir / "output").stdout.read()
        return [b.decode("utf-8") for b in a.strip().split(b"\n") if b]

    def get_solutions_list(self):
        a = self.environment.run_command("/bin/ls", self.workdir / "solution").stdout.read()
        return [b.decode("utf-8") for b in a.strip().split(b"\n") if b]

    def get_output(self, output_id):
        with self.environment.open_file(self.workdir / "output" / output_id, "rb") as f:
            return f.read()

    def get_solution(self, solution_id):
        with self.environment.open_file(self.workdir / "solution" / solution_id, "rb") as f:
            return f.read()

    def get_bitmap(self):
        with self.environment.open_file(self.workdir / "bitmap", "rb") as f:
            return f.read()

    def get_events_list(self):
        a = [
            e.decode("utf-8")
            for e in self.environment.run_command("/bin/ls", self.workdir / "events").stdout.read().strip().split(b"\n")
            if e
        ]
        return a

    def get_event(self, event_id):
        with self.environment.open_file(self.workdir / "events" / event_id, "rb") as f:
            return json.loads(f.read())
