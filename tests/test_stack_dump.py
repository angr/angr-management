"""
Test the stack dump that conftest.py arms for a test that runs too long.
"""

from __future__ import annotations

import threading
import time

from stack_dump import LateStackDump, left_behind  # pylint: disable=import-error


def _wait_in_a_frame_to_find(release: threading.Event) -> None:
    release.wait(30)


def _wait_for_a_dump(directory, needle: str) -> list[str]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        dumps = left_behind(directory)
        if dumps and needle in dumps[0]:
            return dumps
        time.sleep(0.05)
    return left_behind(directory)


def test_a_test_that_runs_too_long_leaves_every_thread_stack(tmp_path) -> None:
    # more threads than faulthandler would write, which writes the newest first and so would leave the main one out
    release = threading.Event()
    waiters = [
        threading.Thread(target=_wait_in_a_frame_to_find, args=(release,), name=f"waiter {n}") for n in range(120)
    ]
    for waiter in waiters:
        waiter.start()
    dump = LateStackDump()
    try:
        dump.arm(tmp_path, "tests/test_example.py::test_stuck", 0.2)
        dumps = _wait_for_a_dump(tmp_path, "_wait_in_a_frame_to_find")
    finally:
        release.set()
        for waiter in waiters:
            waiter.join()
        dump.disarm()

    assert len(dumps) == 1
    assert dumps[0].startswith("tests/test_example.py::test_stuck was still running after 0.2 s.")
    # every waiting thread's stack and this one's, the main thread's, which comes first
    assert "_wait_in_a_frame_to_find" in dumps[0]
    main = dumps[0].index("Thread 'MainThread'")
    assert dumps[0].count("Thread 'waiter ") == 120
    assert main < dumps[0].index("Thread 'waiter ")
    assert "test_a_test_that_runs_too_long_leaves_every_thread_stack" in dumps[0][main:]
    # disarming removes the file, so only a process killed before it disarms leaves one
    assert not left_behind(tmp_path)


def test_a_test_that_ends_in_time_leaves_nothing(tmp_path) -> None:
    dump = LateStackDump()
    dump.arm(tmp_path, "tests/test_example.py::test_quick", 0.5)
    dump.disarm()
    time.sleep(1)

    assert not left_behind(tmp_path)
    assert not list(tmp_path.iterdir())


def test_a_later_process_does_not_remove_an_earlier_one_s_dump(tmp_path) -> None:
    # a replacement xdist worker can get the pid of the one that was killed, as both objects here share one pid
    killed, replacement = LateStackDump(), LateStackDump()
    try:
        killed.arm(tmp_path, "tests/test_example.py::test_stuck", 0.1)
        dumps = _wait_for_a_dump(tmp_path, "test_stuck")
        replacement.arm(tmp_path, "tests/test_example.py::test_quick", 30)
        replacement.disarm()

        assert len(dumps) == 1
        assert left_behind(tmp_path) == dumps
    finally:
        killed.disarm()
