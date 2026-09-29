# SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
# SPDX-License-Identifier: MIT

"""Isolated Linux process-group regression; no orphan processes left to PID 1."""

import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import jobs


def exercise_group_cleanup(root):
    # This test process alone adopts and reaps the helper when its leader exits.
    # Do not change the unittest runner's child-reaping semantics.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER)")
    helper = (
        "import os,signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "print(os.getpid(), flush=True); time.sleep(60)"
    )
    leader = (
        "import os,signal,subprocess,sys,time\n"
        "from pathlib import Path\n"
        "def stop(*_):\n"
        "    Path(sys.argv[1]).write_text('leader exited on TERM')\n"
        "    sys.exit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "subprocess.Popen([sys.executable, '-c', sys.argv[2]])\n"
        "time.sleep(60)\n"
    )
    marker = root / "leader-exited"
    child = subprocess.Popen(
        [sys.executable, "-c", leader, str(marker), helper],
        stdout=subprocess.PIPE, text=True, start_new_session=True,
    )
    (root / "group-pid").write_text(str(child.pid))
    helper_pid = None
    try:
        helper_pid = int(child.stdout.readline())  # Outer test has a hard timeout.
        jobs.TERMINATION_GRACE_SECONDS = 0.2
        started = time.monotonic()
        jobs.Worker([]).terminate_child(child)
        assert time.monotonic() - started < 2
        assert marker.is_file(), "leader did not exit promptly on TERM"
        assert child.returncode == 0, child.returncode
        # The leader was reaped by Worker, not by this fixture.
        try:
            os.waitpid(child.pid, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            raise AssertionError("direct child was not reaped")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            pid, status = os.waitpid(helper_pid, os.WNOHANG)
            if pid:
                helper_pid = None
                assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
                break
            time.sleep(0.01)
        else:
            raise AssertionError("TERM-ignoring helper survived group termination")
    finally:
        if helper_pid is not None or child.returncode is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait(timeout=2)
        if helper_pid is not None:
            os.waitpid(helper_pid, 0)
        child.stdout.close()


@unittest.skipUnless(sys.platform == "linux", "Linux process-group/subreaper semantics")
class ProcessGroupTests(unittest.TestCase):
    def test_exited_leader_does_not_spare_term_ignoring_helper(self):
        with tempfile.TemporaryDirectory(prefix="evectl-group-test-") as directory:
            root = Path(directory)
            child = subprocess.Popen(
                [sys.executable, __file__, "--exercise", directory],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                stdout, stderr = child.communicate(timeout=8)
                self.assertEqual(child.returncode, 0, stdout + stderr)
            finally:
                if child.poll() is None:
                    pid_file = root / "group-pid"
                    if pid_file.exists():
                        try:
                            os.killpg(int(pid_file.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    child.kill()
                    child.communicate(timeout=2)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--exercise":
        exercise_group_cleanup(Path(sys.argv[2]))
    else:
        unittest.main()
