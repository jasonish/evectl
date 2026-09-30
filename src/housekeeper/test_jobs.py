# SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
# SPDX-License-Identifier: MIT

"""Run: make test-housekeeper (disables bytecode caches, including in subprocesses)."""

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import jobs


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class FakeStop:
    def __init__(self, clock, stop_at=None):
        self.clock = clock
        self.stop_at = stop_at
        self.stopped = False

    def is_set(self):
        return self.stopped

    def set(self):
        self.stopped = True

    def wait(self, delay):
        self.clock.now += delay
        if self.stop_at is not None and self.clock.now >= self.stop_at:
            self.set()
        return self.stopped


class FakeChild:
    pid = 12345

    def __init__(self, stubborn=False):
        self.returncode = None
        self.stubborn = stubborn
        self.waits = []

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        self.waits.append(timeout)
        self.returncode = -signal.SIGKILL if self.stubborn else -signal.SIGTERM
        return self.returncode


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "filestore"
        self.directory.mkdir()
        self.config = self.root / "config.json"
        self.settings = {"retention_days": 7, "interval_seconds": 300,
                         "timeout_seconds": 240}
        self.write_config()
        self.output = io.StringIO()
        self.redirect = contextlib.redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def write_config(self, value=None):
        if value is None:
            value = {"file_extraction": self.settings}
        self.config.write_text(json.dumps(value), encoding="utf-8")

    def job(self):
        with mock.patch.object(jobs, "FILESTORE", str(self.directory)):
            return jobs.load_jobs(self.config)[0]

    def tool(self, body):
        executable = self.root / "suricatactl"
        executable.write_text("#!{}\n{}\n".format(sys.executable, body), encoding="utf-8")
        executable.chmod(0o755)
        patcher = mock.patch.dict(os.environ, {"PATH": str(self.root)})
        patcher.start()
        self.addCleanup(patcher.stop)
        return executable

    def test_config_and_fixed_whole_filestore_command(self):
        job = jobs.load_jobs(self.config)[0]
        self.assertEqual(job.argv, ["suricatactl", "filestore", "prune",
                                   "--directory", "/var/log/suricata/filestore",
                                   "--age", "7d"])
        self.assertEqual((job.interval_seconds, job.timeout_seconds), (300, 240))
        self.settings["retention_days"] = 19
        self.write_config()
        self.assertEqual(jobs.load_jobs(self.config)[0].argv[-1], "19d")

    def test_invalid_config(self):
        for key in self.settings:
            for value in [0, -1, True, False, 1.5, "7", None, [], {}]:
                with self.subTest(key=key, value=value):
                    settings = dict(self.settings, **{key: value})
                    self.write_config({"file_extraction": settings})
                    with self.assertRaises(ValueError):
                        jobs.load_jobs(self.config)
        for value in [[], None, {}, {"file_extraction": []},
                      {"file_extraction": {}},
                      {"file_extraction": dict(self.settings, directory="/tmp")},
                      {"file_extraction": self.settings, "other": {}}]:
            self.config.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                jobs.load_jobs(self.config)
        self.config.write_text("not json", encoding="utf-8")
        self.assertEqual(jobs.main([str(self.config)]), 1)

    def test_immediate_monotonic_sequential_runs(self):
        clock = FakeClock()
        stop = FakeStop(clock)
        first, second = self.job(), self.job()
        first.interval_seconds = second.interval_seconds = 10
        second.name = "future_job"
        worker = jobs.Worker([first, second], stop, clock)
        runs = []

        def run(job):
            runs.append((job.name, clock()))
            clock.now += 12  # Longer than the interval, still no catch-up burst.
            if len(runs) == 4:
                stop.set()

        with mock.patch.object(worker, "run_job", side_effect=run):
            worker.run()
        self.assertEqual(runs, [("file_extraction", 100), ("future_job", 112),
                                ("file_extraction", 124), ("future_job", 136)])

    def test_interval_measured_from_start(self):
        clock = FakeClock()
        stop = FakeStop(clock)
        job = self.job()
        worker = jobs.Worker([job], stop, clock)
        starts = []

        def run(current):
            starts.append(clock())
            clock.now += 2
            if len(starts) == 2:
                stop.set()

        with mock.patch.object(worker, "run_job", side_effect=run):
            worker.run()
        self.assertEqual(starts, [100, 400])

    def test_nonzero_failure_is_retried_and_success_remembered(self):
        clock = FakeClock()
        stop = FakeStop(clock)
        job = self.job()
        worker = jobs.Worker([job], stop, clock)
        results = [jobs.Completion("completed", 3), jobs.Completion("completed", 0),
                   jobs.Completion("completed", 4)]

        def command(*args):
            result = results.pop(0)
            if not results:
                stop.set()
            return result

        with mock.patch.object(worker, "command", side_effect=command) as call:
            worker.run()
        self.assertEqual(call.call_count, 3)
        self.assertNotEqual(job.last_successful_completion, "never")
        output = self.output.getvalue()
        self.assertIn("exit=3", output)
        self.assertIn("exit=4", output)
        self.assertIn("elapsed=", output)
        self.assertIn("last_successful_command_completion=never", output)
        self.assertIn("does not guarantee all deletions", output)

    def test_timeout_retries_without_recording_success(self):
        clock = FakeClock()
        stop = FakeStop(clock)
        job = self.job()
        worker = jobs.Worker([job], stop, clock)
        calls = []

        def command(*args):
            calls.append(clock())
            self.assertEqual(job.last_successful_completion, "never")
            if len(calls) == 1:
                clock.now += job.timeout_seconds
                return jobs.Completion("timed out", -signal.SIGTERM)
            stop.set()
            return jobs.Completion("interrupted", -signal.SIGTERM)

        with mock.patch.object(worker, "command", side_effect=command):
            worker.run()
        self.assertEqual(calls, [100, 400])
        self.assertEqual(job.last_successful_completion, "never")
        self.assertIn("status=timed out", self.output.getvalue())

    def test_missing_directory_retries(self):
        clock = FakeClock()
        stop = FakeStop(clock)
        job = self.job()
        self.directory.rmdir()
        worker = jobs.Worker([job], stop, clock)
        original_wait = stop.wait

        def wait(delay):
            self.directory.mkdir(exist_ok=True)
            return original_wait(delay)

        def command(*args):
            stop.set()
            return jobs.Completion("completed", 0)

        with mock.patch.object(stop, "wait", side_effect=wait), \
                mock.patch.object(worker, "command", side_effect=command) as call:
            worker.run()
        self.assertEqual(call.call_count, 1)
        self.assertIn("directory is missing", self.output.getvalue())
        self.assertNotEqual(job.last_successful_completion, "never")

    def test_missing_executable_during_job_retries(self):
        worker = jobs.Worker([self.job()])
        with mock.patch.object(jobs.subprocess, "Popen", side_effect=FileNotFoundError("gone")):
            worker.run_job(worker.jobs[0])
        self.tool("pass")
        worker.run_job(worker.jobs[0])
        self.assertIn("failed: gone", self.output.getvalue())
        self.assertNotEqual(worker.jobs[0].last_successful_completion, "never")

    def test_signal_handler_only_sets_flag_and_stops_scheduling(self):
        worker = jobs.Worker([self.job()])
        with mock.patch.object(worker.stop, "set", side_effect=AssertionError("signal acquired lock")), \
                mock.patch.object(worker, "run_job") as run:
            worker.request_stop(signal.SIGTERM, None)
            worker.run()
        run.assert_not_called()
        self.assertTrue(worker.is_stopping())

    def test_timeout_terminates_and_reaps(self):
        clock = FakeClock()
        child = FakeChild()
        worker = jobs.Worker([], FakeStop(clock), clock)
        with mock.patch.object(jobs.subprocess, "Popen", return_value=child), \
                mock.patch.object(jobs.time, "sleep"), \
                mock.patch.object(jobs.os, "killpg") as kill:
            result = worker.command(["fake"], 1)
        self.assertEqual(result.status, "timed out")
        self.assertEqual(kill.call_args_list,
                         [mock.call(child.pid, signal.SIGTERM),
                          mock.call(child.pid, signal.SIGKILL)])
        self.assertEqual(child.waits, [5])

    def test_shutdown_escalates_and_reaps(self):
        clock = FakeClock()
        stop = FakeStop(clock, stop_at=100.2)
        child = FakeChild(stubborn=True)
        worker = jobs.Worker([], stop, clock)
        with mock.patch.object(jobs.subprocess, "Popen", return_value=child), \
                mock.patch.object(jobs.time, "sleep"), \
                mock.patch.object(jobs.os, "killpg") as kill:
            result = worker.command(["fake"], 240)
        self.assertEqual(result.status, "interrupted")
        self.assertEqual(kill.call_args_list,
                         [mock.call(child.pid, signal.SIGTERM),
                          mock.call(child.pid, signal.SIGKILL)])
        self.assertEqual(child.waits, [5])
        with mock.patch.object(jobs.subprocess, "Popen") as spawn:
            self.assertEqual(worker.command(["fake"], 240).status, "interrupted")
            spawn.assert_not_called()

    def test_unexpected_error_reaps_child_and_propagates(self):
        clock = FakeClock()
        stop = FakeStop(clock)
        child = FakeChild()
        worker = jobs.Worker([], stop, clock)
        with mock.patch.object(jobs.subprocess, "Popen", return_value=child), \
                mock.patch.object(jobs.time, "sleep"), \
                mock.patch.object(jobs.os, "killpg") as kill, \
                mock.patch.object(stop, "wait", side_effect=RuntimeError("broken")):
            with self.assertRaisesRegex(RuntimeError, "broken"):
                worker.command(["fake"], 10)
        self.assertEqual(kill.call_args_list,
                         [mock.call(child.pid, signal.SIGTERM),
                          mock.call(child.pid, signal.SIGKILL)])
        self.assertIsNotNone(child.returncode)

    def test_reaping_failure_is_fatal_not_an_ordinary_job_failure(self):
        job = self.job()
        worker = jobs.Worker([job])
        with mock.patch.object(worker, "command", side_effect=OSError("cannot reap")):
            with self.assertRaisesRegex(OSError, "cannot reap"):
                worker.run_job(job)

    def test_check_uses_help_only_and_leaves_filestore_untouched(self):
        record = self.root / "argv.json"
        self.tool("import json, sys\n"
                  "from pathlib import Path\n"
                  "Path({!r}).write_text(json.dumps(sys.argv[1:]))".format(str(record)))
        capture = self.directory / "disposable"
        capture.write_text("test fixture", encoding="utf-8")
        with mock.patch.object(jobs, "FILESTORE", str(self.directory)):
            self.assertEqual(jobs.main(["--check", str(self.config)]), 0)
        self.assertEqual(json.loads(record.read_text()), ["filestore", "prune", "--help"])
        self.assertEqual(list(self.directory.iterdir()), [capture])
        self.assertEqual(capture.read_text(), "test fixture")

    def test_check_missing_tool_and_incompatible_tool_are_fatal(self):
        with mock.patch.dict(os.environ, {"PATH": str(self.root)}):
            self.assertEqual(jobs.main(["--check", str(self.config)]), 1)
            self.assertEqual(jobs.main([str(self.config)]), 1)
        self.tool("import sys\nsys.exit(2)")
        self.assertEqual(jobs.main(["--check", str(self.config)]), 1)
        self.assertEqual(jobs.main([str(self.config)]), 1)
        self.assertIn("incompatible suricatactl", self.output.getvalue())

    def test_check_rejects_missing_unwritable_and_readonly_mount(self):
        self.tool("pass")
        with mock.patch.object(jobs, "FILESTORE", str(self.directory)):
            with mock.patch.object(jobs.os, "access", return_value=False):
                self.assertEqual(jobs.main(["--check", str(self.config)]), 1)
            with mock.patch.object(jobs.tempfile, "TemporaryFile",
                                   side_effect=OSError("Read-only file system")):
                self.assertEqual(jobs.main(["--check", str(self.config)]), 1)
        with mock.patch.object(jobs, "FILESTORE", str(self.root / "missing-log/filestore")):
            self.assertEqual(jobs.main(["--check", str(self.config)]), 1)

    def test_check_accepts_missing_filestore_without_creating_it(self):
        self.tool("pass")
        self.directory.rmdir()
        before = self.root.stat()
        with mock.patch.object(jobs, "FILESTORE", str(self.directory)):
            self.assertEqual(jobs.main(["--check", str(self.config)]), 0)
        self.assertFalse(self.directory.exists())
        after = self.root.stat()
        self.assertEqual((before.st_uid, before.st_gid, before.st_mode),
                         (after.st_uid, after.st_gid, after.st_mode))

    def test_check_missing_filestore_still_requires_writable_log_mount(self):
        self.tool("pass")
        self.directory.rmdir()
        with mock.patch.object(jobs, "FILESTORE", str(self.directory)):
            with mock.patch.object(jobs.os, "access", return_value=False):
                self.assertEqual(jobs.main(["--check", str(self.config)]), 1)
            with mock.patch.object(jobs.tempfile, "TemporaryFile",
                                   side_effect=OSError("Read-only file system")):
                self.assertEqual(jobs.main(["--check", str(self.config)]), 1)
        self.assertFalse(self.directory.exists())

    def test_check_existing_filestore_stat_error_is_fatal(self):
        with mock.patch.object(jobs.os, "stat", side_effect=PermissionError("denied")), \
                mock.patch.object(jobs, "check_directory") as check:
            with self.assertRaises(PermissionError):
                jobs.check_filestore_mount(str(self.directory))
        check.assert_not_called()

    def test_tool_check_timeout_fatal(self):
        worker = jobs.Worker([self.job()])
        with mock.patch.object(jobs.shutil, "which", return_value="/fake/suricatactl"), \
                mock.patch.object(worker, "command", return_value=jobs.Completion("timed out")):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                worker.check_tool()

    def test_fatal_worker_error_nonzero_and_handlers_restored(self):
        self.tool("pass")
        before = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        with mock.patch.object(jobs.Worker, "run", side_effect=RuntimeError("broken worker")):
            self.assertEqual(jobs.main([str(self.config)]), 1)
        for sig, handler in before.items():
            self.assertEqual(signal.getsignal(sig), handler)

    def test_real_command_timeout(self):
        executable = self.tool("import time\ntime.sleep(60)")
        worker = jobs.Worker([])
        started = time.monotonic()
        with mock.patch.object(jobs, "TERMINATION_GRACE_SECONDS", 0.1):
            result = worker.command([str(executable)], 0.1)
        self.assertEqual(result.status, "timed out")
        self.assertEqual(result.returncode, -signal.SIGTERM)
        self.assertLess(time.monotonic() - started, 3)

    def test_real_cli_signal_during_active_command(self):
        # Run the actual CLI with only the fixed mount path redirected to a
        # disposable fixture. The fake tool announces readiness through stdout.
        self.tool("import os, signal, sys, time\n"
                  "if '--help' in sys.argv: sys.exit(0)\n"
                  "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                  "print('READY', os.getpid(), flush=True)\n"
                  "time.sleep(60)")
        launcher = ("import sys; sys.path.insert(0, {!r}); import jobs; "
                    "jobs.FILESTORE = {!r}; jobs.TERMINATION_GRACE_SECONDS = 0.1; "
                    "sys.exit(jobs.main(sys.argv[1:]))").format(
                        str(Path(jobs.__file__).parent), str(self.directory))
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum):
                process = subprocess.Popen([sys.executable, "-u", "-c", launcher,
                                            str(self.config)], stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, text=True)
                lines = []
                ready = threading.Event()
                child_pids = []

                def reader():
                    for line in process.stdout:
                        lines.append(line)
                        if line.startswith("READY "):
                            child_pids.append(int(line.split()[1]))
                            ready.set()

                thread = threading.Thread(target=reader, daemon=True)
                thread.start()
                try:
                    self.assertTrue(ready.wait(5), "".join(lines))
                    process.send_signal(signum)
                    self.assertEqual(process.wait(timeout=5), 0)
                    thread.join(timeout=2)
                    self.assertIn("status=interrupted", "".join(lines))
                    self.assertIn("escalating to SIGKILL", "".join(lines))
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child_pids[0], 0)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                    for pid in child_pids:
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    thread.join(timeout=2)
                    process.stdout.close()


if __name__ == "__main__":
    unittest.main()
