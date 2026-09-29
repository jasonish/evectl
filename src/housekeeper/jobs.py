#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
# SPDX-License-Identifier: MIT

"""Sequential housekeeping jobs; missed intervals are skipped, never overlapped.

Run with ./jobs.py [--check] config.json. The generated configuration
sets a 240-second pruning timeout by default. Termination gets five seconds
before SIGKILL. A successful command does not guarantee every file was deleted.
Only the Python standard library is required.
"""

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time


FILESTORE = "/var/log/suricata/filestore"
TERMINATION_GRACE_SECONDS = 5
POLL_SECONDS = 0.1


def log(message):
    timestamp = datetime.now(timezone.utc).isoformat()
    print("{} {}".format(timestamp, message), flush=True)


@dataclass
class Job:
    name: str
    argv: list
    interval_seconds: int
    timeout_seconds: int
    directory: str
    next_run: float = 0
    last_successful_completion: str = "never"


def load_jobs(path):
    with open(path, encoding="utf-8") as config_file:
        config = json.load(config_file)
    if not isinstance(config, dict) or set(config) != {"file_extraction"}:
        raise ValueError("configuration must contain only file_extraction")
    settings = config["file_extraction"]
    keys = {"retention_days", "interval_seconds", "timeout_seconds"}
    if not isinstance(settings, dict) or set(settings) != keys:
        raise ValueError("file_extraction requires exactly: " + ", ".join(sorted(keys)))
    for key in sorted(keys):
        value = settings[key]
        if type(value) is not int or value <= 0:
            raise ValueError("file_extraction.{} must be a positive integer".format(key))
    return [Job(
        name="file_extraction",
        argv=["suricatactl", "filestore", "prune", "--directory", FILESTORE,
              "--age", "{}d".format(settings["retention_days"])],
        interval_seconds=settings["interval_seconds"],
        timeout_seconds=settings["timeout_seconds"],
        directory=FILESTORE,
    )]


def check_directory(directory):
    if not os.path.isdir(directory):
        raise OSError("filestore directory is missing: " + directory)
    if not os.access(directory, os.R_OK | os.W_OK | os.X_OK):
        raise PermissionError("filestore is not accessible/writable: " + directory)
    # Exercise mount permissions, including read-only filesystems, as the actual
    # container user. No capture files are read, modified or removed.
    with os.scandir(directory):
        pass
    with tempfile.TemporaryFile(dir=directory) as probe:
        probe.write(b"housekeeping permission check\n")
        probe.flush()


def check_filestore_mount(directory):
    # On first start Suricata may not have created filestore yet. Validate the
    # mounted log directory in that case, without creating a root-owned
    # filestore that Suricata might not be able to write into. The worker will
    # retry missing filestore directories on its normal schedule.
    try:
        os.stat(directory)
    except FileNotFoundError:
        check_directory(os.path.dirname(directory))
    else:
        check_directory(directory)


@dataclass
class Completion:
    status: str
    returncode: object = None


class Worker:
    def __init__(self, jobs, stop=None, clock=time.monotonic):
        self.jobs = jobs
        self.stop = stop if stop is not None else threading.Event()
        self.clock = clock
        self.stop_requested = False

    def request_stop(self, signum, frame):
        # A flag assignment cannot deadlock by re-entering Event's lock if a
        # signal arrives inside Event.wait(). Normal code handles child reaping.
        self.stop_requested = True

    def is_stopping(self):
        return self.stop_requested or self.stop.is_set()

    @staticmethod
    def signal_child(child, signum):
        try:
            # Signal the child's separate process group, including helpers.
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass

    def terminate_child(self, child):
        try:
            self.signal_child(child, signal.SIGTERM)
            # Do not poll/wait (reap) the leader yet: its unreaped PID pins the
            # process-group ID against reuse on Linux, even if it exits before
            # a helper. Give the whole group a bounded grace period, then kill
            # it regardless of the leader's exit. killpg(..., 0) is not useful
            # here: zombies keep a group "alive" but cannot respond to signals.
            time.sleep(TERMINATION_GRACE_SECONDS)
            log("process-group grace period of {}s ended; escalating to SIGKILL".format(
                TERMINATION_GRACE_SECONDS))
            self.signal_child(child, signal.SIGKILL)
        finally:
            # Reap the direct child, never wait indefinitely for orphan zombies
            # owned by PID 1. A reaping failure is a fatal worker error.
            child.wait(timeout=TERMINATION_GRACE_SECONDS)

    def command(self, argv, timeout_seconds):
        if self.is_stopping():
            return Completion("interrupted")
        try:
            child = subprocess.Popen(argv, start_new_session=True)
        except OSError as error:
            return Completion("failed: {}".format(error))
        try:
            deadline = self.clock() + timeout_seconds
            while True:
                if self.is_stopping():
                    self.terminate_child(child)
                    return Completion("interrupted", child.returncode)
                returncode = child.poll()
                if returncode is not None:
                    return Completion("completed", returncode)
                remaining = deadline - self.clock()
                if remaining <= 0:
                    self.terminate_child(child)
                    return Completion("timed out", child.returncode)
                self.stop.wait(min(POLL_SECONDS, remaining))
        finally:
            # Also reap on unexpected Python errors before failing the worker.
            if child.poll() is None:
                self.terminate_child(child)

    def check_tool(self):
        if shutil.which("suricatactl") is None:
            raise RuntimeError("required executable suricatactl was not found in PATH")
        result = self.command(["suricatactl", "filestore", "prune", "--help"], 30)
        if result.status == "interrupted":
            return False
        if result.status != "completed" or result.returncode != 0:
            raise RuntimeError(
                "incompatible suricatactl: filestore prune --help {} (exit {})".format(
                    result.status, result.returncode))
        return True

    def run_job(self, job):
        started = self.clock()
        log("{} start argv={!r}".format(job.name, job.argv))
        try:
            check_directory(job.directory)
        except OSError as error:
            # Mount failures can be transient after startup. Try again later.
            result = Completion("failed: {}".format(error))
        else:
            # Spawn errors are ordinary failures, but termination/reaping and
            # other worker errors must propagate rather than silently retry.
            result = self.command(job.argv, job.timeout_seconds)
        if result.status == "completed" and result.returncode == 0:
            job.last_successful_completion = datetime.now(timezone.utc).isoformat()
        log("{} status={} exit={} elapsed={:.3f}s "
            "last_successful_command_completion={} "
            "(command success does not guarantee all deletions)".format(
                job.name, result.status, result.returncode,
                self.clock() - started, job.last_successful_completion))

    def run(self):
        while not self.is_stopping():
            for job in self.jobs:
                if self.is_stopping():
                    break
                if self.clock() >= job.next_run:
                    started = self.clock()
                    self.run_job(job)
                    # Schedule from the start of the pass, skipping any slots
                    # missed during a slow command rather than catching up.
                    periods = int((self.clock() - started) // job.interval_seconds) + 1
                    job.next_run = started + periods * job.interval_seconds
            if not self.is_stopping():
                delay = max(0, min(job.next_run for job in self.jobs) - self.clock())
                self.stop.wait(min(POLL_SECONDS, delay))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="validate config, tool compatibility and mount without pruning")
    parser.add_argument("config", help="path to generated JSON configuration")
    args = parser.parse_args(argv)
    previous_handlers = {}
    try:
        worker = Worker(load_jobs(args.config))
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[signum] = signal.signal(signum, worker.request_stop)
        if not worker.check_tool():
            # A cancelled preflight must not be reported as a successful check.
            return 1 if args.check else 0
        if args.check:
            for job in worker.jobs:
                check_filestore_mount(job.directory)
            log("housekeeping check successful (no pruning performed)")
        else:
            worker.run()
            log("housekeeping stopped")
        return 0
    except Exception as error:
        log("fatal housekeeping error: {}: {}".format(type(error).__name__, error))
        return 1
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    sys.exit(main())
