# SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
# SPDX-License-Identifier: MIT

"""Non-destructive CLI regressions: cargo build, then Python unittest discovery.

PATH contains only fixture executables. All service/image state is simulated;
these tests do not prove Docker/Podman's actual image replacement behavior.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import fake_runtime


BINARY = Path(__file__).resolve().parents[2] / "target/debug/evectl"
SPEC_LABEL = "org.evebox.evectl.housekeeping-spec"


@unittest.skipUnless(sys.platform == "linux", "Linux CLI lifecycle")
class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file():
            raise RuntimeError("run cargo build before CLI fixture tests")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="evectl-cli-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runtime = self.root / "runtime"
        (self.runtime / "containers").mkdir(parents=True)
        (self.runtime / "image-id").write_text("image-1")
        self.instance = self.root / "instance"
        (self.instance / "data").mkdir(parents=True)
        (self.instance / "config").mkdir()
        self.data = self.instance / "data/keep"
        self.data.write_text("data must survive failed discovery")
        self.config = self.instance / "config/keep"
        self.config.write_text("configuration must survive failed discovery")
        self.env = dict(os.environ, PATH=str(self.bin),
                        EVECTL_FAKE_RUNTIME=str(self.runtime))
        self.env.pop("EVECTL_FAKE_FAIL", None)
        self.env.pop("EVECTL_FAKE_ERROR", None)
        self.write_config()

    def write_config(self, suricata=False, agent=False, server=False):
        self.instance.joinpath("evectl.toml").write_text(
            '[suricata]\nenabled = {}\neve-output = "file"\n'
            'interfaces = ["fixture0"]\nimage = "fixture:testing"\n'
            '[suricata.file-extraction]\nenabled = {}\nmax-age-days = 7\n'
            '[evebox-server]\nenabled = {}\nimage = "fixture:testing"\n'
            '[evebox-agent]\nenabled = {}\nserver = "https://fixture.invalid"\n'
            '[elasticsearch]\nenabled = false\n'.format(
                str(suricata).lower(), str(suricata).lower(),
                str(server).lower(), str(agent).lower()))

    def install_runtime(self, name="docker"):
        executable = self.bin / name
        executable.write_text("#!{}\n".format(sys.executable)
                              + Path(fake_runtime.__file__).read_text())
        executable.chmod(0o755)
        return executable

    def argv(self, *args, podman=False):
        return [str(BINARY), "--no-root", *(["--podman"] if podman else []),
                "-D", str(self.instance), *args]

    def cli(self, *args, podman=False, success=True):
        result = subprocess.run(self.argv(*args, podman=podman), env=self.env,
                                stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=15)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def commands(self):
        path = self.runtime / "commands"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def seed(self, service):
        path = self.runtime / "containers" / ("instance-evectl-" + service)
        path.write_text(json.dumps(fake_runtime.state()))
        return path

    def assert_retained(self):
        self.assertEqual(self.data.read_text(), "data must survive failed discovery")
        self.assertEqual(self.config.read_text(), "configuration must survive failed discovery")
        self.assertTrue((self.instance / "evectl.toml").is_file())

    def test_absent_executables_allow_filesystem_only_uninstall(self):
        result = self.cli("uninstall", "--config", "--yes")
        self.assertIn("filesystem-only uninstall", result.stdout + result.stderr)
        self.assertFalse(self.instance.exists())
        self.assertEqual(self.commands(), [])

    def test_confirmed_empty_runtime_allows_uninstall(self):
        self.install_runtime()
        self.cli("uninstall", "--config", "--yes")
        self.assertFalse(self.instance.exists())
        self.assertIn(["docker", "ps", "--all", "--format", "{{.Names}}"], self.commands())

    def test_discovery_failures_retain_files(self):
        for runtime in ("docker", "podman"):
            for command, error in (("--version", "broken installed runtime"),
                                   ("ps", "Cannot connect to daemon"),
                                   ("ps", "permission denied on runtime socket")):
                with self.subTest(runtime=runtime, command=command, error=error):
                    self.install_runtime(runtime)
                    self.env.update(EVECTL_FAKE_FAIL=command, EVECTL_FAKE_ERROR=error)
                    result = self.cli("uninstall", "--config", "--yes",
                                      podman=runtime == "podman", success=False)
                    self.assertIn(error, result.stdout + result.stderr)
                    self.assert_retained()
                    self.assertFalse(any(row[1] in ("stop", "rm") for row in self.commands()))

    def test_inaccessible_podman_is_not_a_missing_docker_fallback(self):
        self.install_runtime("podman")
        self.env.update(EVECTL_FAKE_FAIL="ps", EVECTL_FAKE_ERROR="Podman permission denied")
        result = self.cli("uninstall", "--config", "--yes", success=False)
        self.assertIn("Podman permission denied", result.stdout + result.stderr)
        self.assert_retained()
        self.assertIn(["podman", "ps", "--all", "--format", "{{.Names}}"], self.commands())

    def test_unexecutable_and_broken_interpreter_are_not_absence(self):
        executable = self.install_runtime()
        executable.chmod(0o644)
        self.cli("uninstall", "--config", "--yes", success=False)
        self.assert_retained()
        executable.write_text("#!/definitely-missing-evectl-test-interpreter\n")
        executable.chmod(0o755)
        self.cli("uninstall", "--config", "--yes", success=False)
        self.assert_retained()

    def test_missing_selected_podman_does_not_ignore_installed_docker(self):
        self.install_runtime()
        self.cli("uninstall", "--config", "--yes", podman=True, success=False)
        self.assert_retained()

    def test_failures_after_discovery_also_retain_files(self):
        self.install_runtime()
        service = self.seed("suricata")
        for command in ("inspect", "stop", "rm"):
            with self.subTest(command=command):
                self.env["EVECTL_FAKE_FAIL"] = command
                self.cli("uninstall", "--config", "--yes", success=False)
                self.assert_retained()
                self.assertTrue(service.exists())

    def test_uninstall_removes_worker_before_services_and_files(self):
        self.install_runtime()
        for service in ("housekeeping", "housekeeper", "suricata", "evebox-agent"):
            self.seed(service)
        self.cli("uninstall", "--config", "--yes")
        self.assertFalse(self.instance.exists())
        self.assertEqual(list((self.runtime / "containers").iterdir()), [])
        removed = [row[-1] for row in self.commands() if row[1] == "rm"]
        self.assertEqual(removed, ["instance-evectl-" + service for service in
                                  ("housekeeping", "housekeeper", "suricata", "evebox-agent")])

    def test_same_tag_new_image_id_reconciles_worker(self):
        self.install_runtime()
        self.write_config(suricata=True)
        self.seed("suricata")  # Exercise the already-running Suricata fast path.
        worker = self.runtime / "containers/instance-evectl-housekeeper"
        self.cli("start")
        first = json.loads(worker.read_text())
        self.cli("start")
        self.assertEqual(json.loads(worker.read_text())["Id"], first["Id"])
        (self.runtime / "image-id").write_text("image-2")
        offset = len(self.commands())
        self.cli("start")
        updated = json.loads(worker.read_text())
        self.assertEqual(first["Config"]["Image"], updated["Config"]["Image"])
        self.assertNotEqual(first["Id"], updated["Id"])
        self.assertEqual(updated["Image"], "image-2")
        self.assertNotEqual(first["Config"]["Labels"][SPEC_LABEL],
                            updated["Config"]["Labels"][SPEC_LABEL])
        commands = self.commands()[offset:]
        steps = [row[1] for row in commands if row[1] in ("stop", "rm", "run")]
        self.assertEqual(steps, ["stop", "rm", "run", "run"])
        self.assertTrue(any("--check" in row for row in commands))
        self.assertTrue(any("--detach" in row for row in commands))

    def test_foreground_signals_stop_and_reap_including_agent_only(self):
        self.install_runtime()
        for signum in (signal.SIGINT, signal.SIGTERM):
            for agent_only in (False, True):
                with self.subTest(signal=signum, agent_only=agent_only):
                    self.write_config(suricata=not agent_only, agent=True)
                    services = ["evebox-agent"] if agent_only else ["evebox-agent", "suricata"]
                    for service in services:
                        for suffix in ("ready", "reaped"):
                            (self.runtime / ("instance-evectl-" + service + "." + suffix)).unlink(
                                missing_ok=True)
                    offset = len(self.commands())
                    child = subprocess.Popen(
                        self.argv("start", "--debug"), env=self.env,
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, start_new_session=True)
                    try:
                        deadline = time.monotonic() + 10
                        while time.monotonic() < deadline:
                            if all((self.runtime / ("instance-evectl-" + service + ".ready")).exists()
                                   for service in services):
                                break
                            if child.poll() is not None:
                                self.fail("foreground exited early: " + repr(child.communicate()))
                            time.sleep(0.02)
                        else:
                            self.fail("foreground fake services did not start")
                        if not agent_only:
                            self.assertTrue((self.runtime / "containers/instance-evectl-housekeeper").exists())
                        child.send_signal(signum)
                        stdout, stderr = child.communicate(timeout=10)
                        self.assertEqual(child.returncode, 0, stdout + stderr)
                        self.assertIn("Received shutdown signal", stdout + stderr)
                        self.assertEqual(list((self.runtime / "containers").iterdir()), [])
                        for service in services:
                            self.assertTrue((self.runtime / ("instance-evectl-" + service + ".reaped")).exists())
                        if not agent_only:
                            stops = [row[-1] for row in self.commands()[offset:]
                                     if row[1] == "stop"]
                            # Ignore initial best-effort stops before startup.
                            shutdown = stops[stops.index("instance-evectl-housekeeper"):]
                            self.assertEqual(shutdown[0], "instance-evectl-housekeeper")
                            self.assertIn("instance-evectl-evebox-agent", shutdown)
                    finally:
                        if child.poll() is None:
                            os.killpg(child.pid, signal.SIGKILL)
                            child.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
