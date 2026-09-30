# SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
# SPDX-License-Identifier: MIT

"""Opt-in integration tests; never start Suricata capture or pull images.

From the checkout root (build target/debug/evectl first):

    PYTHONDONTWRITEBYTECODE=1 \
    EVECTL_TEST_RUNTIME=docker EVECTL_TEST_IMAGE=jasonish/suricata:latest \
        python3 -m unittest discover -s src/housekeeper -p test_runtime.py -v
    PYTHONDONTWRITEBYTECODE=1 \
    EVECTL_TEST_RUNTIME=podman EVECTL_TEST_IMAGE=docker.io/jasonish/suricata:8.0 \
        python3 -m unittest discover -s src/housekeeper -p test_runtime.py -v

Both variables are required. The image must already exist locally and contain
Python 3, suricatactl, and the suricata user. Podman is used without sudo. Each
test owns a unique tempfile instance, disposable files, and named containers.
The CLI always uses --no-root and an explicit instance directory. No systemd,
reboots, actual IDS startup, or uninstall --all are exercised.
"""

import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


RUNTIME = os.environ.get("EVECTL_TEST_RUNTIME", "")
IMAGE = os.environ.get("EVECTL_TEST_IMAGE", "")
CHECKOUT = Path(__file__).resolve().parents[2]
BINARY = CHECKOUT / "target/debug/evectl"
SPEC_LABEL = "org.evebox.evectl.housekeeping-spec"
DAY = 86400


@unittest.skipUnless(RUNTIME and IMAGE, "set EVECTL_TEST_RUNTIME and EVECTL_TEST_IMAGE")
class HousekeepingRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if RUNTIME not in ("docker", "podman"):
            raise ValueError("EVECTL_TEST_RUNTIME must be docker or podman")
        if not BINARY.is_file():
            raise RuntimeError("build target/debug/evectl before running runtime tests")
        # Inspect only: missing images are failures, never an invitation to pull.
        result = cls.command([RUNTIME, "image", "inspect", IMAGE])
        cls.image_id = json.loads(result.stdout)[0]["Id"]

    @staticmethod
    def command(argv, timeout=60, check=True, env=None):
        argv = [str(arg) for arg in argv]
        # Kill the entire CLI subprocess group on timeout, including any runtime
        # client it spawned. Container cleanup is separately registered below.
        with subprocess.Popen(
            argv, cwd=CHECKOUT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True, env=env,
        ) as child:
            try:
                stdout, stderr = child.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                stdout, stderr = child.communicate(timeout=10)
                raise AssertionError(
                    "command timed out: {}\n{}\n{}".format(
                        shlex.join(argv), stdout, stderr))
        result = subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)
        if check and result.returncode:
            raise AssertionError("command failed ({}): {}\n{}\n{}".format(
                result.returncode, shlex.join(argv), stdout, stderr))
        return result

    def runtime(self, *args, **kwargs):
        return self.command([RUNTIME, *args], **kwargs)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="evectl-hk-runtime-"))
        self.assertRegex(self.root.name, r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
        self.prefix = self.root.name + "-evectl"
        self.dummy = self.prefix + "-suricata"
        self.worker = self.prefix + "-housekeeper"
        self.legacy_worker = self.prefix + "-housekeeping"
        self.helper = self.prefix + "-fixture"
        self.logdir = self.root / "data/suricata/log"
        self.filestore = self.logdir / "filestore"
        self.suricata_enabled = True
        self.addCleanup(self.cleanup)
        self.filestore.mkdir(parents=True)
        self.write_config()
        self.create_dummy()

    def mount(self, source, destination):
        label = ":z" if Path("/sys/fs/selinux/enforce").exists() else ""
        return "{}:{}{}".format(source, destination, label)

    def create_dummy(self):
        self.runtime(
            "run", "--pull=never", "--detach", "--network=none", "--user=0",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--stop-timeout=2", "--name=" + self.dummy,
            "--entrypoint=python3", IMAGE, "-c",
            "import signal,time; "
            "signal.signal(signal.SIGTERM, lambda *_: exit(0)); time.sleep(3600)",
        )
        self.assertTrue(self.inspect(self.dummy)["State"]["Running"])

    def write_config(self, days=7, suricata=True):
        self.suricata_enabled = suricata
        # EveCtl checks EveBox's image even when disabled. Use the same
        # locally available image name for both; these tests never pull.
        self.root.joinpath("evectl.toml").write_text(
            '[suricata]\nenabled = {}\neve-output = "file"\nimage = {}\n'
            '[suricata.file-extraction]\nenabled = true\nmax-age-days = {}\n'
            '[evebox-server]\nenabled = false\nimage = {}\n'
            '[evebox-agent]\nenabled = false\n'
            '[elasticsearch]\nenabled = false\n'.format(
                str(suricata).lower(), json.dumps(IMAGE), days,
                json.dumps(IMAGE)), encoding="utf-8")

    def cli(self, *args):
        if args == ("start",) and self.suricata_enabled:
            # Refuse to reach actual IDS startup if the dummy died unexpectedly.
            state = self.inspect(self.dummy)
            self.assertTrue(state["State"]["Running"], "sleeping stand-in is not running")
            self.assertIn("time.sleep(3600)", " ".join(state["Config"]["Cmd"]))
        flags = ["--no-root"] + (["--podman"] if RUNTIME == "podman" else [])
        return self.command([BINARY, *flags, "-D", self.root, *args], timeout=90)

    def inspect(self, name):
        return json.loads(self.runtime("inspect", name).stdout)[0]

    def names(self):
        return set(self.runtime("ps", "--all", "--format", "{{.Names}}").stdout.splitlines())

    def running_worker(self):
        state = self.inspect(self.worker)
        self.assertTrue(state["State"]["Running"], state["State"])
        self.assertFalse(state["State"].get("Restarting", False), state["State"])
        return state

    def wait_for(self, predicate, description, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.25)
        logs = self.runtime("logs", "--tail=40", self.worker, check=False)
        self.fail("timed out waiting for {}\n{}\n{}".format(
            description, logs.stdout, logs.stderr))

    def fixture(self, relative, days):
        path = self.filestore / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"disposable housekeeping integration fixture\n")
        timestamp = time.time() - days * DAY
        os.utime(path, (timestamp, timestamp))
        return path

    def helper_python(self, script):
        return self.runtime(
            "run", "--pull=never", "--rm", "--network=none", "--user=0",
            "--name=" + self.helper, "--entrypoint=python3",
            "--volume=" + self.mount(self.root, "/fixture"),
            self.image_id, "-c", script,
        )

    def cleanup(self):
        # Include unnamed preflight containers left behind by a timed-out CLI,
        # but only when their bind source is strictly inside our unique root.
        errors = []
        try:
            containers = self.runtime("ps", "--all", "--format", "{{.ID}}").stdout.split()
            owned = {self.dummy, self.worker, self.legacy_worker, self.helper}
            for container in containers:
                state = self.inspect(container)
                if any(
                    mount.get("Source") == str(self.root)
                    or mount.get("Source", "").startswith(str(self.root) + "/")
                    for mount in state.get("Mounts", [])
                ):
                    owned.add(container)
            existing = self.names()
            for name in owned:
                if name in existing or name in containers:
                    result = self.runtime("rm", "--force", name, check=False)
                    if result.returncode and name in self.names():
                        errors.append(result.stderr)
        except Exception as error:
            errors.append(str(error))
        try:
            if self.root.exists():
                try:
                    shutil.rmtree(self.root)
                except PermissionError:
                    # Rootless Podman maps Suricata ownership to a subordinate
                    # host UID. Delete only fixture contents in that namespace.
                    self.helper_python(
                        "import pathlib,shutil; p=pathlib.Path('/fixture'); "
                        "[(shutil.rmtree(x) if x.is_dir() and not x.is_symlink() "
                        "else x.unlink()) for x in p.iterdir()]")
                    shutil.rmtree(self.root)
            self.assertFalse(self.root.exists())
            self.assertFalse({self.dummy, self.worker, self.legacy_worker, self.helper} & self.names())
        except Exception as error:
            errors.append(str(error))
        if errors:
            self.fail("cleanup failed for {}: {}".format(self.root, "; ".join(errors)))

    def test_pruning_and_reconciliation(self):
        old = self.fixture("aa/" + "a" * 64, 14)
        old_tmp = self.fixture("tmp/file.aged", 14)
        fresh = self.fixture("bb/" + "b" * 64, 0)
        fresh_tmp = self.fixture("tmp/file.fresh", 0)
        middle = self.fixture("cc/" + "c" * 64, 3)
        self.cli("start")
        first = self.running_worker()
        self.assertEqual(first["Config"]["Image"], IMAGE)
        self.assertEqual(first["Config"]["Entrypoint"], ["evectl-housekeeper"])
        self.assertEqual(first["Config"]["Cmd"], ["/housekeeping/config.json"])
        self.assertIn("PYTHONUNBUFFERED=1", first["Config"]["Env"])
        self.assertEqual(first["Config"]["Image"], self.inspect(self.dummy)["Config"]["Image"])
        self.assertEqual(first["Image"], self.inspect(self.dummy)["Image"])
        self.wait_for(lambda: not old.exists() and not old_tmp.exists(), "first prune")
        for path in (fresh, fresh_tmp, middle):
            self.assertTrue(path.is_file(), path)
        assets = self.root / "config/housekeeping"
        self.assertEqual(assets.joinpath("jobs.py").stat().st_mode & 0o777, 0o755)
        self.assertEqual(assets.joinpath("jobs.py").read_bytes(),
                         Path(__file__).with_name("jobs.py").read_bytes())
        config = json.loads(assets.joinpath("config.json").read_text())
        self.assertEqual(config["file_extraction"], {
            "retention_days": 7, "interval_seconds": 300, "timeout_seconds": 240})
        self.assertRegex(first["Config"]["Labels"][SPEC_LABEL], r"^[0-9a-f]{64}$")
        self.assertEqual(first["HostConfig"]["RestartPolicy"]["Name"], "unless-stopped")
        self.assertEqual(first["HostConfig"]["NetworkMode"], "none")

        self.cli("start")
        self.assertEqual(self.running_worker()["Id"], first["Id"])
        self.runtime("stop", "--time=10", self.worker)
        self.runtime("rm", self.worker)
        self.cli("start")
        recreated = self.running_worker()
        self.assertNotEqual(recreated["Id"], first["Id"])

        self.runtime("stop", "--time=10", self.worker)
        self.assertFalse(self.inspect(self.worker)["State"]["Running"])
        self.cli("start")
        resumed = self.running_worker()
        self.assertNotEqual(resumed["Id"], recreated["Id"])

        self.write_config(days=1)
        self.cli("start")
        changed = self.running_worker()
        self.assertNotEqual(changed["Id"], resumed["Id"])
        self.assertNotEqual(changed["Config"]["Labels"][SPEC_LABEL],
                            resumed["Config"]["Labels"][SPEC_LABEL])
        self.assertEqual(json.loads(assets.joinpath("config.json").read_text())
                         ["file_extraction"]["retention_days"], 1)
        self.wait_for(lambda: not middle.exists(), "changed retention prune")
        self.assertTrue(fresh.is_file())
        self.assertTrue(fresh_tmp.is_file())

    def logdir_metadata(self):
        result = self.helper_python(
            "import json,os; s=os.stat('/fixture/data/suricata/log'); "
            "print(json.dumps([s.st_uid,s.st_gid,s.st_mode & 0o777]))")
        return json.loads(result.stdout)

    def assert_missing_filestore_start(self):
        metadata = self.logdir_metadata()
        self.assertFalse(self.filestore.exists())
        self.cli("start")
        first = self.running_worker()

        def missing_pass_logged():
            logs = self.runtime("logs", "--tail=40", self.worker)
            return "status=failed: filestore directory is missing:" in (
                logs.stdout + logs.stderr)

        # Wait for an actual pass, not merely a briefly running container.
        # The normal worker must report the missing directory and keep running.
        self.wait_for(missing_pass_logged, "missing filestore retry scheduled")
        self.assertFalse(self.filestore.exists())
        self.assertEqual(self.logdir_metadata(), metadata)
        self.cli("start")
        second = self.running_worker()
        self.assertEqual(second["Id"], first["Id"])
        self.assertEqual(second["State"]["StartedAt"], first["State"]["StartedAt"])
        self.assertFalse(self.filestore.exists())
        self.assertEqual(self.logdir_metadata(), metadata)
        self.assertTrue(self.inspect(self.dummy)["State"]["Running"])
        return first

    def test_missing_filestore_with_writable_parent(self):
        self.filestore.rmdir()
        self.assertTrue(os.access(self.logdir, os.W_OK))
        self.assert_missing_filestore_start()

    @unittest.skipIf(os.geteuid() == 0,
                     "host root bypasses the logdir's ordinary-user permissions")
    def test_missing_filestore_with_suricata_owned_parent(self):
        # Remove the empty host fixture before Suricata takes ownership. The
        # host CLI cannot mkdir inside this 0755 directory afterwards, including
        # with rootless Podman's subordinate-UID mapping.
        self.filestore.rmdir()
        result = self.helper_python(
            "import json,os,pwd; u=pwd.getpwnam('suricata'); "
            "p='/fixture/data/suricata/log'; "
            "os.chown(p,u.pw_uid,u.pw_gid); os.chmod(p,0o755); "
            "print(json.dumps([u.pw_uid,u.pw_gid]))")
        uid, gid = json.loads(result.stdout)
        self.assertNotEqual(uid, 0)
        if self.logdir.stat().st_uid == os.geteuid():
            self.skipTest("image Suricata UID maps to the invoking host user")
        self.assertFalse(os.access(self.logdir, os.W_OK))
        self.assertEqual(self.logdir_metadata(), [uid, gid, 0o755])
        first = self.assert_missing_filestore_start()

        # Simulate late creation by Suricata without starting any IDS process.
        # Enter the mount first because the tempfile instance ancestor is 0700,
        # then drop to the image's Suricata user before creating any files.
        self.helper_python(
            "import os,pathlib,pwd,time; u=pwd.getpwnam('suricata'); "
            "os.chdir('/fixture/data/suricata/log'); "
            "os.setgroups([]); os.setgid(u.pw_gid); os.setuid(u.pw_uid); "
            "root=pathlib.Path('filestore'); "
            "dirs=[root,root/'aa',root/'tmp']; "
            "[p.mkdir(mode=0o755) for p in dirs]; "
            "files=[root/'aa'/('a'*64),root/'tmp'/'aged',root/'tmp'/'fresh']; "
            "[p.write_bytes(b'disposable late fixture') for p in files]; "
            "[os.utime(p,(time.time()-14*86400,)*2) for p in files[:2]]")
        old = self.filestore / "aa" / ("a" * 64)
        old_tmp = self.filestore / "tmp/aged"
        fresh = self.filestore / "tmp/fresh"
        for path in (old, old_tmp, fresh):
            self.assertTrue(path.is_file(), path)
        # Restart only this disposable worker to get an immediate next pass
        # instead of waiting the production 300-second interval.
        self.runtime("restart", "--time=10", self.worker)
        self.assertEqual(self.running_worker()["Id"], first["Id"])
        self.wait_for(lambda: not old.exists() and not old_tmp.exists(),
                      "prune of late Suricata-created filestore")
        self.assertTrue(fresh.is_file())
        self.assertEqual(self.logdir_metadata(), [uid, gid, 0o755])
        self.running_worker()
        self.assertTrue(self.inspect(self.dummy)["State"]["Running"])

    def test_legacy_name_is_retired(self):
        self.cli("start")
        original = self.running_worker()["Id"]
        self.runtime("rename", self.worker, self.legacy_worker)
        self.cli("start")
        self.assertNotIn(self.legacy_worker, self.names())
        self.assertNotEqual(self.running_worker()["Id"], original)

        self.runtime("rename", self.worker, self.legacy_worker)
        self.write_config(days=0)
        self.cli("start")
        self.assertNotIn(self.legacy_worker, self.names())
        self.assertNotIn(self.worker, self.names())

        self.write_config()
        self.cli("start")
        self.runtime("rename", self.worker, self.legacy_worker)
        self.cli("stop")
        self.assertNotIn(self.legacy_worker, self.names())
        self.assertNotIn(self.worker, self.names())

        self.create_dummy()
        self.cli("start")
        self.runtime("rename", self.worker, self.legacy_worker)
        self.runtime("rm", "--force", self.dummy)
        # The legacy worker alone must still be found by uninstall.
        self.cli("uninstall", "--yes")
        self.assertNotIn(self.legacy_worker, self.names())
        self.assertFalse(self.root.joinpath("data").exists())

    def test_disabling_removes_stale_worker(self):
        for settings in ({"days": 0}, {"suricata": False}):
            with self.subTest(settings=settings):
                self.write_config()
                self.cli("start")
                self.running_worker()
                self.write_config(**settings)
                self.cli("start")
                self.assertNotIn(self.worker, self.names())
                self.assertTrue(self.inspect(self.dummy)["State"]["Running"])

    def test_dummy_restart_does_not_restart_worker(self):
        self.cli("start")
        before = self.running_worker()
        self.runtime("restart", "--time=2", self.dummy)
        self.assertTrue(self.inspect(self.dummy)["State"]["Running"])
        self.cli("start")
        after = self.running_worker()
        self.assertEqual(after["Id"], before["Id"])
        self.assertEqual(after["State"]["StartedAt"], before["State"]["StartedAt"])

    def test_worker_process_exit_recovers(self):
        self.cli("start")
        before = self.running_worker()
        # Docker requires an initial successful run of at least ten seconds
        # before its restart policy takes effect. Do not use runtime kill/stop:
        # those mark an intentional stop and suppress policy-driven recovery.
        # PID namespace init ignores unhandled signals sent from its own
        # namespace. SIGTERM is handled by the worker, so it exits normally;
        # unless-stopped must recover even this clean process exit.
        time.sleep(11)
        old = self.fixture("dd/" + "d" * 64, 14)
        result = self.runtime("exec", "--user=0", self.worker, "python3", "-c",
                              "import os,signal; os.kill(1, signal.SIGTERM)", check=False)
        self.assertIn(result.returncode, (0, 137, 143), result.stderr)
        self.wait_for(
            lambda: self.inspect(self.worker)["State"]["StartedAt"]
            != before["State"]["StartedAt"], "automatic worker restart", timeout=45)
        after = self.running_worker()
        self.assertEqual(after["Id"], before["Id"])
        self.wait_for(lambda: not old.exists(), "prune after automatic restart")

    def test_restrictive_suricata_ownership_and_uninstall(self):
        result = self.helper_python(
            "import os,pathlib,pwd,time,json; "
            "u=pwd.getpwnam('suricata'); "
            "root=pathlib.Path('/fixture/data/suricata/log/filestore'); "
            "dirs=[root,root/'ee',root/'tmp']; "
            "[p.mkdir(exist_ok=True) for p in dirs]; "
            "files=[root/'ee'/('e'*64),root/'tmp'/'aged',root/'tmp'/'fresh']; "
            "[p.write_bytes(b'disposable fixture') for p in files]; "
            "[os.utime(p,(time.time()-14*86400,)*2) for p in files[:2]]; "
            "[os.chown(p,u.pw_uid,u.pw_gid) for p in dirs+files]; "
            "[os.chmod(p,0o700) for p in dirs]; "
            "[os.chmod(p,0o600) for p in files]; "
            "print(json.dumps([u.pw_uid,u.pw_gid]))")
        uid, gid = json.loads(result.stdout)
        self.assertNotEqual(uid, 0)
        self.cli("start")
        self.running_worker()
        snapshot_script = (
            "import pathlib,json; root=pathlib.Path('/fixture/data/suricata/log/filestore'); "
            "print(json.dumps({str(p.relative_to(root)): "
            "[p.stat().st_uid,p.stat().st_gid,p.stat().st_mode & 0o777] "
            "for p in [root,*root.rglob('*')]}))")
        snapshot = json.loads(self.helper_python(snapshot_script).stdout)
        self.assertNotIn("ee/" + "e" * 64, snapshot)
        self.assertNotIn("tmp/aged", snapshot)
        self.assertEqual(snapshot["tmp/fresh"], [uid, gid, 0o600])
        for directory in (".", "ee", "tmp"):
            self.assertEqual(snapshot[directory], [uid, gid, 0o700])
        self.cli("uninstall", "--config", "--yes")
        self.assertFalse(self.root.exists())
        self.assertNotIn(self.worker, self.names())
        self.assertNotIn(self.dummy, self.names())

    def test_foreground_startup_failure_removes_worker(self):
        # No capture interfaces are configured. Foreground startup may query
        # version and dump config, but must fail before creating an IDS process.
        self.runtime("stop", "--time=2", self.dummy)
        self.runtime("rm", self.dummy)
        flags = ["--no-root"] + (["--podman"] if RUNTIME == "podman" else [])
        result = self.command(
            [BINARY, *flags, "-D", self.root, "start", "--debug"],
            timeout=90, check=False)
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("Starting housekeeper", output)
        self.assertIn("no network interface set", output)
        self.assertTrue(self.root.joinpath("config/housekeeping/jobs.py").is_file())
        self.assertNotIn(self.worker, self.names())
        self.assertNotIn(self.dummy, self.names())

    def test_stop_and_uninstall_lifecycle(self):
        self.fixture("ff/" + "f" * 64, 0)
        self.cli("start")
        self.running_worker()
        self.cli("stop")
        self.assertNotIn(self.worker, self.names())
        self.assertNotIn(self.dummy, self.names())
        self.assertTrue(self.filestore.is_dir())
        self.create_dummy()
        self.cli("start")
        self.running_worker()
        self.cli("uninstall", "--yes")
        self.assertFalse(self.root.joinpath("data").exists())
        self.assertTrue(self.root.joinpath("evectl.toml").is_file())
        self.assertTrue(self.root.joinpath("config/housekeeping/jobs.py").is_file())
        self.assertNotIn(self.worker, self.names())
        self.assertNotIn(self.dummy, self.names())


@unittest.skipUnless(RUNTIME and IMAGE, "set EVECTL_TEST_RUNTIME and EVECTL_TEST_IMAGE")
class UninstallWithoutRuntimeTests(unittest.TestCase):
    def test_uninstall_without_runtime_removes_filesystem(self):
        with tempfile.TemporaryDirectory(prefix="evectl-hk-no-runtime-") as directory:
            root = Path(directory)
            empty_path = root / "empty-path"
            empty_path.mkdir()
            instance = root / "instance"
            (instance / "config/housekeeping").mkdir(parents=True)
            (instance / "data/suricata/log/filestore").mkdir(parents=True)
            (instance / "evectl.toml").write_text("[suricata]\nenabled = false\n")
            (instance / "config/housekeeping/jobs.py").write_text("# disposable\n")
            (instance / "data/suricata/log/filestore/fixture").write_text("disposable\n")
            env = dict(os.environ, PATH=str(empty_path))
            result = HousekeepingRuntimeTests.command(
                [BINARY, "--no-root", "-D", instance,
                 "uninstall", "--config", "--yes"], env=env)
            self.assertIn("Uninstall complete", result.stdout + result.stderr)
            self.assertFalse(instance.exists())
            self.assertEqual(list(empty_path.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
