// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Native background launches without a console or a pipe-draining launcher.

use std::fs::OpenOptions;
use std::io;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// Refresh a stopped worker from a real copy, never a hard link to the launcher.
/// Stage the copy so a failed refresh leaves the previous executable intact.
/// Callers must not refresh an executable while its worker is running.
pub(super) fn copy_worker_executable(source: &Path, destination: &Path) -> io::Result<()> {
    let parent = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Worker executable has no parent",
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let staged = tempfile::NamedTempFile::new_in(parent)?;
    std::fs::copy(source, staged.path())?;
    staged.as_file().sync_all()?;
    staged.persist(destination).map_err(|err| err.error)?;
    Ok(())
}

fn output(path: Option<&Path>) -> io::Result<Stdio> {
    match path {
        Some(path) => OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map(Stdio::from),
        None => Ok(Stdio::null()),
    }
}

/// Spawn directly and return without waiting for the service to exit or close pipes.
/// Windows receives Command's arguments, working directory and environment directly,
/// keeping credentials out of argv and avoiding PowerShell's extra quoting layer.
pub(super) fn spawn_detached(
    command: &mut Command,
    stdout: Option<&Path>,
    stderr: Option<&Path>,
) -> io::Result<Child> {
    // CREATE_NO_WINDOW also supports runtimes that exit early with DETACHED_PROCESS.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    command
        .creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
        .stdin(Stdio::null())
        .stdout(output(stdout)?)
        .stderr(output(stderr)?)
        .spawn()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    // Only stop the child created by the test, including on assertion failure.
    struct TestChild(Child);

    impl Drop for TestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn powershell() -> Command {
        let system_root = std::env::var_os("SystemRoot").unwrap();
        let mut command = Command::new(
            Path::new(&system_root).join("System32/WindowsPowerShell/v1.0/powershell.exe"),
        );
        command.args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
        ]);
        command
    }

    #[test]
    fn detached_launch_returns_while_long_lived_child_is_running() {
        let mut command = powershell();
        command.args(["-Command", "Start-Sleep -Seconds 30"]);
        let started = Instant::now();
        let mut child = TestChild(spawn_detached(&mut command, None, None).unwrap());
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(child.0.try_wait().unwrap().is_none());
    }

    #[test]
    fn detached_logs_return_without_waiting_and_preserve_args_environment_and_directory() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("Test User's working directory");
        std::fs::create_dir(&directory).unwrap();
        let script = directory.join("child script.ps1");
        std::fs::write(
            &script,
            "param([string]$Value)\n\
             [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n\
             Write-Output $Value\n\
             Write-Output $env:EVEBOX_SERVER_KEY\n\
             Write-Output (Get-Location).Path\n\
             [Console]::Error.WriteLine('child-stderr')\n\
             Start-Sleep -Seconds 30\n",
        )
        .unwrap();
        let stdout = directory.join("child stdout.log");
        let stderr = directory.join("child stderr.log");
        let argument = r#"spaces, 'apostrophes', "quotes", and trailing slash\"#;
        let mut command = powershell();
        command.arg("-File").arg(&script).arg(argument);
        command.current_dir(&directory);
        command.env("EVEBOX_SERVER_KEY", "test-agent-key");
        command.env_remove("EVECTL_TEST_UNUSED_VARIABLE");
        let started = Instant::now();
        let mut child =
            TestChild(spawn_detached(&mut command, Some(&stdout), Some(&stderr)).unwrap());
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(!command.get_args().any(|arg| arg == "test-agent-key"));

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let out = std::fs::read_to_string(&stdout).unwrap_or_default();
            let err = std::fs::read_to_string(&stderr).unwrap_or_default();
            if err.contains("child-stderr") {
                let lines: Vec<_> = out.lines().collect();
                assert_eq!(
                    lines,
                    [argument, "test-agent-key", directory.to_str().unwrap()]
                );
                assert!(child.0.try_wait().unwrap().is_none());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Child did not write its logs: {out}\n{err}"
            );
            if let Some(status) = child.0.try_wait().unwrap() {
                panic!(
                    "Child exited with {status}: stdout {:?}, stderr {:?}",
                    std::fs::read(&stdout).unwrap(),
                    std::fs::read(&stderr).unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // The copied test executable supplies a long-lived worker without touching
    // the installed stack. Only the parent test sets this environment variable.
    #[test]
    #[ignore = "Child process fixture for worker_copy_does_not_lock_launcher"]
    fn worker_copy_fixture() {
        let Some(ready) = std::env::var_os("EVECTL_TEST_WORKER_READY") else {
            return;
        };
        std::fs::write(ready, b"ready").unwrap();
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn worker_copy_does_not_lock_launcher() {
        let root = tempfile::tempdir().unwrap();
        let launcher = root.path().join("evectl.exe");
        let worker = root.path().join("run/housekeeper.exe");
        let ready = root.path().join("ready");
        std::fs::copy(std::env::current_exe().unwrap(), &launcher).unwrap();
        copy_worker_executable(&launcher, &worker).unwrap();
        let mut command = Command::new(&worker);
        command.args([
            "--ignored",
            "--exact",
            "windows::process::tests::worker_copy_fixture",
        ]);
        command.env("EVECTL_TEST_WORKER_READY", &ready);
        let mut child = TestChild(spawn_detached(&mut command, None, None).unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(child.0.try_wait().unwrap().is_none(), "Worker exited early");
            assert!(Instant::now() < deadline, "Worker did not become ready");
            std::thread::sleep(Duration::from_millis(50));
        }

        // The main binary remains replaceable while housekeeping is alive.
        std::fs::write(&launcher, b"updated launcher").unwrap();
        assert!(child.0.try_wait().unwrap().is_none());
        drop(child);

        // A later worker launch refreshes its copy from the updated launcher.
        copy_worker_executable(&launcher, &worker).unwrap();
        assert_eq!(std::fs::read(&worker).unwrap(), b"updated launcher");
        assert!(copy_worker_executable(&root.path().join("missing.exe"), &worker).is_err());
        assert_eq!(std::fs::read(&worker).unwrap(), b"updated launcher");
    }

    #[test]
    fn detached_launch_reports_missing_executables_and_invalid_log_paths() {
        let root = tempfile::tempdir().unwrap();
        let mut command = Command::new(root.path().join("missing.exe"));
        assert_eq!(
            spawn_detached(&mut command, None, None).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let mut command = powershell();
        let missing = root.path().join("missing directory/stdout.log");
        assert!(spawn_detached(&mut command, Some(&missing), None).is_err());
    }
}
