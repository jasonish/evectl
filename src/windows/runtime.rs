// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Managed background processes: PID and runtime metadata files,
//! process queries, and detached launches.

use super::paths::Paths;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const EVEBOX_STARTUP_GRACE_PERIOD: Duration = Duration::from_millis(750);
const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// A managed background process. The serialized names are stored in
/// the runtime metadata files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Role {
    #[serde(rename = "suricata")]
    Suricata,
    #[serde(rename = "evebox")]
    EveBoxServer,
    #[serde(rename = "evebox-agent")]
    EveBoxAgent,
    #[serde(rename = "housekeeper")]
    Housekeeper,
}

impl Role {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Role::Suricata => "suricata",
            Role::EveBoxServer => "evebox",
            Role::EveBoxAgent => "evebox-agent",
            Role::Housekeeper => "housekeeper",
        }
    }

    /// Directory holding the PID and runtime metadata files.
    fn run_dir(self, paths: &Paths) -> PathBuf {
        match self {
            Role::Suricata | Role::Housekeeper => paths.suricata_run_dir(),
            Role::EveBoxServer => paths.evebox_dir(),
            Role::EveBoxAgent => paths.evebox_agent_dir(),
        }
    }

    pub(super) fn pid_path(self, paths: &Paths) -> PathBuf {
        self.run_dir(paths).join(format!("{}.pid", self.as_str()))
    }

    pub(super) fn runtime_path(self, paths: &Paths) -> PathBuf {
        self.run_dir(paths)
            .join(format!("{}.runtime.json", self.as_str()))
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(super) struct RuntimeMetadata {
    pub(super) pid: u32,
    pub(super) role: Role,
    pub(super) exe_path: String,
    pub(super) argv: Vec<String>,
    started_at: u64,
    stdout_path: Option<String>,
    stderr_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NamedProcessInfo {
    #[serde(rename = "Id")]
    id: u32,
    #[serde(rename = "ProcessName")]
    process_name: Option<String>,
    #[serde(rename = "Path")]
    path: Option<String>,
}

pub(super) fn write_pid(path: &Path, pid: u32) -> Result<()> {
    std::fs::write(path, format!("{pid}\n"))
        .context(format!("Failed to write PID file {}", path.display()))
}

fn read_pid(path: &Path) -> Result<Option<u32>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(path)
        .context(format!("Failed to read PID file {}", path.display()))?;
    let pid = raw
        .trim()
        .parse::<u32>()
        .context(format!("Failed to parse PID file {}", path.display()))?;
    Ok(Some(pid))
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path).context(format!("Failed to remove file {}", path.display()))?;
    }
    Ok(())
}

pub(super) fn write_runtime_metadata(path: &Path, metadata: &RuntimeMetadata) -> Result<()> {
    let contents = serde_json::to_string_pretty(metadata)?;
    std::fs::write(path, contents).context(format!(
        "Failed to write runtime metadata {}",
        path.display()
    ))
}

fn read_runtime_metadata(path: &Path) -> Result<Option<RuntimeMetadata>> {
    if !path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(path).context(format!(
        "Failed to read runtime metadata {}",
        path.display()
    ))?;
    let metadata = serde_json::from_str(&contents).context(format!(
        "Failed to parse runtime metadata {}",
        path.display()
    ))?;
    Ok(Some(metadata))
}

fn normalize_path_for_compare(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

pub(super) fn command_argv(command: &Command) -> Vec<String> {
    let mut argv = vec![command.get_program().to_string_lossy().to_string()];
    argv.extend(
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string()),
    );
    argv
}

pub(super) fn build_runtime_metadata(
    role: Role,
    command: &Command,
    pid: u32,
    stdout_path: Option<&Path>,
    stderr_path: Option<&Path>,
) -> Result<RuntimeMetadata> {
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before UNIX_EPOCH")?
        .as_secs();

    Ok(RuntimeMetadata {
        pid,
        role,
        exe_path: command.get_program().to_string_lossy().to_string(),
        argv: command_argv(command),
        started_at,
        stdout_path: stdout_path.map(|path| path.to_string_lossy().to_string()),
        stderr_path: stderr_path.map(|path| path.to_string_lossy().to_string()),
    })
}

pub(super) fn spawn_detached(command: &mut Command) -> Result<u32> {
    spawn_detached_with_logs(command, None, None)
}

pub(super) fn spawn_detached_with_logs(
    command: &mut Command,
    stdout: Option<&Path>,
    stderr: Option<&Path>,
) -> Result<u32> {
    // Dropping Child closes our process handle; it doesn't stop the detached service.
    super::process::spawn_detached(command, stdout, stderr)
        .map(|child| child.id())
        .with_context(|| {
            format!(
                "Failed to spawn detached process {}",
                command.get_program().to_string_lossy()
            )
        })
}

pub(super) fn count_named_processes(process_name: &str) -> Result<usize> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$p = @(Get-Process -Name '{}' -ErrorAction SilentlyContinue); Write-Output $p.Count",
                process_name.replace('\'', "''")
            ),
        ])
        .output()
        .context("Failed to query process list")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to query process list: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .trim()
        .parse::<usize>()
        .context("Failed to parse process count")
}

fn list_named_processes(process_name: &str) -> Result<Vec<NamedProcessInfo>> {
    let script = format!(
        "$procs = @(Get-Process -Name '{}' -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path); ConvertTo-Json -InputObject @($procs) -Compress",
        process_name.replace('\'', "''")
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .context("Failed to query process details")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to query process details: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    if stdout.is_empty() {
        return Ok(vec![]);
    }

    serde_json::from_str(stdout).context("Failed to parse process details")
}

pub(super) fn is_pid_running(pid: u32) -> bool {
    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$p = Get-Process -Id {} -ErrorAction SilentlyContinue; if ($null -ne $p) {{ exit 0 }} else {{ exit 1 }}",
                pid
            ),
        ])
        .status()
        .is_ok_and(|status| status.success())
}

fn get_process_exe_path(pid: u32) -> Result<Option<PathBuf>> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$p = Get-Process -Id {} -ErrorAction SilentlyContinue; if ($null -ne $p -and $p.Path) {{ Write-Output $p.Path }}",
                pid
            ),
        ])
        .output()
        .context("Failed to inspect process executable path")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Failed to inspect process executable path: {}",
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let path = stdout.trim();
    if path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PathBuf::from(path)))
    }
}

pub(super) fn process_matches_exe(pid: u32, exe_path: &Path) -> Result<bool> {
    let running_path = match get_process_exe_path(pid)? {
        Some(path) => path,
        None => return Ok(false),
    };

    Ok(normalize_path_for_compare(&running_path) == normalize_path_for_compare(exe_path))
}

fn path_is_same_or_descendant(path: &Path, dir: &Path) -> bool {
    let path = normalize_path_for_compare(path);
    let dir = normalize_path_for_compare(dir);

    if path == dir {
        return true;
    }

    let mut prefix = dir;
    if !prefix.ends_with('\\') {
        prefix.push('\\');
    }

    path.starts_with(&prefix)
}

fn process_matches_dir(
    process: &NamedProcessInfo,
    dir: &Path,
    exact_exe_path: Option<&Path>,
) -> Result<bool> {
    if let Some(path) = process.path.as_deref() {
        return Ok(path_is_same_or_descendant(Path::new(path), dir));
    }

    if let Some(exe_path) = exact_exe_path {
        return process_matches_exe(process.id, exe_path);
    }

    Ok(false)
}

fn format_process_info(process: &NamedProcessInfo) -> String {
    match process.path.as_deref() {
        Some(path) if !path.is_empty() => format!(
            "PID {} ({}) [{}]",
            process.id,
            process.process_name.as_deref().unwrap_or("unknown"),
            path
        ),
        _ => format!(
            "PID {} ({})",
            process.id,
            process.process_name.as_deref().unwrap_or("unknown")
        ),
    }
}

pub(super) fn log_processes_in_dir(
    process_name: &str,
    dir: &Path,
    exact_exe_path: Option<&Path>,
) -> Result<()> {
    let mut matches = vec![];

    for process in list_named_processes(process_name)? {
        if process_matches_dir(&process, dir, exact_exe_path)? {
            matches.push(format_process_info(&process));
        }
    }

    if matches.is_empty() {
        info!(
            "No {} processes were found running from {}",
            process_name,
            dir.display()
        );
    } else {
        warn!(
            "Detected {} process(es) running from {}:\n- {}",
            process_name,
            dir.display(),
            matches.join("\n- ")
        );
    }

    Ok(())
}

pub(super) fn stop_named_processes_in_dir(
    process_name: &str,
    dir: &Path,
    exact_exe_path: Option<&Path>,
) -> Result<()> {
    let mut matched_pids = vec![];

    for process in list_named_processes(process_name)? {
        if !process_matches_dir(&process, dir, exact_exe_path)? {
            continue;
        }

        info!(
            "Stopping {} process {} from managed path {}",
            process_name,
            format_process_info(&process),
            dir.display()
        );
        stop_pid(process.id)?;
        matched_pids.push(process.id);
    }

    if matched_pids.is_empty() {
        return Ok(());
    }

    let mut remaining = vec![];
    for process in list_named_processes(process_name)? {
        if process_matches_dir(&process, dir, exact_exe_path)? {
            remaining.push(format_process_info(&process));
        }
    }

    if remaining.is_empty() {
        Ok(())
    } else {
        bail!(
            "{} processes are still running from {}:\n- {}",
            process_name,
            dir.display(),
            remaining.join("\n- ")
        )
    }
}

pub(super) fn stop_pid(pid: u32) -> Result<()> {
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status()
        .context(format!("Failed to stop process {}", pid))?;

    if !status.success() {
        bail!("taskkill failed for PID {}", pid);
    }

    let started = std::time::Instant::now();
    while started.elapsed() < PROCESS_STOP_TIMEOUT {
        if !is_pid_running(pid) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    bail!("Process {} did not exit after taskkill", pid)
}

pub(super) fn cleanup_runtime_files(paths: &Paths, role: Role) -> Result<()> {
    let pid_path = role.pid_path(paths);
    let runtime_path = role.runtime_path(paths);
    remove_file_if_exists(&pid_path)?;
    remove_file_if_exists(&runtime_path)?;
    Ok(())
}

pub(super) fn managed_process_is_running(paths: &Paths, role: Role) -> Result<bool> {
    let pid_path = role.pid_path(paths);
    let runtime_path = role.runtime_path(paths);
    let metadata = match read_runtime_metadata(&runtime_path)? {
        Some(metadata) => metadata,
        None => {
            if pid_path.exists() {
                remove_file_if_exists(&pid_path)?;
            }
            return Ok(false);
        }
    };

    if metadata.role != role {
        warn!(
            "Runtime metadata {} belongs to role {} instead of {}. Cleaning it up.",
            runtime_path.display(),
            metadata.role,
            role
        );
        cleanup_runtime_files(paths, role)?;
        return Ok(false);
    }

    if !is_pid_running(metadata.pid) {
        cleanup_runtime_files(paths, role)?;
        return Ok(false);
    }

    if !process_matches_exe(metadata.pid, Path::new(&metadata.exe_path))? {
        warn!(
            "PID {} for role {} no longer matches {}. Cleaning up stale state.",
            metadata.pid, role, metadata.exe_path
        );
        cleanup_runtime_files(paths, role)?;
        return Ok(false);
    }

    if let Some(pid) = read_pid(&pid_path)?
        && pid != metadata.pid
    {
        warn!(
            "PID file {} disagrees with runtime metadata for role {}. Rewriting it.",
            pid_path.display(),
            role
        );
        write_pid(&pid_path, metadata.pid)?;
    }

    Ok(true)
}

pub(super) fn stop_managed_process(paths: &Paths, role: Role) -> Result<()> {
    let pid_path = role.pid_path(paths);
    let runtime_path = role.runtime_path(paths);
    let metadata = match read_runtime_metadata(&runtime_path)? {
        Some(metadata) => metadata,
        None => {
            remove_file_if_exists(&pid_path)?;
            return Ok(());
        }
    };

    if metadata.role != role {
        warn!(
            "Runtime metadata {} belongs to role {} instead of {}. Removing stale state.",
            runtime_path.display(),
            metadata.role,
            role
        );
        cleanup_runtime_files(paths, role)?;
        return Ok(());
    }

    let pid_running = is_pid_running(metadata.pid);
    if pid_running && process_matches_exe(metadata.pid, Path::new(&metadata.exe_path))? {
        info!("Stopping {} process with PID {}", role, metadata.pid);
        stop_pid(metadata.pid)?;
    } else if pid_running {
        warn!(
            "Refusing to stop PID {} for role {} because it no longer matches {}",
            metadata.pid, role, metadata.exe_path
        );
    }

    cleanup_runtime_files(paths, role)
}

pub(super) fn get_managed_runtime_metadata(
    paths: &Paths,
    role: Role,
) -> Result<Option<RuntimeMetadata>> {
    if !managed_process_is_running(paths, role)? {
        return Ok(None);
    }

    read_runtime_metadata(&role.runtime_path(paths))
}

pub(super) fn validate_background_process_started(metadata: &RuntimeMetadata) -> Result<()> {
    std::thread::sleep(EVEBOX_STARTUP_GRACE_PERIOD);

    if !is_pid_running(metadata.pid) {
        bail!("{} exited immediately after startup", metadata.role);
    }

    if !process_matches_exe(metadata.pid, Path::new(&metadata.exe_path))? {
        bail!(
            "{} PID {} no longer matches {}",
            metadata.role,
            metadata.pid,
            metadata.exe_path
        );
    }

    Ok(())
}

pub(super) fn format_command_line(command: &Command) -> String {
    fn quote(arg: &str) -> String {
        if arg.contains([' ', '\t', '"']) {
            format!("\"{}\"", arg.replace('"', "\\\""))
        } else {
            arg.to_string()
        }
    }

    let mut parts = vec![quote(&command.get_program().to_string_lossy())];
    for arg in command.get_args() {
        parts.push(quote(&arg.to_string_lossy()));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_and_runtime_files_are_stable() {
        let paths = Paths::new(PathBuf::from(r"C:\evectl"));
        for (role, name, dir) in [
            (Role::Suricata, "suricata", paths.suricata_run_dir()),
            (Role::EveBoxServer, "evebox", paths.evebox_dir()),
            (Role::EveBoxAgent, "evebox-agent", paths.evebox_agent_dir()),
            (Role::Housekeeper, "housekeeper", paths.suricata_run_dir()),
        ] {
            assert_eq!(role.as_str(), name);
            assert_eq!(serde_json::to_string(&role).unwrap(), format!("\"{name}\""));
            assert_eq!(
                serde_json::from_str::<Role>(&format!("\"{name}\"")).unwrap(),
                role
            );
            assert_eq!(role.pid_path(&paths), dir.join(format!("{name}.pid")));
            assert_eq!(
                role.runtime_path(&paths),
                dir.join(format!("{name}.runtime.json"))
            );
        }
    }
}
