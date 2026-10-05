// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Starting, stopping, and restarting the Windows service stack.

use super::evebox::{evebox_exe_path, find_evebox_exe};
use super::interfaces::{
    WindowsInterface, configured_interface_guid, normalize_interface_guid, resolve_interface_guid,
    windows_interfaces,
};
use super::paths::{Paths, ensure_dir, load_evectl_config};
use super::runtime::{
    Role, RuntimeMetadata, cleanup_runtime_files, command_argv, format_command_line,
    launch_managed, list_named_processes, managed_process_is_running, managed_runtime_metadata,
    stop_managed_process, stop_pid, validate_background_process_started,
};
use super::suricata::{
    build_suricata_command, ensure_suricata_start_allowed, find_suricata_executable,
    start_suricata_background, wait_for_suricata_pid_readiness,
};
use crate::prelude::*;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

const EVEBOX_PORT: &str = "5636";

static CTRL_C_RECEIVED: AtomicBool = AtomicBool::new(false);
static CTRL_C_HANDLER_SETUP: OnceLock<Result<(), String>> = OnceLock::new();

#[derive(Debug, Default, Clone)]
pub(super) struct RestartPlan {
    pub(super) suricata_running: bool,
    pub(super) suricata_guid: Option<String>,
    evebox_server_running: bool,
    evebox_agent_running: bool,
    housekeeper_running: bool,
}

impl RestartPlan {
    pub(super) fn any(&self) -> bool {
        self.suricata_running
            || self.evebox_server_running
            || self.evebox_agent_running
            || self.housekeeper_running
    }
}

/// Host for the EveBox server to listen on. Remote access without a
/// bind address listens on all IPv4 interfaces.
fn evebox_bind_host(
    server: &crate::config::EveBoxServerConfig,
    interfaces: &[WindowsInterface],
) -> Result<String> {
    if !server.allow_remote {
        return Ok("127.0.0.1".to_string());
    }
    match server.bind_address.as_deref() {
        None => Ok("0.0.0.0".to_string()),
        Some(value) if value.parse::<std::net::IpAddr>().is_ok() => Ok(value.to_string()),
        Some(name) => interfaces
            .iter()
            .find(|interface| {
                interface.name == name && interface.ip_address.parse::<std::net::Ipv4Addr>().is_ok()
            })
            .map(|interface| interface.ip_address.clone())
            .ok_or_else(|| anyhow!("No IPv4 address found for interface {name}")),
    }
}

/// Server options derived from the configuration: TLS, authentication,
/// and the listen address.
fn evebox_server_options(
    server: &crate::config::EveBoxServerConfig,
    interfaces: &[WindowsInterface],
) -> Result<Vec<String>> {
    let mut options = vec![];
    if server.no_auth {
        options.push("--no-auth".to_string());
    }
    if server.no_tls {
        options.push("--no-tls".to_string());
    }
    options.push("--host".to_string());
    options.push(evebox_bind_host(server, interfaces)?);
    options.push("--port".to_string());
    options.push(EVEBOX_PORT.to_string());
    Ok(options)
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct WindowsStatus {
    pub(super) suricata_enabled: bool,
    pub(super) suricata_installed: bool,
    pub(super) suricata_running: bool,
    pub(super) evebox_installed: bool,
    pub(super) evebox_server_enabled: bool,
    pub(super) evebox_server_running: bool,
    pub(super) evebox_agent_enabled: bool,
    pub(super) evebox_agent_running: bool,
    pub(super) housekeeper_enabled: bool,
    pub(super) housekeeper_running: bool,
}

impl WindowsStatus {
    pub(super) fn any_enabled(self) -> bool {
        self.suricata_enabled || self.evebox_server_enabled || self.evebox_agent_enabled
    }

    pub(super) fn any_running(self) -> bool {
        self.suricata_running
            || self.evebox_server_running
            || self.evebox_agent_running
            || self.housekeeper_running
    }

    /// True when one of the services started by `evectl start` is
    /// running; housekeeping is reconciled rather than restarted.
    fn services_running(self) -> bool {
        self.suricata_running || self.evebox_server_running || self.evebox_agent_running
    }

    pub(super) fn evebox_enabled(self) -> bool {
        self.evebox_server_enabled || self.evebox_agent_enabled
    }

    /// True when every enabled service has an executable the menu's
    /// Start action can launch.
    pub(super) fn ready_to_start(self) -> bool {
        self.any_enabled()
            && (!self.suricata_enabled || self.suricata_installed)
            && (!self.evebox_enabled() || self.evebox_installed)
    }
}

pub(super) fn windows_status(paths: &Paths, config: &Config) -> Result<WindowsStatus> {
    Ok(WindowsStatus {
        suricata_enabled: config.suricata.enabled,
        suricata_installed: find_suricata_executable(paths).is_some(),
        suricata_running: managed_process_is_running(paths, Role::Suricata)?,
        evebox_installed: find_evebox_exe(&paths.evebox_install_dir())?.is_some(),
        evebox_server_enabled: config.evebox_server.enabled,
        evebox_server_running: managed_process_is_running(paths, Role::EveBoxServer)?,
        evebox_agent_enabled: config.evebox_agent.enabled,
        evebox_agent_running: managed_process_is_running(paths, Role::EveBoxAgent)?,
        housekeeper_enabled: super::file_extraction::cleanup_enabled(config),
        housekeeper_running: managed_process_is_running(paths, Role::Housekeeper)?,
    })
}

/// The service status, refusing to start when nothing is enabled.
fn enabled_services(paths: &Paths, config: &Config) -> Result<WindowsStatus> {
    let status = windows_status(paths, config)?;
    if !status.any_enabled() {
        bail!("No services are enabled. Run 'evectl install' first.");
    }
    Ok(status)
}

/// URL for reaching the EveBox server from this host. With remote
/// access on all interfaces, the first non-loopback IPv4 address is
/// used, like the Linux status output.
pub(super) fn evebox_server_url(config: &crate::config::Config) -> String {
    let interfaces = windows_interfaces().unwrap_or_default();
    evebox_server_url_for(&config.evebox_server, &interfaces)
}

fn evebox_server_url_for(
    server: &crate::config::EveBoxServerConfig,
    interfaces: &[WindowsInterface],
) -> String {
    let scheme = if server.no_tls { "http" } else { "https" };
    let host = match evebox_bind_host(server, interfaces) {
        Ok(host) if host == "0.0.0.0" => interfaces
            .iter()
            .filter_map(|interface| interface.ip_address.parse::<std::net::Ipv4Addr>().ok())
            .find(|address| !address.is_loopback())
            .map(|address| address.to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        Ok(host) => host,
        Err(err) => {
            warn!("Failed to resolve the EveBox bind address: {err}");
            "127.0.0.1".to_string()
        }
    };
    format!("{scheme}://{host}:{EVEBOX_PORT}")
}

fn suricata_guid_from_metadata(metadata: &RuntimeMetadata) -> Option<String> {
    metadata.argv.windows(2).find_map(|window| {
        if window[0] == "-i" {
            normalize_interface_guid(&window[1])
        } else {
            None
        }
    })
}

pub(super) fn capture_restart_plan(paths: &Paths) -> Result<RestartPlan> {
    let suricata_running = managed_runtime_metadata(paths, Role::Suricata)?;
    let suricata_guid = suricata_running
        .as_ref()
        .and_then(suricata_guid_from_metadata)
        .or_else(|| configured_interface_guid(paths).ok().flatten());

    let evebox_server_running = managed_runtime_metadata(paths, Role::EveBoxServer)?.is_some();
    let evebox_agent_running = managed_runtime_metadata(paths, Role::EveBoxAgent)?.is_some();

    Ok(RestartPlan {
        suricata_running: suricata_running.is_some(),
        suricata_guid,
        evebox_server_running,
        evebox_agent_running,
        housekeeper_running: managed_process_is_running(paths, Role::Housekeeper)?,
    })
}

pub(super) fn restart_managed_components(
    paths: &Paths,
    config: &Config,
    plan: &RestartPlan,
) -> Result<()> {
    let result = (|| {
        if plan.suricata_running {
            let guid = plan.suricata_guid.as_deref().ok_or_else(|| {
                anyhow!(
                    "Failed to determine the interface GUID used by the previously running Suricata process"
                )
            })?;

            let suricata = start_suricata_background(paths, config, guid)?;
            wait_for_suricata_pid_readiness(paths, suricata.pid, Path::new(&suricata.exe_path))?;
        }

        if plan.evebox_server_running {
            let evebox = start_evebox_background(paths, config)?;
            validate_background_process_started(&evebox)?;
        }

        if plan.evebox_agent_running {
            let agent = start_evebox_agent_background(paths, config)?;
            validate_background_process_started(&agent)?;
        }
        if plan.suricata_running || plan.housekeeper_running {
            reconcile_housekeeper(paths, config)?;
        }

        Ok(())
    })();

    if result.is_err() {
        let _ = stop_stack(paths);
    }

    result
}

/// Pre-flight check used before starting any EveBox process. The
/// per-role checks in the start functions are skipped here so a
/// server and an agent can be started in sequence.
fn ensure_evebox_start_allowed(paths: &Paths) -> Result<()> {
    if managed_process_is_running(paths, Role::EveBoxServer)?
        || managed_process_is_running(paths, Role::EveBoxAgent)?
    {
        bail!("A managed EveBox process is already running. Use 'evectl stop' first.");
    }

    let process_count = list_named_processes("evebox")?.len();
    if process_count > 0 {
        bail!(
            "EveBox is already running ({} process(es) found). Use 'evectl stop' first.",
            process_count
        );
    }

    Ok(())
}

fn start_stack_foreground(paths: &Paths, guid: Option<String>) -> Result<()> {
    fn stop_children(children: &mut [(Role, Child)]) {
        // Housekeeping is spawned last; stop it before its producers/readers.
        for (_, child) in children.iter().rev() {
            let _ = stop_pid(child.id());
        }
        for (_, child) in children.iter_mut() {
            let _ = child.wait();
        }
    }

    fn spawn_foreground(
        mut command: Command,
        role: Role,
        children: &mut Vec<(Role, Child)>,
    ) -> Result<u32> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        info!("Running command: {}", format_command_line(&command));
        let mut child = command
            .spawn()
            .context(format!("Failed to start {}", role))?;
        crate::process_output::pipe_output(&mut child, role.as_str(), role == Role::Suricata, None);
        let pid = child.id();
        children.push((role, child));
        Ok(pid)
    }

    let config = load_evectl_config(paths)?;
    let status = enabled_services(paths, &config)?;

    if status.suricata_enabled {
        ensure_suricata_start_allowed(paths)?;
    }
    if status.evebox_enabled() {
        ensure_evebox_start_allowed(paths)?;
        let _ = evebox_exe_path(paths)?;
    }

    if status.housekeeper_running {
        bail!("Managed housekeeping is already running. Use 'evectl stop' first.");
    }
    ensure_ctrlc_handler()?;
    CTRL_C_RECEIVED.store(false, Ordering::SeqCst);

    let mut children: Vec<(Role, Child)> = vec![];

    let startup = (|| -> Result<()> {
        if status.suricata_enabled {
            let guid = resolve_interface_guid(paths, guid, true)?;
            let command = build_suricata_command(paths, &config, &guid)?;
            let suricata_exe = PathBuf::from(command.get_program());
            let pid = spawn_foreground(command, Role::Suricata, &mut children)?;
            wait_for_suricata_pid_readiness(paths, pid, &suricata_exe)?;
        }

        if status.evebox_server_enabled {
            spawn_foreground(
                build_evebox_command(paths, &config)?,
                Role::EveBoxServer,
                &mut children,
            )?;
        }

        if status.evebox_agent_enabled {
            spawn_foreground(
                build_evebox_agent_command(paths, &config)?,
                Role::EveBoxAgent,
                &mut children,
            )?;
        }
        if super::file_extraction::cleanup_enabled(&config) {
            let command = build_housekeeper_command(paths, &config)?;
            prepare_housekeeper_executable(&command)?;
            spawn_foreground(command, Role::Housekeeper, &mut children)?;
        }

        Ok(())
    })();

    if let Err(err) = startup {
        stop_children(&mut children);
        return Err(err);
    }

    println!("Foreground Windows stack started");
    for (role, child) in &children {
        println!("  {} PID: {}", role, child.id());
    }
    if status.evebox_server_enabled {
        println!("  EveBox URL: {}", evebox_server_url(&config));
    }
    println!("Press Ctrl-C to stop.");

    let mut failure: Option<String> = None;
    let mut shutdown_requested = false;
    let mut statuses: Vec<Option<std::process::ExitStatus>> = vec![None; children.len()];

    loop {
        let mut request_shutdown = false;

        if !shutdown_requested && CTRL_C_RECEIVED.swap(false, Ordering::SeqCst) {
            info!("Received Ctrl-C, stopping foreground Windows stack");
            request_shutdown = true;
        }

        for (index, (role, child)) in children.iter_mut().enumerate() {
            if statuses[index].is_none()
                && let Some(status) = child.try_wait()?
            {
                if !shutdown_requested && !request_shutdown {
                    failure = Some(format!("{} exited with status: {}", role, status));
                    request_shutdown = true;
                }
                statuses[index] = Some(status);
            }
        }

        if request_shutdown && !shutdown_requested {
            shutdown_requested = true;
            for (index, (_, child)) in children.iter().enumerate().rev() {
                if statuses[index].is_none() {
                    let _ = stop_pid(child.id());
                }
            }
        }

        if statuses.iter().all(|status| status.is_some()) {
            break;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    if let Some(message) = failure {
        bail!(message);
    }

    Ok(())
}

fn build_evebox_command(paths: &Paths, config: &Config) -> Result<Command> {
    let evebox_exe = evebox_exe_path(paths)?;

    let evebox_root_dir = paths.evebox_dir();
    let evebox_data_dir = paths.evebox_data_dir();
    ensure_dir(&evebox_root_dir)?;
    ensure_dir(&evebox_data_dir)?;

    let mut command = Command::new(&evebox_exe);
    command.current_dir(&evebox_data_dir);
    command.arg("server");
    command.arg("--sqlite");
    command.args(evebox_server_options(
        &config.evebox_server,
        &windows_interfaces()?,
    )?);
    command.arg("-D");
    command.arg(&evebox_data_dir);
    command.arg(paths.suricata_eve_json());
    super::fpc::configure_evebox_command(&mut command, config, &paths.suricata_pcap_dir());
    super::file_extraction::configure_evebox_command(
        &mut command,
        config,
        &paths.suricata_filestore_dir(),
    );

    Ok(command)
}

fn start_evebox_background(paths: &Paths, config: &Config) -> Result<RuntimeMetadata> {
    if managed_process_is_running(paths, Role::EveBoxServer)? {
        bail!("A managed EveBox server is already running. Use 'evectl stop' first.");
    }

    let mut command = build_evebox_command(paths, config)?;
    launch_managed(paths, Role::EveBoxServer, &mut command, None)
}

/// Write the EveBox agent input configuration with Windows paths.
/// Forward slashes keep the YAML free of escape issues.
fn write_evebox_agent_config(paths: &Paths) -> Result<PathBuf> {
    fn yaml_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    let agent_dir = paths.evebox_agent_dir();
    let data_dir = paths.evebox_agent_data_dir();
    ensure_dir(&data_dir)?;

    let config_path = agent_dir.join("evectl-input.yaml");
    let contents = format!(
        "# Generated by evectl. Do not edit.\ndata-directory: \"{}\"\ninput:\n  paths:\n    - \"{}\"\n",
        yaml_path(&data_dir),
        yaml_path(&paths.suricata_eve_json())
    );

    std::fs::write(&config_path, contents).context(format!(
        "Failed to write EveBox agent configuration {}",
        config_path.display()
    ))?;

    Ok(config_path)
}

fn build_evebox_agent_command(paths: &Paths, config: &Config) -> Result<Command> {
    if config.evebox_agent.server.trim().is_empty() {
        bail!("The EveBox agent server URL is not configured");
    }

    let evebox_exe = evebox_exe_path(paths)?;
    let agent_dir = paths.evebox_agent_dir();
    ensure_dir(&agent_dir)?;
    let config_path = write_evebox_agent_config(paths)?;

    let mut command = Command::new(&evebox_exe);
    command.current_dir(&agent_dir);
    command.arg("agent");
    command.arg("--config");
    command.arg(&config_path);
    command.arg("--server");
    command.arg(&config.evebox_agent.server);
    if config.evebox_agent.disable_certificate_validation {
        command.arg("--disable-certificate-check");
    }
    super::fpc::configure_agent_command(&mut command, config, &paths.suricata_pcap_dir());
    super::file_extraction::configure_evebox_command(
        &mut command,
        config,
        &paths.suricata_filestore_dir(),
    );

    Ok(command)
}

fn start_evebox_agent_background(paths: &Paths, config: &Config) -> Result<RuntimeMetadata> {
    if managed_process_is_running(paths, Role::EveBoxAgent)? {
        bail!("A managed EveBox agent is already running. Use 'evectl stop' first.");
    }

    let mut command = build_evebox_agent_command(paths, config)?;
    launch_managed(paths, Role::EveBoxAgent, &mut command, None)
}

/// Use a separate executable so the worker does not lock the EveCtl launcher
/// against replacement by a staged self-update.
fn build_housekeeper_command(paths: &Paths, config: &Config) -> Result<Command> {
    let mut command = Command::new(paths.housekeeper_exe());
    command
        .arg("housekeep")
        .arg("--retention-days")
        .arg(config.suricata.file_extraction.max_age_days().to_string());
    Ok(command)
}

/// Refresh only when launching, after any previous worker has been stopped.
fn prepare_housekeeper_executable(command: &Command) -> Result<()> {
    super::process::copy_worker_executable(
        &std::env::current_exe()?,
        Path::new(command.get_program()),
    )
    .context("Failed to prepare the housekeeping executable")
}

pub(super) fn run_housekeeper(paths: &Paths, retention_days: u32) -> Result<()> {
    let directory = paths.suricata_filestore_dir();
    ensure_ctrlc_handler()?;
    info!(
        "Filestore cleanup: {} (retention: {retention_days} days)",
        directory.display()
    );
    loop {
        match super::file_extraction::prune(&directory, retention_days, SystemTime::now()) {
            Ok(removed) => info!("Filestore cleanup removed {removed} files"),
            Err(err) => warn!("Filestore cleanup failed: {err:#}"),
        }
        let next = std::time::Instant::now() + super::file_extraction::CLEANUP_INTERVAL;
        while std::time::Instant::now() < next {
            if CTRL_C_RECEIVED.load(Ordering::SeqCst) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Restore a stopped worker or replace one whose retention settings changed.
fn reconcile_housekeeper(paths: &Paths, config: &Config) -> Result<Option<RuntimeMetadata>> {
    if !super::file_extraction::cleanup_enabled(config) {
        stop_managed_process(paths, Role::Housekeeper)?;
        return Ok(None);
    }
    let mut command = build_housekeeper_command(paths, config)?;
    if let Some(metadata) = managed_runtime_metadata(paths, Role::Housekeeper)? {
        if metadata.argv == command_argv(&command) {
            return Ok(Some(metadata));
        }
        stop_managed_process(paths, Role::Housekeeper)?;
    }
    ensure_dir(&paths.suricata_run_dir())?;
    ensure_dir(&paths.suricata_log_dir())?;
    prepare_housekeeper_executable(&command)?;
    let metadata = launch_managed(
        paths,
        Role::Housekeeper,
        &mut command,
        Some((
            &paths.housekeeper_stdout_log(),
            &paths.housekeeper_stderr_log(),
        )),
    )?;
    if let Err(err) = validate_background_process_started(&metadata) {
        let _ = stop_pid(metadata.pid);
        let _ = cleanup_runtime_files(paths, Role::Housekeeper);
        return Err(err);
    }
    Ok(Some(metadata))
}

pub(super) fn start_stack(paths: &Paths, debug: bool, guid: Option<String>) -> Result<()> {
    if debug {
        return start_stack_foreground(paths, guid);
    }

    let config = load_evectl_config(paths)?;
    let status = enabled_services(paths, &config)?;

    if status.services_running() {
        bail!("The Windows-managed stack is already running. Use 'evectl stop' first.");
    }

    if status.evebox_enabled() {
        ensure_evebox_start_allowed(paths)?;
        let _ = evebox_exe_path(paths)?;
    }

    let result = (|| -> Result<Vec<RuntimeMetadata>> {
        let mut started = vec![];

        if status.suricata_enabled {
            let guid = resolve_interface_guid(paths, guid, true)?;
            let suricata = start_suricata_background(paths, &config, &guid)?;
            wait_for_suricata_pid_readiness(paths, suricata.pid, Path::new(&suricata.exe_path))?;
            started.push(suricata);
        }

        if status.evebox_server_enabled {
            let evebox = start_evebox_background(paths, &config)?;
            validate_background_process_started(&evebox)?;
            started.push(evebox);
        }

        if status.evebox_agent_enabled {
            let agent = start_evebox_agent_background(paths, &config)?;
            validate_background_process_started(&agent)?;
            started.push(agent);
        }
        if let Some(housekeeper) = reconcile_housekeeper(paths, &config)? {
            started.push(housekeeper);
        }

        Ok(started)
    })();

    let started = match result {
        Ok(started) => started,
        Err(err) => {
            let _ = stop_stack(paths);
            return Err(err);
        }
    };

    println!("Windows stack started in background");
    for metadata in &started {
        println!("  {} PID: {}", metadata.role, metadata.pid);
    }
    if status.suricata_enabled {
        println!("  Suricata log: {}", paths.suricata_log_dir().display());
    }
    if status.evebox_server_enabled {
        println!("  EveBox data:  {}", paths.evebox_data_dir().display());
        println!("  EveBox URL:   {}", evebox_server_url(&config));
    }

    Ok(())
}

/// Restart the stack, preferring the interface the running Suricata
/// was started with (e.g. a --guid override) over the saved config.
pub(super) fn restart_stack(paths: &Paths) -> Result<()> {
    crate::restart_notice::complete_restart(paths.root(), || {
        let guid = capture_restart_plan(paths)?.suricata_guid;
        stop_stack(paths)?;
        start_stack(paths, false, guid)
    })
}

pub(super) fn stop_stack(paths: &Paths) -> Result<()> {
    let mut errors = vec![];

    if let Err(err) = stop_managed_process(paths, Role::Housekeeper) {
        errors.push(format!("Failed to stop housekeeping: {err}"));
    }
    if let Err(err) = stop_managed_process(paths, Role::EveBoxAgent) {
        errors.push(format!("Failed to stop EveBox agent: {err}"));
    }

    if let Err(err) = stop_managed_process(paths, Role::EveBoxServer) {
        errors.push(format!("Failed to stop EveBox: {err}"));
    }

    if let Err(err) = stop_managed_process(paths, Role::Suricata) {
        errors.push(format!("Failed to stop Suricata: {err}"));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        bail!("{}", errors.join("\n"))
    }
}

fn ensure_ctrlc_handler() -> Result<()> {
    let result = CTRL_C_HANDLER_SETUP.get_or_init(|| {
        ctrlc::set_handler(|| {
            CTRL_C_RECEIVED.store(true, Ordering::SeqCst);
        })
        .map_err(|err| err.to_string())
    });

    match result {
        Ok(()) => Ok(()),
        Err(err) => bail!("Failed to set Ctrl-C handler: {}", err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interfaces() -> Vec<WindowsInterface> {
        vec![
            WindowsInterface {
                name: "Loopback".to_string(),
                ip_address: "127.0.0.1".to_string(),
                guid: "{lo}".to_string(),
            },
            WindowsInterface {
                name: "Ethernet".to_string(),
                ip_address: "192.0.2.10".to_string(),
                guid: "{eth}".to_string(),
            },
            WindowsInterface {
                name: "Wi-Fi 6".to_string(),
                ip_address: "fe80::1".to_string(),
                guid: "{wifi}".to_string(),
            },
        ]
    }

    #[test]
    fn evebox_server_options_follow_remote_tls_and_auth_settings() {
        let mut server = crate::config::EveBoxServerConfig::default();
        assert_eq!(
            evebox_server_options(&server, &interfaces()).unwrap(),
            ["--host", "127.0.0.1", "--port", "5636"]
        );

        server.no_tls = true;
        server.no_auth = true;
        server.allow_remote = true;
        assert_eq!(
            evebox_server_options(&server, &interfaces()).unwrap(),
            [
                "--no-auth",
                "--no-tls",
                "--host",
                "0.0.0.0",
                "--port",
                "5636"
            ]
        );

        server.bind_address = Some("192.0.2.10".to_string());
        assert_eq!(
            evebox_bind_host(&server, &interfaces()).unwrap(),
            "192.0.2.10"
        );
        server.bind_address = Some("Ethernet".to_string());
        assert_eq!(
            evebox_bind_host(&server, &interfaces()).unwrap(),
            "192.0.2.10"
        );
        for missing in ["Wi-Fi 6", "Unknown"] {
            server.bind_address = Some(missing.to_string());
            assert!(evebox_bind_host(&server, &interfaces()).is_err());
        }

        // The bind address is ignored without remote access.
        server.allow_remote = false;
        assert_eq!(
            evebox_bind_host(&server, &interfaces()).unwrap(),
            "127.0.0.1"
        );
    }

    #[test]
    fn evebox_server_url_reflects_scheme_and_reachable_address() {
        let mut server = crate::config::EveBoxServerConfig::default();
        assert_eq!(
            evebox_server_url_for(&server, &interfaces()),
            "https://127.0.0.1:5636"
        );
        server.no_tls = true;
        server.allow_remote = true;
        assert_eq!(
            evebox_server_url_for(&server, &interfaces()),
            "http://192.0.2.10:5636"
        );
        assert_eq!(evebox_server_url_for(&server, &[]), "http://127.0.0.1:5636");
        server.bind_address = Some("Ethernet".to_string());
        assert_eq!(
            evebox_server_url_for(&server, &interfaces()),
            "http://192.0.2.10:5636"
        );
        server.bind_address = Some("Unknown".to_string());
        assert_eq!(
            evebox_server_url_for(&server, &interfaces()),
            "http://127.0.0.1:5636"
        );
    }

    #[test]
    fn housekeeper_command_snapshots_retention_without_credentials() {
        let mut config = Config::default();
        config.suricata.file_extraction.max_age_days = Some(19);
        config.evebox_agent.key = Some("secret-agent-key".into());
        let paths = Paths::new(PathBuf::from(r"C:\evectl"));
        let command = build_housekeeper_command(&paths, &config).unwrap();
        assert_eq!(Path::new(command.get_program()), paths.housekeeper_exe());
        assert_ne!(
            Path::new(command.get_program()),
            std::env::current_exe().unwrap()
        );
        assert_eq!(
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["housekeep", "--retention-days", "19"]
        );
        assert_eq!(command.get_envs().count(), 0);
    }
}
