// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Starting, stopping, and restarting the Windows service stack.

use super::evebox::get_evebox_exe_path;
use super::interfaces::{
    WindowsInterface, get_configured_interface_guid, get_windows_interfaces,
    normalize_interface_guid, resolve_interface_guid,
};
use super::paths::{
    ensure_dir, get_evebox_agent_data_dir, get_evebox_agent_dir, get_evebox_agent_pid_path,
    get_evebox_agent_runtime_path, get_evebox_data_dir, get_evebox_pid_path, get_evebox_root_dir,
    get_evebox_runtime_path, get_evectl_data_dir, get_suricata_eve_json_path,
    get_suricata_filestore_dir, get_suricata_log_dir, get_suricata_pcap_dir, get_suricata_run_dir,
    load_evectl_config,
};
use super::runtime::{
    ROLE_EVEBOX, ROLE_EVEBOX_AGENT, ROLE_HOUSEKEEPER, ROLE_SURICATA, RuntimeMetadata,
    build_runtime_metadata, cleanup_runtime_files, command_argv, count_named_processes,
    format_command_line, get_managed_runtime_metadata, managed_process_is_running, role_paths,
    spawn_detached, spawn_detached_with_logs, stop_managed_process, stop_pid,
    validate_background_process_started, write_pid, write_runtime_metadata,
};
use super::suricata::{
    build_suricata_command, ensure_suricata_start_allowed, start_suricata_background,
    stop_suricata_managed, wait_for_suricata_pid_readiness, wait_for_suricata_readiness,
};
use crate::prelude::*;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

const STATUS_CONTROL_C_EXIT: i32 = -1073741510;

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

/// URL for reaching the EveBox server from this host. With remote
/// access on all interfaces, the first non-loopback IPv4 address is
/// used, like the Linux status output.
pub(super) fn evebox_server_url(config: &crate::config::Config) -> String {
    let interfaces = get_windows_interfaces().unwrap_or_default();
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

pub(super) fn capture_restart_plan() -> Result<RestartPlan> {
    let suricata_running = get_managed_runtime_metadata(ROLE_SURICATA)?;
    let suricata_guid = suricata_running
        .as_ref()
        .and_then(suricata_guid_from_metadata)
        .or_else(|| get_configured_interface_guid().ok().flatten());

    let evebox_server_running = get_managed_runtime_metadata(ROLE_EVEBOX)?.is_some();
    let evebox_agent_running = get_managed_runtime_metadata(ROLE_EVEBOX_AGENT)?.is_some();

    Ok(RestartPlan {
        suricata_running: suricata_running.is_some(),
        suricata_guid,
        evebox_server_running,
        evebox_agent_running,
        housekeeper_running: managed_process_is_running(ROLE_HOUSEKEEPER)?,
    })
}

pub(super) fn restart_managed_components(plan: &RestartPlan) -> Result<()> {
    let result = (|| {
        if plan.suricata_running {
            let guid = plan.suricata_guid.as_deref().ok_or_else(|| {
                anyhow!(
                    "Failed to determine the interface GUID used by the previously running Suricata process"
                )
            })?;

            let suricata = start_suricata_background(guid)?;
            wait_for_suricata_readiness(&suricata)?;
        }

        if plan.evebox_server_running {
            let evebox = start_evebox_background()?;
            validate_background_process_started(&evebox)?;
        }

        if plan.evebox_agent_running {
            let agent = start_evebox_agent_background()?;
            validate_background_process_started(&agent)?;
        }
        if plan.suricata_running || plan.housekeeper_running {
            reconcile_housekeeper(&load_evectl_config()?)?;
        }

        Ok(())
    })();

    if result.is_err() {
        let _ = stop_stack();
    }

    result
}

fn process_line_reader<R: std::io::Read + Send + 'static>(output: R, label: &'static str) {
    let reader = BufReader::new(output).lines();
    for line in reader {
        match line {
            Ok(line) => {
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(&mut stdout, "{}: {}", label, line);
                let _ = stdout.flush();
            }
            Err(err) => {
                debug!("Failed to read {} output: {}", label, err);
                break;
            }
        }
    }
}

fn process_output_handler(child: &mut Child, label: &'static str) {
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || process_line_reader(stdout, label));
    }

    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || process_line_reader(stderr, label));
    }
}

/// Pre-flight check used before starting any EveBox process. The
/// per-role checks in the start functions are skipped here so a
/// server and an agent can be started in sequence.
fn ensure_evebox_start_allowed() -> Result<()> {
    if managed_process_is_running(ROLE_EVEBOX)? || managed_process_is_running(ROLE_EVEBOX_AGENT)? {
        bail!("A managed EveBox process is already running. Use 'evectl stop' first.");
    }

    let process_count = count_named_processes("evebox")?;
    if process_count > 0 {
        bail!(
            "EveBox is already running ({} process(es) found). Use 'evectl stop' first.",
            process_count
        );
    }

    Ok(())
}

fn start_stack_foreground(guid: Option<String>) -> Result<()> {
    fn stop_children(children: &mut Vec<(&'static str, Child)>) {
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
        role: &'static str,
        children: &mut Vec<(&'static str, Child)>,
    ) -> Result<u32> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        info!("Running command: {}", format_command_line(&command));
        let mut child = command
            .spawn()
            .context(format!("Failed to start {}", role))?;
        process_output_handler(&mut child, role);
        let pid = child.id();
        children.push((role, child));
        Ok(pid)
    }

    let config = load_evectl_config()?;
    let use_suricata = config.suricata.enabled;
    let use_server = config.evebox_server.enabled;
    let use_agent = config.evebox_agent.enabled;

    if !use_suricata && !use_server && !use_agent {
        bail!("No services are enabled. Run 'evectl install' first.");
    }

    if use_suricata {
        ensure_suricata_start_allowed()?;
    }
    if use_server || use_agent {
        ensure_evebox_start_allowed()?;
        let _ = get_evebox_exe_path()?;
    }

    if managed_process_is_running(ROLE_HOUSEKEEPER)? {
        bail!("Managed housekeeping is already running. Use 'evectl stop' first.");
    }
    ensure_ctrlc_handler()?;
    CTRL_C_RECEIVED.store(false, Ordering::SeqCst);

    let mut children: Vec<(&'static str, Child)> = vec![];

    let startup = (|| -> Result<()> {
        if use_suricata {
            let guid = resolve_interface_guid(guid, true)?;
            let command = build_suricata_command(&guid)?;
            let suricata_exe = PathBuf::from(command.get_program());
            let pid = spawn_foreground(command, ROLE_SURICATA, &mut children)?;
            wait_for_suricata_pid_readiness(pid, &suricata_exe)?;
        }

        if use_server {
            spawn_foreground(build_evebox_command()?, ROLE_EVEBOX, &mut children)?;
        }

        if use_agent {
            spawn_foreground(
                build_evebox_agent_command()?,
                ROLE_EVEBOX_AGENT,
                &mut children,
            )?;
        }
        if super::file_extraction::cleanup_enabled(&config) {
            let command = build_housekeeper_command(&config)?;
            prepare_housekeeper_executable(&command)?;
            spawn_foreground(command, ROLE_HOUSEKEEPER, &mut children)?;
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
    if use_server {
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

fn build_evebox_command() -> Result<Command> {
    let evebox_exe = get_evebox_exe_path()?;

    let evebox_root_dir = get_evebox_root_dir()?;
    let evebox_data_dir = get_evebox_data_dir()?;
    ensure_dir(&evebox_root_dir)?;
    ensure_dir(&evebox_data_dir)?;

    let config = load_evectl_config()?;
    let mut command = Command::new(&evebox_exe);
    command.current_dir(&evebox_data_dir);
    command.arg("server");
    command.arg("--sqlite");
    command.args(evebox_server_options(
        &config.evebox_server,
        &get_windows_interfaces()?,
    )?);
    command.arg("-D");
    command.arg(&evebox_data_dir);
    command.arg(get_suricata_eve_json_path()?);
    super::fpc::configure_evebox_command(&mut command, &config, &get_suricata_pcap_dir()?);
    super::file_extraction::configure_evebox_command(
        &mut command,
        &config,
        &get_suricata_filestore_dir()?,
    );

    Ok(command)
}

fn start_evebox_background() -> Result<RuntimeMetadata> {
    if managed_process_is_running(ROLE_EVEBOX)? {
        bail!("A managed EveBox server is already running. Use 'evectl stop' first.");
    }

    let mut command = build_evebox_command()?;
    info!("Running command: {}", format_command_line(&command));
    let pid = spawn_detached(&mut command)?;
    let metadata = build_runtime_metadata(ROLE_EVEBOX, &command, pid, None, None)?;

    write_pid(&get_evebox_pid_path()?, pid)?;
    write_runtime_metadata(&get_evebox_runtime_path()?, &metadata)?;

    Ok(metadata)
}

/// Write the EveBox agent input configuration with Windows paths.
/// Forward slashes keep the YAML free of escape issues.
fn write_evebox_agent_config() -> Result<PathBuf> {
    fn yaml_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    let agent_dir = get_evebox_agent_dir()?;
    let data_dir = get_evebox_agent_data_dir()?;
    ensure_dir(&data_dir)?;

    let config_path = agent_dir.join("evectl-input.yaml");
    let contents = format!(
        "# Generated by evectl. Do not edit.\ndata-directory: \"{}\"\ninput:\n  paths:\n    - \"{}\"\n",
        yaml_path(&data_dir),
        yaml_path(&get_suricata_eve_json_path()?)
    );

    std::fs::write(&config_path, contents).context(format!(
        "Failed to write EveBox agent configuration {}",
        config_path.display()
    ))?;

    Ok(config_path)
}

fn build_evebox_agent_command() -> Result<Command> {
    let config = load_evectl_config()?;
    if config.evebox_agent.server.trim().is_empty() {
        bail!("The EveBox agent server URL is not configured");
    }

    let evebox_exe = get_evebox_exe_path()?;
    let agent_dir = get_evebox_agent_dir()?;
    ensure_dir(&agent_dir)?;
    let config_path = write_evebox_agent_config()?;

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
    super::fpc::configure_agent_command(&mut command, &config, &get_suricata_pcap_dir()?);
    super::file_extraction::configure_evebox_command(
        &mut command,
        &config,
        &get_suricata_filestore_dir()?,
    );

    Ok(command)
}

fn start_evebox_agent_background() -> Result<RuntimeMetadata> {
    if managed_process_is_running(ROLE_EVEBOX_AGENT)? {
        bail!("A managed EveBox agent is already running. Use 'evectl stop' first.");
    }

    let mut command = build_evebox_agent_command()?;
    info!("Running command: {}", format_command_line(&command));
    let pid = spawn_detached(&mut command)?;
    let metadata = build_runtime_metadata(ROLE_EVEBOX_AGENT, &command, pid, None, None)?;

    write_pid(&get_evebox_agent_pid_path()?, pid)?;
    write_runtime_metadata(&get_evebox_agent_runtime_path()?, &metadata)?;

    Ok(metadata)
}

fn stop_evebox_managed() -> Result<()> {
    stop_managed_process(ROLE_EVEBOX)
}

fn stop_evebox_agent_managed() -> Result<()> {
    stop_managed_process(ROLE_EVEBOX_AGENT)
}

/// Use a separate executable so the worker does not lock the EveCtl launcher
/// against replacement by a staged self-update.
fn build_housekeeper_command(config: &Config) -> Result<Command> {
    let mut command = Command::new(get_suricata_run_dir()?.join("housekeeper.exe"));
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

pub(super) fn run_housekeeper(retention_days: u32) -> Result<()> {
    let directory = get_suricata_filestore_dir()?;
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
fn reconcile_housekeeper(config: &Config) -> Result<Option<RuntimeMetadata>> {
    if !super::file_extraction::cleanup_enabled(config) {
        stop_managed_process(ROLE_HOUSEKEEPER)?;
        return Ok(None);
    }
    let mut command = build_housekeeper_command(config)?;
    if let Some(metadata) = get_managed_runtime_metadata(ROLE_HOUSEKEEPER)? {
        if metadata.argv == command_argv(&command) {
            return Ok(Some(metadata));
        }
        stop_managed_process(ROLE_HOUSEKEEPER)?;
    }
    ensure_dir(&get_suricata_run_dir()?)?;
    ensure_dir(&get_suricata_log_dir()?)?;
    let stdout = get_suricata_log_dir()?.join("housekeeper-stdout.log");
    let stderr = get_suricata_log_dir()?.join("housekeeper-stderr.log");
    prepare_housekeeper_executable(&command)?;
    info!("Running command: {}", format_command_line(&command));
    let pid = spawn_detached_with_logs(&mut command, Some(&stdout), Some(&stderr))?;
    let result = (|| {
        let metadata = build_runtime_metadata(
            ROLE_HOUSEKEEPER,
            &command,
            pid,
            Some(&stdout),
            Some(&stderr),
        )?;
        let (pid_path, runtime_path) = role_paths(ROLE_HOUSEKEEPER)?;
        write_pid(&pid_path, pid)?;
        write_runtime_metadata(&runtime_path, &metadata)?;
        validate_background_process_started(&metadata)?;
        Ok(Some(metadata))
    })();
    if result.is_err() {
        let _ = stop_pid(pid);
        let _ = cleanup_runtime_files(ROLE_HOUSEKEEPER);
    }
    result
}

pub(super) fn start_stack(debug: bool, guid: Option<String>) -> Result<()> {
    if debug {
        return start_stack_foreground(guid);
    }

    let config = load_evectl_config()?;
    let use_suricata = config.suricata.enabled;
    let use_server = config.evebox_server.enabled;
    let use_agent = config.evebox_agent.enabled;

    if !use_suricata && !use_server && !use_agent {
        bail!("No services are enabled. Run 'evectl install' first.");
    }

    if managed_process_is_running(ROLE_SURICATA)?
        || managed_process_is_running(ROLE_EVEBOX)?
        || managed_process_is_running(ROLE_EVEBOX_AGENT)?
    {
        bail!("The Windows-managed stack is already running. Use 'evectl stop' first.");
    }

    if use_server || use_agent {
        ensure_evebox_start_allowed()?;
        let _ = get_evebox_exe_path()?;
    }

    let result = (|| -> Result<Vec<RuntimeMetadata>> {
        let mut started = vec![];

        if use_suricata {
            let guid = resolve_interface_guid(guid, true)?;
            let suricata = start_suricata_background(&guid)?;
            wait_for_suricata_readiness(&suricata)?;
            started.push(suricata);
        }

        if use_server {
            let evebox = start_evebox_background()?;
            validate_background_process_started(&evebox)?;
            started.push(evebox);
        }

        if use_agent {
            let agent = start_evebox_agent_background()?;
            validate_background_process_started(&agent)?;
            started.push(agent);
        }
        if let Some(housekeeper) = reconcile_housekeeper(&config)? {
            started.push(housekeeper);
        }

        Ok(started)
    })();

    let started = match result {
        Ok(started) => started,
        Err(err) => {
            let _ = stop_stack();
            return Err(err);
        }
    };

    println!("Windows stack started in background");
    for metadata in &started {
        println!("  {} PID: {}", metadata.role, metadata.pid);
    }
    if use_suricata {
        println!("  Suricata log: {}", get_suricata_log_dir()?.display());
    }
    if use_server {
        println!("  EveBox data:  {}", get_evebox_data_dir()?.display());
        println!("  EveBox URL:   {}", evebox_server_url(&config));
    }

    Ok(())
}

/// Restart the stack, preferring the interface the running Suricata
/// was started with (e.g. a --guid override) over the saved config.
pub(super) fn restart_stack() -> Result<()> {
    let guid = capture_restart_plan()?.suricata_guid;
    stop_stack()?;
    start_stack(false, guid)?;
    if let Err(err) = super::update::clear_restart_recommendation(&get_evectl_data_dir()?) {
        warn!("Services restarted, but failed to clear the restart recommendation: {err}");
    }
    Ok(())
}

pub(super) fn stop_stack() -> Result<()> {
    let mut errors = vec![];

    if let Err(err) = stop_managed_process(ROLE_HOUSEKEEPER) {
        errors.push(format!("Failed to stop housekeeping: {err}"));
    }
    if let Err(err) = stop_evebox_agent_managed() {
        errors.push(format!("Failed to stop EveBox agent: {err}"));
    }

    if let Err(err) = stop_evebox_managed() {
        errors.push(format!("Failed to stop EveBox: {err}"));
    }

    if let Err(err) = stop_suricata_managed() {
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
        let command = build_housekeeper_command(&config).unwrap();
        assert_eq!(
            Path::new(command.get_program()),
            get_suricata_run_dir().unwrap().join("housekeeper.exe")
        );
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
