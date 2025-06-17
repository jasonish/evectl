// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::container::ContainerManager;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum ServiceManager {
    Container(ContainerManager),
    #[cfg(windows)]
    Process(ProcessManager),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub name: String,
    pub executable_path: PathBuf,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
    pub env_vars: std::collections::HashMap<String, String>,
    pub log_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub running: bool,
    pub pid: Option<u32>,
    pub start_time: Option<std::time::SystemTime>,
    pub command_line: Option<String>,
}

pub trait ServiceControl {
    fn start(&self, service: &ServiceDefinition) -> Result<()>;
    fn stop(&self, service_name: &str) -> Result<()>;
    fn is_running(&self, service_name: &str) -> bool;
    fn get_status(&self, service_name: &str) -> Result<ServiceStatus>;
    fn list_services(&self) -> Result<Vec<ServiceStatus>>;
    fn service_exists(&self, service_name: &str) -> bool;
}

impl ServiceControl for ContainerManager {
    fn start(&self, service: &ServiceDefinition) -> Result<()> {
        // Remove any existing container first
        self.quiet_rm(&service.name);

        let mut command = self.command();
        command.arg("run");
        command.arg("--name").arg(&service.name);
        command.arg("-d"); // detached mode

        // Add volumes and other container configuration from env_vars
        for (key, value) in &service.env_vars {
            if key.starts_with("VOLUME_") {
                command.arg("--volume").arg(value);
            } else if key == "PUBLISH_PORT" {
                command.arg("--publish").arg(value);
            } else if key == "NET_MODE" && value == "host" {
                command.arg("--net=host");
            } else if key.starts_with("EVEBOX_") {
                // Pass EveBox environment variables to the container
                command.arg("--env").arg(format!("{}={}", key, value));
            }
        }

        command.arg(&service.executable_path); // This would be the image name for containers
        command.args(&service.args);

        // Log the container command being executed
        info!("Starting container service {} with command:", service.name);
        info!("  Container runtime: {:?}", self);
        info!("  Full command: {:?}", command);

        let output = command.output()?;
        if !output.status.success() {
            bail!(String::from_utf8_lossy(&output.stderr).to_string());
        }

        Ok(())
    }

    fn stop(&self, service_name: &str) -> Result<()> {
        self.stop(service_name, Some("SIGINT"))
    }

    fn is_running(&self, service_name: &str) -> bool {
        self.is_running(service_name)
    }

    fn get_status(&self, service_name: &str) -> Result<ServiceStatus> {
        if let Ok(state) = self.state(service_name) {
            Ok(ServiceStatus {
                name: service_name.to_string(),
                running: state.running,
                pid: None,        // Container PID not directly accessible
                start_time: None, // Would need to parse from container inspect
                command_line: None,
            })
        } else {
            Ok(ServiceStatus {
                name: service_name.to_string(),
                running: false,
                pid: None,
                start_time: None,
                command_line: None,
            })
        }
    }

    fn list_services(&self) -> Result<Vec<ServiceStatus>> {
        // This would require listing all containers with evectl prefix
        Ok(vec![])
    }

    fn service_exists(&self, service_name: &str) -> bool {
        self.container_exists(service_name)
    }
}

#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct ProcessManager {
    state_dir: PathBuf,
}

#[cfg(windows)]
impl ProcessManager {
    pub fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }

    fn state_file_path(&self, service_name: &str) -> PathBuf {
        self.state_dir.join(format!("{}.json", service_name))
    }

    fn save_service_state(&self, status: &ServiceStatus) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir)?;
        let state_file = self.state_file_path(&status.name);
        let json = serde_json::to_string_pretty(status)?;
        std::fs::write(state_file, json)?;
        Ok(())
    }

    fn load_service_state(&self, service_name: &str) -> Result<ServiceStatus> {
        let state_file = self.state_file_path(service_name);
        if !state_file.exists() {
            return Ok(ServiceStatus {
                name: service_name.to_string(),
                running: false,
                pid: None,
                start_time: None,
                command_line: None,
            });
        }

        let json = std::fs::read_to_string(state_file)?;
        let mut status: ServiceStatus = serde_json::from_str(&json)?;

        // Verify the process is still running
        if let Some(pid) = status.pid {
            status.running = self.is_process_running(pid);
            if !status.running {
                status.pid = None;
                status.start_time = None;
                status.command_line = None;
            }
        }

        Ok(status)
    }

    fn is_process_running(&self, pid: u32) -> bool {
        // Use tasklist to check if process is running
        if let Ok(output) = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout.contains(&pid.to_string());
        }

        false
    }
}

#[cfg(windows)]
impl ServiceControl for ProcessManager {
    fn start(&self, service: &ServiceDefinition) -> Result<()> {
        // Check if already running
        if self.is_running(&service.name) {
            return Ok(());
        }

        let mut command = std::process::Command::new(&service.executable_path);
        command.args(&service.args);

        if let Some(working_dir) = &service.working_dir {
            command.current_dir(working_dir);
        }

        for (key, value) in &service.env_vars {
            command.env(key, value);
        }

        // Log the command being executed
        info!("Starting service {} with command:", service.name);
        info!("  Executable: {:?}", service.executable_path);
        info!("  Arguments: {:?}", service.args);
        if let Some(wd) = &service.working_dir {
            info!("  Working directory: {:?}", wd);
        }
        if !service.env_vars.is_empty() {
            info!("  Environment variables: {:?}", service.env_vars);
        }

        // Redirect stdout/stderr to log file if specified
        if let Some(log_file) = &service.log_file {
            if let Some(parent) = log_file.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let log_file_handle = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_file)?;
            command.stdout(log_file_handle.try_clone()?);
            command.stderr(log_file_handle);
        }

        let child = command.spawn()?;
        let pid = child.id();

        // Save service state
        let status = ServiceStatus {
            name: service.name.clone(),
            running: true,
            pid: Some(pid),
            start_time: Some(std::time::SystemTime::now()),
            command_line: Some(format!("{:?}", service)),
        };

        self.save_service_state(&status)?;

        info!("Started {} with PID {}", service.name, pid);
        Ok(())
    }

    fn stop(&self, service_name: &str) -> Result<()> {
        let status = self.load_service_state(service_name)?;

        if let Some(pid) = status.pid {
            if self.is_process_running(pid) {
                // Use taskkill to terminate the process with /F for forceful termination
                let output = std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/T", "/F"]) // /T kills child processes, /F forces termination
                    .output()?;

                if !output.status.success() {
                    bail!(
                        "Failed to kill process {}: {}",
                        pid,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }

                info!("Stopped {} (PID {})", service_name, pid);
            }
        }

        // Clear service state
        let cleared_status = ServiceStatus {
            name: service_name.to_string(),
            running: false,
            pid: None,
            start_time: None,
            command_line: None,
        };

        self.save_service_state(&cleared_status)?;
        Ok(())
    }

    fn is_running(&self, service_name: &str) -> bool {
        if let Ok(status) = self.load_service_state(service_name) {
            status.running && status.pid.is_some()
        } else {
            false
        }
    }

    fn get_status(&self, service_name: &str) -> Result<ServiceStatus> {
        self.load_service_state(service_name)
    }

    fn list_services(&self) -> Result<Vec<ServiceStatus>> {
        let mut services = Vec::new();

        if let Ok(entries) = std::fs::read_dir(&self.state_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".json") {
                        let service_name = name.trim_end_matches(".json");
                        if let Ok(status) = self.load_service_state(service_name) {
                            services.push(status);
                        }
                    }
                }
            }
        }

        Ok(services)
    }

    fn service_exists(&self, service_name: &str) -> bool {
        // A service exists if we have a state file for it, regardless of running status
        self.state_file_path(service_name).exists()
    }
}

impl ServiceManager {
    pub fn container(manager: ContainerManager) -> Self {
        Self::Container(manager)
    }

    #[cfg(windows)]
    pub fn process(state_dir: PathBuf) -> Self {
        Self::Process(ProcessManager::new(state_dir))
    }
}

impl ServiceControl for ServiceManager {
    fn start(&self, service: &ServiceDefinition) -> Result<()> {
        match self {
            ServiceManager::Container(manager) => manager.start(service),
            #[cfg(windows)]
            ServiceManager::Process(manager) => manager.start(service),
        }
    }

    fn stop(&self, service_name: &str) -> Result<()> {
        match self {
            ServiceManager::Container(manager) => manager.stop(service_name, Some("SIGINT")),
            #[cfg(windows)]
            ServiceManager::Process(manager) => manager.stop(service_name),
        }
    }

    fn is_running(&self, service_name: &str) -> bool {
        match self {
            ServiceManager::Container(manager) => manager.is_running(service_name),
            #[cfg(windows)]
            ServiceManager::Process(manager) => manager.is_running(service_name),
        }
    }

    fn get_status(&self, service_name: &str) -> Result<ServiceStatus> {
        match self {
            ServiceManager::Container(manager) => manager.get_status(service_name),
            #[cfg(windows)]
            ServiceManager::Process(manager) => manager.get_status(service_name),
        }
    }

    fn list_services(&self) -> Result<Vec<ServiceStatus>> {
        match self {
            ServiceManager::Container(manager) => manager.list_services(),
            #[cfg(windows)]
            ServiceManager::Process(manager) => manager.list_services(),
        }
    }

    fn service_exists(&self, service_name: &str) -> bool {
        match self {
            ServiceManager::Container(manager) => manager.service_exists(service_name),
            #[cfg(windows)]
            ServiceManager::Process(manager) => manager.service_exists(service_name),
        }
    }
}
