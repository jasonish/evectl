// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Locations of the EveCtl data, Suricata, and EveBox files on Windows.

use crate::prelude::*;
use std::path::{Path, PathBuf};

pub(super) fn get_evectl_data_dir() -> Result<PathBuf> {
    Ok(dirs::data_local_dir()
        .ok_or_else(|| anyhow!("Could not find local data directory"))?
        .join("evectl"))
}

pub(super) fn get_evectl_config_path() -> Result<PathBuf> {
    Ok(get_evectl_data_dir()?.join("evectl.toml"))
}

pub(super) fn get_desktop_dir() -> Result<PathBuf> {
    dirs::desktop_dir().ok_or_else(|| anyhow!("Could not find desktop directory"))
}

// Config::from_windows_file is only compiled on Windows.
#[cfg(windows)]
pub(super) fn load_evectl_config() -> Result<crate::config::Config> {
    let config_path = get_evectl_config_path()?;
    if config_path.exists() {
        crate::config::Config::from_windows_file(&config_path)
    } else {
        Ok(crate::config::Config::default_with_filename(&config_path))
    }
}

pub(super) fn get_suricata_data_dir() -> Result<PathBuf> {
    Ok(get_evectl_data_dir()?.join("suricata"))
}

pub(super) fn get_suricata_run_dir() -> Result<PathBuf> {
    Ok(get_suricata_data_dir()?.join("run"))
}

pub(super) fn get_suricata_log_dir() -> Result<PathBuf> {
    Ok(get_suricata_data_dir()?.join("log"))
}

pub(super) fn get_suricata_pcap_dir() -> Result<PathBuf> {
    Ok(get_suricata_log_dir()?.join("pcap"))
}

pub(super) fn get_suricata_filestore_dir() -> Result<PathBuf> {
    Ok(get_suricata_log_dir()?.join("filestore"))
}

pub(super) fn get_suricata_install_dir() -> Result<PathBuf> {
    Ok(get_suricata_data_dir()?.join("install"))
}

pub(super) fn get_suricata_exe_path() -> Result<PathBuf> {
    Ok(get_suricata_install_dir()?.join("suricata.exe"))
}

pub(super) fn get_suricata_pid_path() -> Result<PathBuf> {
    Ok(get_suricata_run_dir()?.join("suricata.pid"))
}

pub(super) fn get_suricata_runtime_path() -> Result<PathBuf> {
    Ok(get_suricata_run_dir()?.join("suricata.runtime.json"))
}

fn get_suricata_stdout_log_path() -> Result<PathBuf> {
    Ok(get_suricata_log_dir()?.join("suricata-stdout.log"))
}

fn get_suricata_stderr_log_path() -> Result<PathBuf> {
    Ok(get_suricata_log_dir()?.join("suricata-stderr.log"))
}

pub(super) fn get_suricata_eve_json_path() -> Result<PathBuf> {
    Ok(get_suricata_log_dir()?.join("eve.json"))
}

pub(super) fn get_suricata_threshold_config_path() -> Result<PathBuf> {
    Ok(get_suricata_run_dir()?.join("threshold.config"))
}

pub(super) fn get_evebox_root_dir() -> Result<PathBuf> {
    Ok(get_evectl_data_dir()?.join("evebox"))
}

pub(super) fn get_evebox_install_dir() -> Result<PathBuf> {
    Ok(get_evebox_root_dir()?.join("install"))
}

pub(super) fn get_evebox_data_dir() -> Result<PathBuf> {
    Ok(get_evebox_root_dir()?.join("data"))
}

pub(super) fn get_evebox_pid_path() -> Result<PathBuf> {
    Ok(get_evebox_root_dir()?.join("evebox.pid"))
}

pub(super) fn get_evebox_runtime_path() -> Result<PathBuf> {
    Ok(get_evebox_root_dir()?.join("evebox.runtime.json"))
}

pub(super) fn get_evebox_agent_dir() -> Result<PathBuf> {
    Ok(get_evebox_root_dir()?.join("agent"))
}

pub(super) fn get_evebox_agent_data_dir() -> Result<PathBuf> {
    Ok(get_evebox_agent_dir()?.join("data"))
}

pub(super) fn get_evebox_agent_pid_path() -> Result<PathBuf> {
    Ok(get_evebox_agent_dir()?.join("evebox-agent.pid"))
}

pub(super) fn get_evebox_agent_runtime_path() -> Result<PathBuf> {
    Ok(get_evebox_agent_dir()?.join("evebox-agent.runtime.json"))
}

pub(super) fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).context(format!("Failed to create directory {}", path.display()))
}
