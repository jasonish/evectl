// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Locations of the EveCtl data, Suricata, and EveBox files on Windows.
//!
//! Everything lives under one root, `%LOCALAPPDATA%\evectl` by default,
//! so finding that root is the only step that can fail.

use crate::prelude::*;
use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = "evectl.toml";
const DOWNLOADS_DIR: &str = "downloads";

#[derive(Debug, Clone)]
pub(super) struct Paths {
    root: PathBuf,
}

impl Paths {
    /// The paths under the local application data directory.
    pub(super) fn discover() -> Result<Self> {
        let data_local_dir =
            dirs::data_local_dir().ok_or_else(|| anyhow!("Could not find local data directory"))?;
        Ok(Self::new(data_local_dir.join("evectl")))
    }

    pub(super) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The EveCtl data directory holding everything else.
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn config_file(&self) -> PathBuf {
        self.root.join(CONFIG_FILE)
    }

    /// Cache of downloaded installers.
    pub(super) fn downloads_dir(&self) -> PathBuf {
        self.root.join(DOWNLOADS_DIR)
    }

    pub(super) fn suricata_dir(&self) -> PathBuf {
        self.root.join("suricata")
    }

    /// Rules and rule update state. Counts as configuration, like the
    /// rules under the config directory on Linux.
    pub(super) fn suricata_lib_dir(&self) -> PathBuf {
        self.suricata_dir().join("lib")
    }

    pub(super) fn suricata_rules_dir(&self) -> PathBuf {
        self.suricata_lib_dir().join("rules")
    }

    pub(super) fn suricata_update_dir(&self) -> PathBuf {
        self.suricata_lib_dir().join("update")
    }

    /// PID files, runtime metadata, and generated configuration.
    pub(super) fn suricata_run_dir(&self) -> PathBuf {
        self.suricata_dir().join("run")
    }

    pub(super) fn suricata_log_dir(&self) -> PathBuf {
        self.suricata_dir().join("log")
    }

    pub(super) fn suricata_pcap_dir(&self) -> PathBuf {
        self.suricata_log_dir().join("pcap")
    }

    pub(super) fn suricata_filestore_dir(&self) -> PathBuf {
        self.suricata_log_dir().join("filestore")
    }

    pub(super) fn suricata_eve_json(&self) -> PathBuf {
        self.suricata_log_dir().join("eve.json")
    }

    pub(super) fn suricata_threshold_config(&self) -> PathBuf {
        self.suricata_run_dir().join("threshold.config")
    }

    /// The evectl-managed Suricata installation.
    pub(super) fn suricata_install_dir(&self) -> PathBuf {
        self.suricata_dir().join("install")
    }

    pub(super) fn suricata_exe(&self) -> PathBuf {
        self.suricata_install_dir().join("suricata.exe")
    }

    /// The housekeeper runs from its own copy of EveCtl so a staged
    /// self-update can replace the launcher.
    pub(super) fn housekeeper_exe(&self) -> PathBuf {
        self.suricata_run_dir().join("housekeeper.exe")
    }

    pub(super) fn housekeeper_stdout_log(&self) -> PathBuf {
        self.suricata_log_dir().join("housekeeper-stdout.log")
    }

    pub(super) fn housekeeper_stderr_log(&self) -> PathBuf {
        self.suricata_log_dir().join("housekeeper-stderr.log")
    }

    pub(super) fn evebox_dir(&self) -> PathBuf {
        self.root.join("evebox")
    }

    pub(super) fn evebox_install_dir(&self) -> PathBuf {
        self.evebox_dir().join("install")
    }

    pub(super) fn evebox_data_dir(&self) -> PathBuf {
        self.evebox_dir().join("data")
    }

    pub(super) fn evebox_agent_dir(&self) -> PathBuf {
        self.evebox_dir().join("agent")
    }

    pub(super) fn evebox_agent_data_dir(&self) -> PathBuf {
        self.evebox_agent_dir().join("data")
    }
}

// Config::from_windows_file is only compiled on Windows.
#[cfg(windows)]
pub(super) fn load_evectl_config(paths: &Paths) -> Result<Config> {
    let config_path = paths.config_file();
    if config_path.exists() {
        Config::from_windows_file(&config_path)
    } else {
        Ok(Config::default_with_filename(&config_path))
    }
}

pub(super) fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).context(format!("Failed to create directory {}", path.display()))
}
