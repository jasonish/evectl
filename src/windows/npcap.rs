// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Npcap installation, upgrade, and removal.

use super::install::{download_file, launch_windows_installer, wait_for_installer_completion};
use super::paths::{ensure_dir, get_evectl_data_dir};
use super::version::compare_versions;
use crate::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;

const NPCAP_VERSION: &str = "1.88";
const NPCAP_INSTALLED_MARKER: &str = ".evectl-npcap-installed";

pub(super) fn download_npcap() -> Result<()> {
    install_or_upgrade_npcap(false)
}

fn install_or_upgrade_npcap(upgrade: bool) -> Result<()> {
    let installed = is_npcap_installed();
    let should_mark_as_managed = !installed;

    if installed && !upgrade {
        info!("Npcap is already installed on this system.");
        return Ok(());
    }

    if upgrade {
        if installed {
            info!("Upgrading Npcap to version {}...", NPCAP_VERSION);
        } else {
            info!(
                "Npcap was not detected. Installing version {} instead...",
                NPCAP_VERSION
            );
        }
    }

    let url = format!("https://npcap.com/dist/npcap-{}.exe", NPCAP_VERSION);
    let temp_dir = tempfile::tempdir()?;
    let exe_path = temp_dir.path().join(format!("npcap-{}.exe", NPCAP_VERSION));

    download_file(&url, &exe_path, "Npcap")?;

    info!("Launching Npcap installer...");

    launch_windows_installer(&exe_path, "Npcap", false)?;
    wait_for_installer_completion()?;

    if should_mark_as_managed {
        if is_npcap_installed() {
            mark_npcap_managed_installed()?;
            info!("Recorded Npcap as installed by evectl.");
        } else {
            warn!(
                "Npcap installer completed, but Npcap was not detected afterwards. Not recording evectl ownership."
            );
        }
    }

    Ok(())
}

fn get_npcap_installed_marker_path() -> Result<PathBuf> {
    Ok(get_evectl_data_dir()?.join(NPCAP_INSTALLED_MARKER))
}

fn is_npcap_managed_installed() -> Result<bool> {
    Ok(get_npcap_installed_marker_path()?.exists())
}

fn mark_npcap_managed_installed() -> Result<()> {
    let data_dir = get_evectl_data_dir()?;
    ensure_dir(&data_dir)?;

    let marker_path = get_npcap_installed_marker_path()?;
    std::fs::write(
        &marker_path,
        format!("version={NPCAP_VERSION}\ninstalled_by=evectl\n"),
    )
    .context(format!("Failed to write {}", marker_path.display()))
}

fn clear_npcap_managed_installed_marker() -> Result<()> {
    let marker_path = get_npcap_installed_marker_path()?;
    if marker_path.exists() {
        std::fs::remove_file(&marker_path)
            .context(format!("Failed to remove {}", marker_path.display()))?;
    }

    Ok(())
}

fn is_npcap_installed() -> bool {
    let service_exists = ["npcap", "npf"].iter().any(|service| {
        Command::new("sc")
            .args(["query", service])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    });

    if !service_exists {
        return false;
    }

    [
        r"C:\Windows\System32\drivers\npcap.sys",
        r"C:\Windows\System32\drivers\npf.sys",
    ]
    .iter()
    .any(|path| Path::new(path).exists())
}

pub(super) fn npcap_upgrade_needed() -> Result<bool> {
    if !is_npcap_installed() {
        return Ok(true);
    }

    let Some(installed_version) = get_npcap_installed_version()? else {
        return Ok(false);
    };

    let Some(comparison) = compare_versions(&installed_version, NPCAP_VERSION) else {
        return Ok(false);
    };

    Ok(comparison == std::cmp::Ordering::Less)
}

pub(super) fn maybe_upgrade_npcap() -> Result<()> {
    if !is_npcap_installed() {
        info!(
            "Npcap was not detected. Installing version {} before Suricata upgrade...",
            NPCAP_VERSION
        );
        return install_or_upgrade_npcap(true);
    }

    let installed_version = match get_npcap_installed_version()? {
        Some(version) => version,
        None => {
            info!(
                "Npcap is installed, but the installed version could not be determined. Skipping automatic Npcap upgrade."
            );
            return Ok(());
        }
    };

    let comparison = match compare_versions(&installed_version, NPCAP_VERSION) {
        Some(comparison) => comparison,
        None => {
            info!(
                "Npcap version comparison failed (installed: {}, bundled: {}). Skipping automatic Npcap upgrade.",
                installed_version, NPCAP_VERSION
            );
            return Ok(());
        }
    };

    match comparison {
        std::cmp::Ordering::Less => {
            info!(
                "Npcap {} is older than bundled {}. Upgrading Npcap...",
                installed_version, NPCAP_VERSION
            );
            install_or_upgrade_npcap(true)
        }
        std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {
            info!(
                "Npcap {} meets or exceeds bundled {}. Skipping Npcap upgrade.",
                installed_version, NPCAP_VERSION
            );
            Ok(())
        }
    }
}

fn get_npcap_installed_version() -> Result<Option<String>> {
    let script = r#"
$entry = @(
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
) | Where-Object { $_.DisplayName -like 'Npcap*' } | Select-Object -First 1

if ($entry -and $entry.DisplayVersion) {
Write-Output $entry.DisplayVersion
}
"#;

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .context("Failed to query installed Npcap version")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            "Failed to determine installed Npcap version: {}",
            stderr.trim()
        );
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = stdout.trim();
    if version.is_empty() {
        Ok(None)
    } else {
        Ok(Some(version.to_string()))
    }
}

pub(super) fn uninstall_npcap() -> Result<()> {
    if !is_npcap_managed_installed()? {
        if is_npcap_installed() {
            info!(
                "Npcap is installed, but it was not installed by evectl. Skipping Npcap uninstall."
            );
        } else {
            info!("Npcap was not installed by evectl. Skipping Npcap uninstall.");
        }
        return Ok(());
    }

    if !is_npcap_installed() {
        info!(
            "Npcap was marked as installed by evectl, but no Npcap installation was detected. Clearing marker."
        );
        clear_npcap_managed_installed_marker()?;
        return Ok(());
    }

    info!("Uninstalling evectl-managed Npcap installation...");

    let script = r#"
$ErrorActionPreference = 'Stop'
$entry = @(
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
) | Where-Object { $_.DisplayName -like 'Npcap*' } | Select-Object -First 1

if (-not $entry) {
Write-Output 'NOT_FOUND'
exit 0
}

$productCode = $entry.PSChildName
if ($productCode -match '^\{[0-9A-Fa-f\-]+\}$') {
$process = Start-Process -FilePath 'msiexec.exe' -ArgumentList '/x', $productCode, '/qn', '/norestart' -Verb RunAs -Wait -PassThru
exit $process.ExitCode
}

$command = $entry.QuietUninstallString
if ([string]::IsNullOrWhiteSpace($command)) {
$command = $entry.UninstallString
}
if ([string]::IsNullOrWhiteSpace($command)) {
throw 'Unable to determine Npcap uninstall command'
}

if ($command -match '(?i)msiexec(\.exe)?') {
$command = $command -replace '(?i)\s/I(?=\s|\{)', ' /X'
if ($command -notmatch '(?i)\s/(qn|quiet|passive)\b') {
    $command = "$command /qn"
}
if ($command -notmatch '(?i)\s/norestart\b') {
    $command = "$command /norestart"
}
}

$process = Start-Process -FilePath 'cmd.exe' -ArgumentList '/C', $command -Verb RunAs -Wait -PassThru
exit $process.ExitCode
"#;

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .context("Failed to execute Npcap uninstall command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Npcap uninstall failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("NOT_FOUND") {
        info!("Npcap uninstall entry not found. Clearing evectl ownership marker.");
        clear_npcap_managed_installed_marker()?;
        return Ok(());
    }

    clear_npcap_managed_installed_marker()?;
    info!("Npcap uninstall completed");
    Ok(())
}
