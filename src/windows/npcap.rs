// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Npcap installation, upgrade, and removal.

use super::component::Component;
use super::install::{download_file, launch_windows_installer, wait_for_installer_completion};
use super::paths::{Paths, ensure_dir};
use super::runtime::powershell;
use crate::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;

const NPCAP_VERSION: &str = "1.88";
const NPCAP_INSTALLED_MARKER: &str = ".evectl-npcap-installed";

pub(super) fn install_or_upgrade_npcap(paths: &Paths, upgrade: bool) -> Result<()> {
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
            mark_npcap_managed_installed(paths)?;
            info!("Recorded Npcap as installed by evectl.");
        } else {
            warn!(
                "Npcap installer completed, but Npcap was not detected afterwards. Not recording evectl ownership."
            );
        }
    }

    Ok(())
}

fn installed_marker_path(paths: &Paths) -> PathBuf {
    paths.root().join(NPCAP_INSTALLED_MARKER)
}

fn is_npcap_managed_installed(paths: &Paths) -> bool {
    installed_marker_path(paths).exists()
}

fn mark_npcap_managed_installed(paths: &Paths) -> Result<()> {
    ensure_dir(paths.root())?;

    let marker_path = installed_marker_path(paths);
    std::fs::write(
        &marker_path,
        format!("version={NPCAP_VERSION}\ninstalled_by=evectl\n"),
    )
    .context(format!("Failed to write {}", marker_path.display()))
}

fn clear_npcap_managed_installed_marker(paths: &Paths) -> Result<()> {
    let marker_path = installed_marker_path(paths);
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

pub(super) struct Npcap;

impl Component for Npcap {
    fn name(&self) -> &'static str {
        "Npcap"
    }

    fn bundled_version(&self) -> &'static str {
        NPCAP_VERSION
    }

    fn installed(&self, _paths: &Paths) -> bool {
        is_npcap_installed()
    }

    fn installed_version(&self, _paths: &Paths) -> Result<Option<String>> {
        npcap_installed_version()
    }

    /// Npcap may have been installed by someone else; leave it alone
    /// unless it is known to be older.
    fn reinstall_unknown_version(&self) -> bool {
        false
    }

    fn install(&self, paths: &Paths, upgrade: bool) -> Result<()> {
        install_or_upgrade_npcap(paths, upgrade)
    }
}

fn npcap_installed_version() -> Result<Option<String>> {
    let script = r#"
$entry = @(
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
) | Where-Object { $_.DisplayName -like 'Npcap*' } | Select-Object -First 1

if ($entry -and $entry.DisplayVersion) {
Write-Output $entry.DisplayVersion
}
"#;

    let stdout = match powershell(script, "Failed to determine installed Npcap version") {
        Ok(stdout) => stdout,
        Err(err) => {
            warn!("{}", err);
            return Ok(None);
        }
    };
    let version = stdout.trim();
    if version.is_empty() {
        Ok(None)
    } else {
        Ok(Some(version.to_string()))
    }
}

pub(super) fn uninstall_npcap(paths: &Paths) -> Result<()> {
    if !is_npcap_managed_installed(paths) {
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
        clear_npcap_managed_installed_marker(paths)?;
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

    let stdout = powershell(script, "Npcap uninstall failed")?;
    if stdout.contains("NOT_FOUND") {
        info!("Npcap uninstall entry not found. Clearing evectl ownership marker.");
        clear_npcap_managed_installed_marker(paths)?;
        return Ok(());
    }

    clear_npcap_managed_installed_marker(paths)?;
    info!("Npcap uninstall completed");
    Ok(())
}
