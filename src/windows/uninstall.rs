// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Removal of the managed services, data, configuration, and EveCtl itself.

use super::evebox::{find_evebox_exe, uninstall_evebox};
use super::install::{EVEBOX_SHORTCUT_NAME, START_SHORTCUT_NAME};
use super::npcap::uninstall_npcap;
use super::paths::{
    get_desktop_dir, get_evebox_agent_dir, get_evebox_data_dir, get_evebox_install_dir,
    get_evebox_pid_path, get_evebox_runtime_path, get_evectl_config_path, get_evectl_data_dir,
    get_suricata_data_dir, get_suricata_exe_path, get_suricata_install_dir, get_suricata_log_dir,
    get_suricata_run_dir,
};
use super::runtime::{
    ROLE_EVEBOX, ROLE_EVEBOX_AGENT, ROLE_HOUSEKEEPER, ROLE_SURICATA, log_processes_in_dir,
    managed_process_is_running, stop_named_processes_in_dir,
};
use super::stack::stop_stack;
use super::suricata::uninstall_suricata;
use crate::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;

fn log_uninstall_process_diagnostics() -> Result<()> {
    let suricata_install_dir = get_suricata_install_dir()?;
    let suricata_exe_path = get_suricata_exe_path()?;
    log_processes_in_dir("suricata", &suricata_install_dir, Some(&suricata_exe_path))?;

    let evebox_install_dir = get_evebox_install_dir()?;
    let evebox_exe_path = find_evebox_exe(&evebox_install_dir)?;
    log_processes_in_dir("evebox", &evebox_install_dir, evebox_exe_path.as_deref())?;

    Ok(())
}

fn ensure_managed_services_stopped_for_uninstall() -> Result<()> {
    let any_running = managed_process_is_running(ROLE_SURICATA)?
        || managed_process_is_running(ROLE_EVEBOX)?
        || managed_process_is_running(ROLE_EVEBOX_AGENT)?
        || managed_process_is_running(ROLE_HOUSEKEEPER)?;

    if !any_running {
        return Ok(());
    }

    info!("Stopping managed Windows services before uninstall");
    stop_stack().context("Failed to stop managed Windows stack before uninstall")?;

    if managed_process_is_running(ROLE_SURICATA)?
        || managed_process_is_running(ROLE_EVEBOX)?
        || managed_process_is_running(ROLE_EVEBOX_AGENT)?
        || managed_process_is_running(ROLE_HOUSEKEEPER)?
    {
        bail!("Managed Windows services are still running after stop was requested");
    }

    Ok(())
}

fn ensure_unmanaged_evectl_processes_stopped_for_uninstall() -> Result<()> {
    let suricata_install_dir = get_suricata_install_dir()?;
    let suricata_exe_path = get_suricata_exe_path()?;
    stop_named_processes_in_dir("suricata", &suricata_install_dir, Some(&suricata_exe_path))?;

    let evebox_install_dir = get_evebox_install_dir()?;
    let evebox_exe_path = find_evebox_exe(&evebox_install_dir)?;
    stop_named_processes_in_dir("evebox", &evebox_install_dir, evebox_exe_path.as_deref())?;

    Ok(())
}

/// The directories and files holding runtime data: event data,
/// logs, pid files, and the installer download cache.
fn data_paths_for_uninstall() -> Result<Vec<PathBuf>> {
    Ok(vec![
        get_suricata_log_dir()?,
        get_suricata_run_dir()?,
        get_evebox_data_dir()?,
        get_evebox_agent_dir()?,
        get_evebox_pid_path()?,
        get_evebox_runtime_path()?,
        get_evectl_data_dir()?.join("downloads"),
        get_evectl_data_dir()?.join(super::update::RESTART_MARKER),
    ])
}

/// The configuration paths. Suricata rules and ruleset selections
/// count as configuration, matching the Linux layout where rules
/// live under the config directory.
fn config_paths_for_uninstall() -> Result<Vec<PathBuf>> {
    Ok(vec![
        get_evectl_config_path()?,
        get_suricata_data_dir()?.join("lib"),
    ])
}

fn existing_shortcuts() -> Result<Vec<PathBuf>> {
    let desktop_dir = get_desktop_dir()?;
    Ok([START_SHORTCUT_NAME, EVEBOX_SHORTCUT_NAME]
        .iter()
        .map(|name| desktop_dir.join(name))
        .filter(|path| path.exists())
        .collect())
}

/// A running executable can't delete itself on Windows, so hand
/// the deletion to a detached helper that retries until this
/// process has exited.
fn schedule_self_delete(exe: &Path) -> Result<()> {
    // A staged self-update isn't locked and can go right away.
    if let Some(file_name) = exe.file_name().and_then(|name| name.to_str()) {
        let staged = exe.with_file_name(format!("{}.new", file_name));
        if staged.exists() {
            let _ = std::fs::remove_file(&staged);
        }
    }

    let script = r#"
$target = $env:EVECTL_SELF_DELETE_TARGET

for ($i = 0; $i -lt 120; $i++) {
try {
    Remove-Item -LiteralPath $target -Force
    exit 0
} catch {
    Start-Sleep -Milliseconds 250
}
}

exit 1
"#;

    Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", script])
        .env("EVECTL_SELF_DELETE_TARGET", exe)
        .spawn()
        .context("Failed to launch self-delete helper")?;

    info!("{} will be removed after EveCtl exits", exe.display());
    Ok(())
}

/// Remove a file or directory, collecting any failure.
fn remove_path(path: &Path, errors: &mut Vec<String>) {
    // The component uninstalls may have already removed it.
    if !path.exists() {
        return;
    }
    info!("Removing {}", path.display());
    let result = if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    if let Err(err) = result {
        errors.push(format!("Failed to remove {}: {}", path.display(), err));
    }
}

/// Uninstall EveBox, Suricata, and evectl-managed Npcap,
/// collecting failures. Returns true if all succeeded.
fn uninstall_components(errors: &mut Vec<String>) -> bool {
    // Informational only, so not fatal.
    if let Err(err) = log_uninstall_process_diagnostics() {
        warn!("Failed to log process diagnostics: {}", err);
    }

    let before = errors.len();

    if let Err(err) = uninstall_evebox() {
        errors.push(format!("EveBox uninstall failed: {}", err));
    }

    if let Err(err) = uninstall_suricata() {
        errors.push(format!("Suricata uninstall failed: {}", err));
    }

    if let Err(err) = uninstall_npcap() {
        errors.push(format!("Npcap uninstall failed: {}", err));
    }

    errors.len() == before
}

/// Uninstall the components, then remove the whole EveCtl
/// directory. The directory holds the Npcap ownership marker and
/// the version markers a retry needs, so it's left in place if any
/// component uninstall failed.
fn uninstall_components_and_directory(evectl_dir: &Path, errors: &mut Vec<String>) {
    if uninstall_components(errors) {
        remove_path(evectl_dir, errors);
    } else {
        warn!(
            "Leaving {} in place so the uninstall can be retried",
            evectl_dir.display()
        );
    }
}

pub(super) fn uninstall(remove_config: bool, all: bool, yes: bool) -> Result<()> {
    let remove_config = remove_config || all;

    if !yes && !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        bail!("No terminal available for confirmation, pass --yes to run without prompting");
    }

    let evectl_dir = get_evectl_data_dir()?;
    let mut paths: Vec<PathBuf> = vec![];
    if !all {
        paths.extend(data_paths_for_uninstall()?);
        if remove_config {
            paths.extend(config_paths_for_uninstall()?);
        }
    }
    paths.retain(|path| path.exists());

    let shortcuts = if all { existing_shortcuts()? } else { vec![] };
    let mut binary = if all {
        crate::selfupdate::removable_exe()
    } else {
        None
    };

    println!("The following will be removed:");
    if all {
        println!("  EveBox, Suricata, and evectl-managed Npcap installations");
        println!("  {}", evectl_dir.display());
    }
    for path in paths.iter().chain(shortcuts.iter()) {
        println!("  {}", path.display());
    }
    if let Some(binary) = &binary {
        println!("  {}", binary.display());
    }

    if !yes && !crate::prompt::confirm_destructive("Proceed with uninstall?") {
        bail!("Uninstall canceled");
    }

    ensure_managed_services_stopped_for_uninstall()?;
    ensure_unmanaged_evectl_processes_stopped_for_uninstall()?;

    let mut errors: Vec<String> = vec![];

    if all {
        uninstall_components_and_directory(&evectl_dir, &mut errors);
    }

    for path in paths.iter().chain(shortcuts.iter()) {
        remove_path(path, &mut errors);
    }

    // When interactive, keep prompting through the layers the
    // flags didn't already cover: configuration, the EveCtl
    // directory, the desktop shortcuts, and finally the binary.
    if !yes && !all {
        let mut config_removed = true;

        if !remove_config {
            let rules_dir = get_suricata_data_dir()?.join("lib");
            if rules_dir.exists() {
                if crate::prompt::confirm_destructive(&format!(
                    "Also remove the Suricata rules directory {}?",
                    rules_dir.display()
                )) {
                    remove_path(&rules_dir, &mut errors);
                } else {
                    config_removed = false;
                }
            }

            let config_path = get_evectl_config_path()?;
            if config_path.exists() {
                if crate::prompt::confirm_destructive(&format!(
                    "Also remove the configuration file {}?",
                    config_path.display()
                )) {
                    remove_path(&config_path, &mut errors);
                } else {
                    config_removed = false;
                }
            }
        }

        // Only offer to remove the EveCtl directory once nothing
        // the user chose to keep remains in it. It holds the
        // installed components, which are uninstalled first.
        if config_removed
            && evectl_dir.exists()
            && crate::prompt::confirm_destructive(&format!(
                "Also remove the EveCtl directory {} including the EveBox, Suricata, and evectl-managed Npcap installations?",
                evectl_dir.display()
            ))
        {
            uninstall_components_and_directory(&evectl_dir, &mut errors);
        }

        let shortcuts = existing_shortcuts()?;
        if !shortcuts.is_empty()
            && crate::prompt::confirm_destructive("Also remove the desktop shortcuts?")
        {
            for path in &shortcuts {
                remove_path(path, &mut errors);
            }
        }

        if let Some(exe) = crate::selfupdate::removable_exe()
            && crate::prompt::confirm_destructive(&format!(
                "Also remove the EveCtl binary {}?",
                exe.display()
            ))
        {
            binary = Some(exe);
        }
    }

    if let Some(binary) = &binary
        && let Err(err) = schedule_self_delete(binary)
    {
        errors.push(format!(
            "Failed to schedule removal of {}: {}",
            binary.display(),
            err
        ));
    }

    if errors.is_empty() {
        info!("Uninstall complete");
        Ok(())
    } else {
        bail!(
            "Uninstall completed with errors:\n- {}",
            errors.join("\n- ")
        )
    }
}

pub(super) fn uninstall_windows_components() -> Result<()> {
    ensure_managed_services_stopped_for_uninstall()?;
    ensure_unmanaged_evectl_processes_stopped_for_uninstall()?;

    let mut errors: Vec<String> = vec![];
    if uninstall_components(&mut errors) {
        info!("Windows component uninstall completed");
        Ok(())
    } else {
        bail!(
            "Windows component uninstall completed with errors:\n- {}",
            errors.join("\n- ")
        )
    }
}
