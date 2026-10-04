// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Component installation and upgrades.

use super::evebox::Download as EveBoxDownload;
use super::evebox::{
    EVEBOX_CHANNEL_MARKER, EVEBOX_VERSION_MARKER, find_evebox_exe, replace_evebox_installation,
};
use super::menu::wizard;
use super::npcap::{install_or_upgrade_npcap, maybe_upgrade_npcap, npcap_upgrade_needed};
use super::paths::{Paths, load_evectl_config};
use super::stack::{
    capture_restart_plan, evebox_server_url, restart_managed_components, stop_stack,
};
use super::suricata::{
    install_or_upgrade_suricata, maybe_upgrade_suricata, suricata_upgrade_needed,
};
use super::update::UpdateOutcome;
use crate::config::EveBoxChannel;
use crate::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) const START_SHORTCUT_NAME: &str = "EveCtl Start.cmd";
pub(super) const EVEBOX_SHORTCUT_NAME: &str = "EveBox.url";

#[derive(Debug, Default, Clone, Copy)]
struct UpgradePlan {
    npcap: bool,
    suricata: bool,
    evebox: bool,
}

impl UpgradePlan {
    fn any(self) -> bool {
        self.npcap || self.suricata || self.evebox
    }
}

pub(super) fn download_file(url: &str, path: &Path, name: &str) -> Result<()> {
    use std::fs::File;
    use std::io::{Read, Write};

    info!("Downloading {} from {}", name, url);
    info!("Saving to {:?}", path);

    let mut response = crate::http::client_builder()
        .build()?
        .get(url)
        .send()
        .context(format!("Failed to download {}", name))?;

    if !response.status().is_success() {
        bail!("Failed to download {}: HTTP {}", name, response.status());
    }

    let total_size = response.content_length().unwrap_or(0);
    let mut file = File::create(path).context(format!("Failed to create file for {}", name))?;

    let pb = if total_size > 0 {
        let pb = ProgressBar::new(total_size);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
            .progress_chars("#>-"));
        pb
    } else {
        ProgressBar::new_spinner()
    };

    let mut downloaded = 0u64;
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = response.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        file.write_all(&buffer[..bytes_read])?;
        downloaded += bytes_read as u64;
        pb.set_position(downloaded);
    }

    pb.finish_with_message("Download complete");
    file.flush()?;
    drop(file);

    info!("Downloaded {} to {:?}", name, path);
    Ok(())
}

pub(super) fn launch_windows_installer(path: &Path, name: &str, elevated: bool) -> Result<()> {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::PCWSTR;

    let path_str = path.to_string_lossy();
    let path_wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

    let verb = if elevated { "runas" } else { "open" }
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    unsafe {
        let result = ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(path_wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );

        if result.0 as usize <= 32 {
            bail!(
                "Failed to launch {} installer. Error code: {:?}",
                name,
                result.0
            );
        }
    }

    info!("{} installer launched successfully", name);
    Ok(())
}

pub(super) fn wait_for_installer_completion() -> Result<()> {
    use std::io::{self, Write};

    info!("Please complete the installation in the opened window.");
    print!("Press Enter when the installation is complete to continue...");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(())
}

pub(super) fn desktop_dir() -> Result<PathBuf> {
    dirs::desktop_dir().ok_or_else(|| anyhow!("Could not find desktop directory"))
}

pub(super) fn add_shortcuts(paths: &Paths) -> Result<()> {
    let desktop_dir = desktop_dir()?;
    let evectl_exe =
        std::env::current_exe().context("Failed to locate current EveCtl executable")?;

    let start_shortcut = desktop_dir.join(START_SHORTCUT_NAME);
    let evebox_shortcut = desktop_dir.join(EVEBOX_SHORTCUT_NAME);

    // The shortcut runs the stack in the foreground so the console
    // window shows the logs and closing it stops the stack.
    let start_contents = format!(
        "@echo off\r\n\"{}\" start --debug\r\n",
        evectl_exe.display()
    );
    std::fs::write(&start_shortcut, start_contents).context(format!(
        "Failed to write desktop shortcut {}",
        start_shortcut.display()
    ))?;

    let evebox_url = evebox_server_url(&load_evectl_config(paths)?);
    let evebox_contents = format!("[InternetShortcut]\r\nURL={}\r\n", evebox_url);
    std::fs::write(&evebox_shortcut, evebox_contents).context(format!(
        "Failed to write desktop shortcut {}",
        evebox_shortcut.display()
    ))?;

    println!("Created desktop shortcuts:");
    println!("  Start:  {}", start_shortcut.display());
    println!("  EveBox: {}", evebox_shortcut.display());
    println!("  EveBox URL: {}", evebox_url);

    Ok(())
}

/// Install what the configuration calls for, running the setup
/// wizard first if nothing has been configured yet.
pub(super) fn install(paths: &Paths) -> Result<()> {
    let mut config = load_evectl_config(paths)?;
    install_with(paths, &mut config)
}

pub(super) fn install_with(paths: &Paths, config: &mut crate::config::Config) -> Result<()> {
    if !(config.suricata.enabled || config.evebox_server.enabled || config.evebox_agent.enabled) {
        return wizard(paths, config);
    }

    install_configured_components(paths, config)
}

/// Install the components required by the enabled services: Npcap and
/// Suricata only when Suricata is enabled, EveBox for a server or
/// agent.
pub(super) fn install_configured_components(
    paths: &Paths,
    config: &crate::config::Config,
) -> Result<()> {
    if config.suricata.enabled {
        install_or_upgrade_npcap(paths, false)?;
        install_or_upgrade_suricata(paths, false)?;
    }

    if config.evebox_server.enabled || config.evebox_agent.enabled {
        install_or_upgrade_evebox(paths, false, config.windows.evebox_channel)?;
    }

    Ok(())
}

/// Only the components required by the enabled services are
/// considered for upgrade; a server-only install for example must
/// not pull in Npcap or Suricata.
fn build_upgrade_plan(paths: &Paths, config: &crate::config::Config) -> Result<UpgradePlan> {
    let use_suricata = config.suricata.enabled;
    let use_evebox = config.evebox_server.enabled || config.evebox_agent.enabled;

    Ok(UpgradePlan {
        npcap: use_suricata && npcap_upgrade_needed()?,
        suricata: use_suricata && suricata_upgrade_needed(paths)?,
        // Always refresh the selected channel on an explicit update. This
        // covers same-version development revisions and intentional channel
        // switches (including development -> an older stable release).
        evebox: use_evebox,
    })
}

pub(super) fn upgrade_windows_components(paths: &Paths) -> Result<UpdateOutcome> {
    super::update::run(crate::selfupdate::self_update(), paths.root(), || {
        upgrade_components(paths)
    })
}

fn upgrade_components(paths: &Paths) -> Result<()> {
    let config = load_evectl_config(paths)?;
    let plan = build_upgrade_plan(paths, &config)?;
    if !plan.any() {
        info!("No component upgrades are available.");
        return Ok(());
    }

    let restart_plan = capture_restart_plan(paths)?;
    if restart_plan.any() {
        info!("Stopping managed Windows services before upgrade");
        stop_stack(paths)?;
    }

    let upgrade_result = (|| {
        if plan.npcap {
            maybe_upgrade_npcap(paths)?;
        }
        if plan.suricata {
            maybe_upgrade_suricata(paths)?;
        }
        if plan.evebox {
            install_or_upgrade_evebox(paths, true, config.windows.evebox_channel)?;
        }
        Ok(())
    })();

    if let Err(err) = upgrade_result {
        if restart_plan.any()
            && let Err(restart_err) = restart_managed_components(paths, &restart_plan)
        {
            return Err(anyhow!(
                "Upgrade failed: {}\nAdditionally failed to restart previously running services: {}",
                err,
                restart_err
            ));
        }
        return Err(err);
    }

    if restart_plan.any() {
        restart_managed_components(paths, &restart_plan)?;
    }

    Ok(())
}

fn install_or_upgrade_evebox(paths: &Paths, upgrade: bool, channel: EveBoxChannel) -> Result<()> {
    let root_dir = paths.evebox_dir();
    let install_dir = paths.evebox_install_dir();
    let data_dir = paths.evebox_data_dir();

    if !upgrade && find_evebox_exe(&install_dir)?.is_some() {
        info!(
            "EveBox is already installed. Run 'evectl update' to install the latest {channel} build."
        );
        return Ok(());
    }

    std::fs::create_dir_all(&root_dir).context("Failed to create EveBox root directory")?;
    std::fs::create_dir_all(&data_dir).context("Failed to create EveBox data directory")?;

    // Resolve the latest version of the selected channel, without caching.
    let download = EveBoxDownload::resolve(channel)?;
    let temp_dir = tempfile::tempdir()?;
    let zip_path = temp_dir.path().join(&download.archive_name);
    download_file(&download.url, &zip_path, &format!("EveBox {channel} build"))?;

    let version = install_evebox_archive(&zip_path, &install_dir, &download)?;
    info!(
        "EveBox {} ({}) installed successfully at {} (data preserved in {})",
        version,
        channel,
        install_dir.display(),
        data_dir.display()
    );
    Ok(())
}

/// Validate the downloaded build before touching the current installation.
fn install_evebox_archive(
    zip_path: &Path,
    install_dir: &Path,
    download: &EveBoxDownload,
) -> Result<String> {
    let root_dir = install_dir
        .parent()
        .context("Missing EveBox root directory")?;
    let staging = tempfile::tempdir_in(root_dir)?;
    let exe_path = extract_evebox_archive(zip_path, staging.path())?;
    let mut command = Command::new(&exe_path);
    command.arg("version");
    let version = crate::run_evebox_version_command(command)?
        .context("Could not determine the downloaded EveBox version")?;
    download.validate_version(&version)?;
    std::fs::write(staging.path().join(EVEBOX_VERSION_MARKER), &version)
        .context("Failed to write EveBox version marker")?;
    std::fs::write(
        staging.path().join(EVEBOX_CHANNEL_MARKER),
        download.channel.to_string(),
    )
    .context("Failed to write EveBox channel marker")?;

    replace_evebox_installation(staging.path(), install_dir)?;
    Ok(version)
}

fn extract_evebox_archive(zip_path: &Path, destination: &Path) -> Result<PathBuf> {
    info!("Extracting EveBox to {}", destination.display());
    let zip_file =
        std::fs::File::open(zip_path).context("Failed to open downloaded EveBox zip file")?;
    let mut archive =
        zip::ZipArchive::new(zip_file).context("Failed to read EveBox zip archive")?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file
            .enclosed_name()
            .context("Invalid path in EveBox zip archive")?;
        let outpath = destination.join(name);

        if file.is_dir() {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut outfile = std::fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    find_evebox_exe(destination)?
        .context("Downloaded EveBox zip archive does not contain evebox.exe")
}

#[cfg(test)]
mod tests {
    use super::super::evebox::{evebox_installed_channel, evebox_installed_version};
    use super::*;
    use std::io::Write;

    fn write_evebox_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let mut archive = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        for (name, contents) in entries {
            archive
                .start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            archive.write_all(contents).unwrap();
        }
        archive.finish().unwrap();
    }

    #[test]
    fn evebox_updates_refresh_both_channels_only_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().to_path_buf());
        for channel in [EveBoxChannel::Release, EveBoxChannel::Development] {
            for (server, agent) in [(false, false), (true, false), (false, true), (true, true)] {
                let mut config = crate::config::Config::default();
                config.evebox_server.enabled = server;
                config.evebox_agent.enabled = agent;
                config.windows.evebox_channel = channel;
                for _ in 0..2 {
                    let plan = build_upgrade_plan(&paths, &config).unwrap();
                    assert_eq!(plan.evebox, server || agent);
                    assert!(!plan.npcap);
                    assert!(!plan.suricata);
                }
            }
        }
    }

    #[test]
    fn evebox_archives_support_flat_and_versioned_layouts() {
        for binary in ["evebox.exe", "evebox-0.30.0-dev-windows-x64/evebox.exe"] {
            let dir = tempfile::tempdir().unwrap();
            let zip_path = dir.path().join("evebox.zip");
            let destination = dir.path().join("staging");
            write_evebox_zip(&zip_path, &[(binary, b"binary"), ("docs/README", b"docs")]);
            let exe = extract_evebox_archive(&zip_path, &destination).unwrap();
            assert_eq!(exe, destination.join(binary));
            assert_eq!(std::fs::read(exe).unwrap(), b"binary");
            assert_eq!(
                std::fs::read(destination.join("docs/README")).unwrap(),
                b"docs"
            );
        }
    }

    #[test]
    fn invalid_evebox_archives_preserve_existing_installation() {
        let dir = tempfile::tempdir().unwrap();
        let install_dir = dir.path().join("install");
        std::fs::create_dir(&install_dir).unwrap();
        std::fs::write(install_dir.join("evebox.exe"), b"old binary").unwrap();
        let zip_path = dir.path().join("evebox.zip");

        let download = EveBoxDownload::development();
        std::fs::write(&zip_path, b"not a zip").unwrap();
        assert!(install_evebox_archive(&zip_path, &install_dir, &download).is_err());
        for entries in [
            vec![("README", b"no binary".as_slice())],
            vec![("evebox.exe", b"not an executable".as_slice())],
            vec![("../outside.txt", b"invalid path".as_slice())],
        ] {
            write_evebox_zip(&zip_path, &entries);
            assert!(install_evebox_archive(&zip_path, &install_dir, &download).is_err());
            assert_eq!(
                std::fs::read(install_dir.join("evebox.exe")).unwrap(),
                b"old binary"
            );
        }
        assert!(!dir.path().join("outside.txt").exists());
    }

    #[test]
    #[ignore = "Downloads and runs official EveBox release/development builds in a temporary directory"]
    fn installs_and_switches_evebox_release_channels() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let install_dir = dir.path().join("install");
        let data_dir = dir.path().join("data");
        std::fs::create_dir(&data_dir).unwrap();
        std::fs::write(data_dir.join("events.sqlite"), b"keep").unwrap();

        // Exercise both directions, including an intentional downgrade.
        for channel in [
            EveBoxChannel::Release,
            EveBoxChannel::Development,
            EveBoxChannel::Release,
        ] {
            let download = EveBoxDownload::resolve(channel).unwrap();
            let zip_path = dir.path().join(&download.archive_name);
            download_file(&download.url, &zip_path, "EveBox channel smoke test").unwrap();
            let version = install_evebox_archive(&zip_path, &install_dir, &download).unwrap();
            println!("Installed EveBox {version} ({channel})");
            assert_eq!(
                evebox_installed_version(&install_dir).unwrap().as_deref(),
                Some(version.as_str())
            );
            assert_eq!(
                evebox_installed_channel(&install_dir).unwrap(),
                Some(channel)
            );
            std::fs::write(install_dir.join("obsolete"), b"old").unwrap();
            // Refreshing an identical build must not be skipped either.
            assert_eq!(
                install_evebox_archive(&zip_path, &install_dir, &download).unwrap(),
                version
            );
            assert!(!install_dir.join("obsolete").exists());
            assert_eq!(
                std::fs::read(data_dir.join("events.sqlite")).unwrap(),
                b"keep"
            );
        }
    }
}
