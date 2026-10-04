// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use super::paths::{Paths, ensure_dir};
use crate::config::EveBoxChannel;
use crate::prelude::*;
use anyhow::ensure;
use semver::Version;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const DEVELOPMENT_URL: &str = "https://evebox.org/files/development/evebox-devel-windows-x64.zip";
const RELEASE_MANIFEST_URL: &str = "https://evebox.org/files/release/latest.json";

#[derive(Debug)]
pub(super) struct Download {
    pub channel: EveBoxChannel,
    pub url: String,
    pub archive_name: String,
    release_version: Option<Version>,
}

impl Download {
    pub(super) fn development() -> Self {
        Self {
            channel: EveBoxChannel::Development,
            url: DEVELOPMENT_URL.into(),
            archive_name: "evebox-devel-windows-x64.zip".into(),
            release_version: None,
        }
    }

    pub(super) fn resolve(channel: EveBoxChannel) -> Result<Self> {
        match channel {
            EveBoxChannel::Development => Ok(Self::development()),
            EveBoxChannel::Release => {
                info!("Resolving latest EveBox release from {RELEASE_MANIFEST_URL}");
                let manifest = crate::http::client_builder()
                    .timeout(Duration::from_secs(30))
                    .build()?
                    .get(RELEASE_MANIFEST_URL)
                    .send()
                    .context("Failed to fetch EveBox release manifest")?
                    .error_for_status()
                    .context("Failed to fetch EveBox release manifest")?
                    .text()?;
                Self::from_release_manifest(&manifest)
            }
        }
    }

    fn from_release_manifest(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct Manifest {
            version: String,
        }
        let manifest: Manifest =
            serde_json::from_str(text).context("Invalid EveBox release manifest")?;
        let version = Version::parse(&manifest.version)
            .context("Invalid version in EveBox release manifest")?;
        ensure!(
            version.pre.is_empty()
                && version.build.is_empty()
                && version.to_string() == manifest.version,
            "Expected a stable version in EveBox release manifest"
        );
        let archive_name = format!("evebox-{version}-windows-x64.zip");
        Ok(Self {
            channel: EveBoxChannel::Release,
            url: format!("https://evebox.org/files/release/{version}/{archive_name}"),
            archive_name,
            release_version: Some(version),
        })
    }

    /// Check the executable's identity before committing a release install.
    /// Main-branch builds may share a semantic version but differ by revision.
    pub(super) fn validate_version(&self, reported: &str) -> Result<()> {
        let version = reported.split_whitespace().next().unwrap_or_default();
        let version = Version::parse(version).context("Invalid downloaded EveBox version")?;
        if let Some(expected) = &self.release_version {
            ensure!(
                &version == expected,
                "Downloaded EveBox version {version} does not match selected release {expected}"
            );
        }
        Ok(())
    }
}

pub(super) const EVEBOX_VERSION_MARKER: &str = ".evectl-evebox-version";
pub(super) const EVEBOX_CHANNEL_MARKER: &str = ".evectl-evebox-channel";

/// Replace the EveBox "admin" user, prompting for the new password.
/// Uses the server's data directory, where EveBox keeps its
/// configuration database.
pub(super) fn reset_evebox_admin_password(paths: &Paths) -> Result<()> {
    let evebox_exe = evebox_exe_path(paths)?;
    let data_dir = paths.evebox_data_dir();
    ensure_dir(&data_dir)?;

    // Removal fails if the user does not exist yet.
    let _ = Command::new(&evebox_exe)
        .arg("-D")
        .arg(&data_dir)
        .args(["config", "users", "rm", "admin"])
        .status();

    let status = Command::new(&evebox_exe)
        .arg("-D")
        .arg(&data_dir)
        .args(["config", "users", "add", "--username", "admin"])
        .status()
        .context("Failed to run EveBox")?;
    if !status.success() {
        bail!("EveBox exited with {status}");
    }
    Ok(())
}

pub(super) fn find_evebox_exe(dir: &Path) -> Result<Option<PathBuf>> {
    let direct_path = dir.join("evebox.exe");
    if direct_path.exists() {
        return Ok(Some(direct_path));
    }

    if !dir.exists() {
        return Ok(None);
    }

    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read EveBox directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        if let Some(exe_path) = find_evebox_exe(&path)? {
            return Ok(Some(exe_path));
        }
    }

    Ok(None)
}

pub(super) fn evebox_exe_path(paths: &Paths) -> Result<PathBuf> {
    find_evebox_exe(&paths.evebox_install_dir())?
        .ok_or_else(|| anyhow!("EveBox is not installed. Run 'evectl install' first."))
}

fn extract_evebox_version_from_path(path: &Path) -> Option<String> {
    for component in path.components() {
        let name = component.as_os_str().to_string_lossy();
        if let Some(version) = name
            .strip_prefix("evebox-")
            .and_then(|rest| rest.strip_suffix("-windows-x64"))
            && !version.is_empty()
        {
            return Some(version.to_string());
        }
    }

    None
}

pub(super) fn evebox_installed_version(install_dir: &Path) -> Result<Option<String>> {
    let marker_path = install_dir.join(EVEBOX_VERSION_MARKER);
    if marker_path.exists() {
        let version = std::fs::read_to_string(&marker_path).context(format!(
            "Failed to read EveBox version marker {}",
            marker_path.display()
        ))?;
        let version = version.trim();
        if !version.is_empty() {
            return Ok(Some(version.to_string()));
        }
    }

    let Some(exe_path) = find_evebox_exe(install_dir)? else {
        return Ok(None);
    };
    Ok(extract_evebox_version_from_path(&exe_path))
}

pub(super) fn evebox_installed_channel(install_dir: &Path) -> Result<Option<EveBoxChannel>> {
    if find_evebox_exe(install_dir)?.is_none() {
        return Ok(None);
    }
    let marker = install_dir.join(EVEBOX_CHANNEL_MARKER);
    if marker.exists() {
        let text = std::fs::read_to_string(&marker)?;
        return <EveBoxChannel as clap::ValueEnum>::from_str(text.trim(), false)
            .map(Some)
            .map_err(|err| anyhow!("Invalid EveBox channel marker: {err}"));
    }
    // Legacy installs had only a version marker or a versioned directory.
    let version = evebox_installed_version(install_dir)?;
    Ok(version.and_then(|version| {
        let version = version.split_whitespace().next()?;
        let version = semver::Version::parse(version).ok()?;
        Some(if version.pre.is_empty() {
            EveBoxChannel::Release
        } else {
            EveBoxChannel::Development
        })
    }))
}

pub(super) fn uninstall_evebox(paths: &Paths) -> Result<()> {
    let root_dir = paths.evebox_dir();

    if !root_dir.exists() {
        info!(
            "EveBox is not installed in {:?}. Skipping EveBox uninstall.",
            root_dir
        );
        return Ok(());
    }

    std::fs::remove_dir_all(&root_dir)
        .context(format!("Failed to remove EveBox directory {:?}", root_dir))?;
    info!("EveBox uninstalled from {:?}", root_dir);
    Ok(())
}

/// Swap only the install directory, retaining the old build for rollback.
pub(super) fn replace_evebox_installation(staging: &Path, install_dir: &Path) -> Result<()> {
    let root_dir = install_dir
        .parent()
        .context("Missing EveBox root directory")?;
    let backup_dir = tempfile::tempdir_in(root_dir)?;
    let backup_path = backup_dir.path().join("previous");
    let had_installation = install_dir.exists();
    if had_installation {
        std::fs::rename(install_dir, &backup_path)
            .context("Failed to move the old EveBox installation; stop EveBox and retry")?;
    }

    if let Err(err) = std::fs::rename(staging, install_dir) {
        if had_installation && let Err(restore_err) = std::fs::rename(&backup_path, install_dir) {
            let retained = backup_dir.keep();
            bail!(
                "Failed to install EveBox: {err}; rollback failed: {restore_err}. Previous installation retained in {}",
                retained.join("previous").display()
            );
        }
        return Err(err).context("Failed to replace EveBox installation");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evebox_channel_markers_support_legacy_installs() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(evebox_installed_channel(dir.path()).unwrap(), None);
        std::fs::write(dir.path().join("evebox.exe"), b"binary").unwrap();
        for (version, expected) in [
            ("0.28.0", EveBoxChannel::Release),
            ("0.30.0-dev rev abc1234", EveBoxChannel::Development),
        ] {
            std::fs::write(dir.path().join(EVEBOX_VERSION_MARKER), version).unwrap();
            assert_eq!(
                evebox_installed_channel(dir.path()).unwrap(),
                Some(expected)
            );
        }
        // The explicit channel wins, even for a main build at a release tag.
        std::fs::write(dir.path().join(EVEBOX_VERSION_MARKER), "0.29.0").unwrap();
        std::fs::write(dir.path().join(EVEBOX_CHANNEL_MARKER), "development").unwrap();
        assert_eq!(
            evebox_installed_channel(dir.path()).unwrap(),
            Some(EveBoxChannel::Development)
        );
    }

    #[test]
    fn evebox_development_versions_include_revision() {
        let first = crate::parse_evebox_version(
            "EveBox Version 0.30.0-dev (rev abc1234); x86_64-pc-windows-gnu",
        );
        let second = crate::parse_evebox_version(
            "EveBox Version 0.30.0-dev (rev def5678); x86_64-pc-windows-gnu",
        );
        assert_eq!(first.as_deref(), Some("0.30.0-dev rev abc1234"));
        assert_ne!(first, second);
    }

    #[test]
    fn evebox_replacement_preserves_data_and_removes_old_files() {
        let dir = tempfile::tempdir().unwrap();
        let install_dir = dir.path().join("install");
        let staging = dir.path().join("staging");
        let data_dir = dir.path().join("data");
        for path in [&install_dir, &staging, &data_dir] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::write(install_dir.join("obsolete"), b"old").unwrap();
        std::fs::write(staging.join("evebox.exe"), b"new binary").unwrap();
        std::fs::write(data_dir.join("events.sqlite"), b"keep").unwrap();

        replace_evebox_installation(&staging, &install_dir).unwrap();
        assert_eq!(
            std::fs::read(install_dir.join("evebox.exe")).unwrap(),
            b"new binary"
        );
        assert!(!install_dir.join("obsolete").exists());
        assert_eq!(
            std::fs::read(data_dir.join("events.sqlite")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn failed_evebox_replacement_restores_old_installation() {
        let dir = tempfile::tempdir().unwrap();
        let install_dir = dir.path().join("install");
        std::fs::create_dir(&install_dir).unwrap();
        std::fs::write(install_dir.join("evebox.exe"), b"old binary").unwrap();

        assert!(replace_evebox_installation(&dir.path().join("missing"), &install_dir).is_err());
        assert_eq!(
            std::fs::read(install_dir.join("evebox.exe")).unwrap(),
            b"old binary"
        );
    }

    #[test]
    fn release_manifest_resolves_versioned_windows_archive() {
        let download = Download::from_release_manifest(r#"{"version":"0.29.0"}"#).unwrap();
        assert_eq!(download.channel, EveBoxChannel::Release);
        assert_eq!(download.archive_name, "evebox-0.29.0-windows-x64.zip");
        assert_eq!(
            download.url,
            "https://evebox.org/files/release/0.29.0/evebox-0.29.0-windows-x64.zip"
        );
        assert!(download.validate_version("0.29.0").is_ok());
        assert!(download.validate_version("0.30.0").is_err());
        assert!(download.validate_version("0.29.0-dev rev abc1234").is_err());
    }

    #[test]
    fn release_manifest_rejects_invalid_and_nonrelease_versions() {
        for manifest in [
            "not JSON",
            "{}",
            r#"{"version":29}"#,
            r#"{"version":""}"#,
            r#"{"version":"../development"}"#,
            r#"{"version":"0.30.0-dev"}"#,
            r#"{"version":"0.29.0+build"}"#,
            r#"{"version":" 0.29.0 "}"#,
        ] {
            assert!(
                Download::from_release_manifest(manifest).is_err(),
                "{manifest}"
            );
        }
    }

    #[test]
    fn development_resolves_offline_and_accepts_changing_revisions() {
        let download = Download::resolve(EveBoxChannel::Development).unwrap();
        assert_eq!(download.channel, EveBoxChannel::Development);
        assert_eq!(download.url, DEVELOPMENT_URL);
        assert_eq!(download.archive_name, "evebox-devel-windows-x64.zip");
        for version in ["0.30.0-dev rev abc1234", "0.30.0-dev rev def5678", "0.29.0"] {
            assert!(download.validate_version(version).is_ok());
        }
        assert!(download.validate_version("unknown").is_err());
    }
}
