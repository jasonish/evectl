// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::config::EveBoxChannel;
use crate::prelude::*;
use anyhow::ensure;
use semver::Version;
use serde::Deserialize;
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

#[cfg(test)]
mod tests {
    use super::*;

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
