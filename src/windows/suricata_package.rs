// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! EveCtl's Windows builds of Suricata, published as zips on the
//! evectl-suricata-windows releases page.

use super::checksum::{checksum_for, file_sha256};
use super::component::{compare_versions, parse_version_parts};
use super::install::download_file;
use super::paths::Paths;
use super::suricata::SURICATA_VERSION;
use crate::prelude::*;
use serde::Deserialize;
use std::cmp::Ordering;
use std::path::PathBuf;
use std::time::Duration;

const REPO: &str = "jasonish/evectl-suricata-windows";

/// The build this EveCtl was released with, published under a release
/// tagged with its version, and the SHA-256 of its zip. Installed when
/// the releases page has nothing newer or can't be checked. Builds
/// from 8.0.7-2 reload rules on a service control.
const PINNED_VERSION: &str = "8.0.8-1";
const PINNED_SHA256: &str = "a73ceba9d3fc868c7715c08b48097f52b52debdc33b5fb7d322f7699ad9e68c4";

const CHECKSUMS_NAME: &str = "SHA256SUMS";
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);

/// A Suricata build to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Package {
    /// The Suricata release and build revision, such as 8.0.7-1.
    pub(super) version: String,
    url: String,
    sha256: String,
}

/// A release as listed by the GitHub releases API.
#[derive(Debug, Deserialize)]
struct Release {
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// A build found on the releases page, before its checksum is fetched.
#[derive(Debug, PartialEq, Eq)]
struct Candidate {
    version: String,
    url: String,
    checksums_url: String,
}

impl Package {
    fn pinned() -> Self {
        Self {
            version: PINNED_VERSION.to_string(),
            url: format!(
                "https://github.com/{REPO}/releases/download/{PINNED_VERSION}/{}",
                file_name(PINNED_VERSION)
            ),
            sha256: PINNED_SHA256.to_string(),
        }
    }

    /// The newest build of the bundled Suricata series on the releases
    /// page, or the pinned build when there's nothing newer or the
    /// releases can't be checked.
    pub(super) fn resolve() -> Self {
        let pinned = Self::pinned();
        match Self::newer_than(&pinned.version) {
            Ok(Some(package)) => {
                info!("Found Suricata build {}", package.version);
                package
            }
            Ok(None) => pinned,
            Err(err) => {
                warn!(
                    "Failed to check for new Suricata builds, using {}: {err:#}",
                    pinned.version
                );
                pinned
            }
        }
    }

    fn newer_than(version: &str) -> Result<Option<Self>> {
        let client = crate::http::client_builder()
            .timeout(LOOKUP_TIMEOUT)
            .user_agent(concat!("evectl/", env!("EVECTL_VERSION")))
            .build()?;

        info!("Checking {REPO} for new Suricata builds");
        let releases = client
            .get(format!(
                "https://api.github.com/repos/{REPO}/releases?per_page=100"
            ))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()?
            .error_for_status()?
            .text()?;
        let releases: Vec<Release> = serde_json::from_str(&releases)
            .context("Invalid response from the GitHub releases API")?;

        let Some(candidate) = newest_candidate(&releases) else {
            return Ok(None);
        };
        if compare_versions(&candidate.version, version) != Some(Ordering::Greater) {
            return Ok(None);
        }

        let checksums = client
            .get(&candidate.checksums_url)
            .send()?
            .error_for_status()?
            .text()
            .with_context(|| format!("Failed to download {}", candidate.checksums_url))?;
        let name = file_name(&candidate.version);
        let sha256 = checksum_for(&checksums, &name)
            .with_context(|| format!("{} has no checksum for {name}", candidate.checksums_url))?;

        Ok(Some(Self {
            version: candidate.version,
            url: candidate.url,
            sha256,
        }))
    }

    /// Download the build into the installer cache, reusing a cached
    /// copy that matches its checksum.
    pub(super) fn download(&self, paths: &Paths) -> Result<PathBuf> {
        let cache_dir = paths.downloads_dir();
        std::fs::create_dir_all(&cache_dir).context(format!(
            "Failed to create installer cache directory {}",
            cache_dir.display()
        ))?;

        let path = cache_dir.join(file_name(&self.version));
        if path.exists() {
            if file_sha256(&path)? == self.sha256 {
                info!("Using the cached Suricata package {}", path.display());
                return Ok(path);
            }
            warn!(
                "The cached Suricata package {} doesn't match its checksum, downloading it again",
                path.display()
            );
        }

        download_file(&self.url, &path, "Suricata")?;
        let checksum = file_sha256(&path)?;
        if checksum != self.sha256 {
            let _ = std::fs::remove_file(&path);
            bail!(
                "The downloaded Suricata package has SHA-256 {checksum}, expected {}",
                self.sha256
            );
        }
        Ok(path)
    }
}

fn file_name(version: &str) -> String {
    format!("suricata-{version}-windows-x86_64.zip")
}

/// The version in a build's file name, such as 8.0.7-1 from
/// suricata-8.0.7-1-windows-x86_64.zip.
fn version_from_file_name(name: &str) -> Option<&str> {
    let version = name
        .strip_prefix("suricata-")?
        .strip_suffix("-windows-x86_64.zip")?;
    let (release, revision) = version.split_once('-')?;
    let numeric = |part: &str| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit());
    let release_parts = release.split('.').collect::<Vec<_>>();
    (release_parts.len() == 3 && release_parts.into_iter().all(numeric) && numeric(revision))
        .then_some(version)
}

/// Whether a build is of the Suricata major and minor version this
/// EveCtl bundles, which it's known to work with.
fn in_bundled_series(version: &str) -> bool {
    match (
        parse_version_parts(version),
        parse_version_parts(SURICATA_VERSION),
    ) {
        (Some(version), Some(bundled)) => version.get(..2) == bundled.get(..2),
        _ => false,
    }
}

/// The newest build in the bundled series. Prereleases, which the
/// releases page uses for test builds, are skipped, as are releases
/// without checksums.
fn newest_candidate(releases: &[Release]) -> Option<Candidate> {
    releases
        .iter()
        .filter(|release| !release.draft && !release.prerelease)
        .filter_map(|release| {
            let checksums = release
                .assets
                .iter()
                .find(|asset| asset.name == CHECKSUMS_NAME)?;
            release.assets.iter().find_map(|asset| {
                let version = version_from_file_name(&asset.name)?;
                in_bundled_series(version).then(|| Candidate {
                    version: version.to_string(),
                    url: asset.browser_download_url.clone(),
                    checksums_url: checksums.browser_download_url.clone(),
                })
            })
        })
        .max_by(|a, b| compare_versions(&a.version, &b.version).unwrap_or(Ordering::Equal))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, prerelease: bool, assets: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": prerelease,
            "assets": assets.iter().map(|name| serde_json::json!({
                "name": name,
                "browser_download_url": format!("https://example.com/{tag}/{name}"),
            })).collect::<Vec<_>>(),
        })
    }

    fn releases(values: Vec<serde_json::Value>) -> Vec<Release> {
        serde_json::from_value(serde_json::Value::Array(values)).unwrap()
    }

    #[test]
    fn versions_come_from_well_formed_file_names() {
        assert_eq!(
            version_from_file_name("suricata-8.0.7-1-windows-x86_64.zip"),
            Some("8.0.7-1")
        );
        assert_eq!(
            version_from_file_name("suricata-10.0.12-34-windows-x86_64.zip"),
            Some("10.0.12-34")
        );
        for name in [
            "suricata-8.0.7-windows-x86_64.zip",
            "suricata-8.0-1-windows-x86_64.zip",
            "suricata-8.0.7-rc1-windows-x86_64.zip",
            "suricata-8.0.7-1-windows-x86_64.tar.gz",
            "SHA256SUMS",
        ] {
            assert_eq!(version_from_file_name(name), None, "{name}");
        }
    }

    #[test]
    fn newest_build_of_the_bundled_series_is_chosen() {
        let zip = |version: &str| file_name(version);
        let listed = releases(vec![
            release("8.0.7-2", false, &[&zip("8.0.7-2"), CHECKSUMS_NAME]),
            release("8.0.8-1", false, &[&zip("8.0.8-1"), CHECKSUMS_NAME]),
            // A test build, a later series, and a release without checksums.
            release("0.2.0-alpha.1", true, &[&zip("8.0.9-1"), CHECKSUMS_NAME]),
            release("9.0.0-1", false, &[&zip("9.0.0-1"), CHECKSUMS_NAME]),
            release("8.0.10-1", false, &[&zip("8.0.10-1")]),
        ]);
        assert_eq!(
            newest_candidate(&listed),
            Some(Candidate {
                version: "8.0.8-1".to_string(),
                url: format!("https://example.com/8.0.8-1/{}", zip("8.0.8-1")),
                checksums_url: "https://example.com/8.0.8-1/SHA256SUMS".to_string(),
            })
        );

        let only_tests = releases(vec![release(
            "0.1.0-alpha.2",
            true,
            &[&zip("8.0.7-1"), CHECKSUMS_NAME],
        )]);
        assert_eq!(newest_candidate(&only_tests), None);
    }

    #[test]
    fn pinned_build_is_in_the_bundled_series_and_replaces_msi_installs() {
        let pinned = Package::pinned();
        assert!(in_bundled_series(&pinned.version));
        assert!(pinned.url.ends_with(&file_name(&pinned.version)));
        assert_eq!(pinned.sha256.len(), 64);
        // An install from the OISF MSI is marked with only the release.
        assert_eq!(
            compare_versions(SURICATA_VERSION, &pinned.version),
            Some(Ordering::Less)
        );
    }
}
