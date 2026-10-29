// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! EveCtl's Windows builds of Suricata, published as zips on the
//! evectl-suricata-windows releases page.

use super::checksum::file_sha256;
use super::install::download_file;
use super::paths::Paths;
use crate::prelude::*;
use std::path::PathBuf;

const REPO: &str = "jasonish/evectl-suricata-windows";

/// The build this EveCtl installs, published under a release tagged
/// with its version, and the SHA-256 of its zip. Builds from 8.0.7-2
/// reload rules on a service control.
pub(super) const PINNED_VERSION: &str = "8.0.8-1";
const PINNED_SHA256: &str = "a73ceba9d3fc868c7715c08b48097f52b52debdc33b5fb7d322f7699ad9e68c4";

/// A Suricata build to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Package {
    /// The Suricata release and build revision, such as 8.0.7-1.
    pub(super) version: String,
    url: String,
    sha256: String,
}

impl Package {
    pub(super) fn pinned() -> Self {
        Self {
            version: PINNED_VERSION.to_string(),
            url: format!(
                "https://github.com/{REPO}/releases/download/{PINNED_VERSION}/{}",
                file_name(PINNED_VERSION)
            ),
            sha256: PINNED_SHA256.to_string(),
        }
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

#[cfg(test)]
mod tests {
    use super::super::component::compare_versions;
    use super::super::suricata::SURICATA_VERSION;
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn pinned_build_replaces_msi_installs() {
        let pinned = Package::pinned();
        assert!(pinned.url.ends_with(&file_name(&pinned.version)));
        assert_eq!(pinned.sha256.len(), 64);
        // An install from the OISF MSI is marked with only the release.
        assert_eq!(
            compare_versions(SURICATA_VERSION, &pinned.version),
            Some(Ordering::Less)
        );
    }
}
