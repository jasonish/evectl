// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! SHA-256 checksums of downloads.

use crate::prelude::*;
use std::path::Path;

/// The checksum of `name` in a `sha256sum` style checksums file.
pub(super) fn checksum_for(checksums: &str, name: &str) -> Option<String> {
    checksums.lines().find_map(|line| {
        let (hash, file) = line.trim().split_once(char::is_whitespace)?;
        let file = file.trim_start().trim_start_matches('*');
        (file == name && hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}

pub(super) fn file_sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_are_found_by_file_name() {
        let hash = "138433A38A69E0B7A5DA3A4F70E21BCC685A08C57298538633F1B086663C078D";
        let checksums = format!(
            "{}  suricata-8.0.6-1-windows-x86_64.zip\n{hash} *suricata-8.0.7-1-windows-x86_64.zip\n",
            "0".repeat(64)
        );
        assert_eq!(
            checksum_for(&checksums, "suricata-8.0.7-1-windows-x86_64.zip"),
            Some(hash.to_ascii_lowercase())
        );
        assert_eq!(
            checksum_for(&checksums, "suricata-8.0.8-1-windows-x86_64.zip"),
            None
        );
        assert_eq!(checksum_for("abc  file.zip", "file.zip"), None);
    }

    #[test]
    fn files_are_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            file_sha256(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
