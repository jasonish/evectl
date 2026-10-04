// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Data left behind after a capture feature is disabled: packet capture
//! spools and extracted files. Nothing manages these once the feature is
//! off, so the menus offer to remove them while services are stopped.

use std::path::{Path, PathBuf};

use crate::prelude::*;

/// A directory of leftover data and the checks around removing it.
pub(crate) trait Leftovers {
    /// What the directory holds, e.g. "packet captures".
    fn what(&self) -> &'static str;
    fn dir(&self) -> Result<PathBuf>;
    fn check_remove(&self) -> Result<()>;
    /// Rechecks service state before deleting, even if checked before
    /// prompting.
    fn remove(&self) -> Result<()>;
}

impl Leftovers for dyn crate::fpc::Backend + '_ {
    fn what(&self) -> &'static str {
        "packet captures"
    }
    fn dir(&self) -> Result<PathBuf> {
        self.spool_dir()
    }
    fn check_remove(&self) -> Result<()> {
        self.check_remove_spool()
    }
    fn remove(&self) -> Result<()> {
        self.remove_spool()
    }
}

impl Leftovers for dyn crate::suricata::configuration::Backend + '_ {
    fn what(&self) -> &'static str {
        "extracted files"
    }
    fn dir(&self) -> Result<PathBuf> {
        self.filestore_dir()
    }
    fn check_remove(&self) -> Result<()> {
        self.check_remove_extracted_files()
    }
    fn remove(&self) -> Result<()> {
        self.remove_extracted_files()
    }
}

/// Remove the leftovers after confirmation, if the backend allows it.
pub(crate) fn remove_with_confirmation(
    leftovers: &(impl Leftovers + ?Sized),
    confirm: impl FnOnce(&str) -> bool,
) -> Result<()> {
    leftovers.check_remove()?;
    let dir = leftovers.dir()?;
    let question = format!(
        "Remove all {} in {} (~{})?",
        leftovers.what(),
        dir.display(),
        format_size(dir_size(&dir)),
    );
    if confirm(&question) {
        leftovers.remove()?;
    }
    Ok(())
}

/// Menu label offering to remove the leftovers, or None if there are
/// none.
pub(crate) fn remove_label(what: &str, dir: &Path) -> Option<String> {
    let size = dir_size(dir);
    (size > 0).then(|| {
        format!(
            "Remove existing {what} (~{} in {})",
            format_size(size),
            dir.display()
        )
    })
}

/// After disabling a feature, point out the leftovers it keeps.
pub(crate) fn note_remaining(what: &str, dir: &Path) {
    if dir_size(dir) > 0 {
        info!(
            "Existing {what} remain in {}; they can be removed from this menu after restarting \
             services",
            dir.display()
        );
        crate::prompt::enter();
    }
}

/// Total size of the files under a directory, recursively, best
/// effort. Symbolic links are not followed.
pub(crate) fn dir_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => dir_size(&entry.path()),
            Ok(file_type) if file_type.is_file() => {
                entry.metadata().map(|metadata| metadata.len()).unwrap_or(0)
            }
            _ => 0,
        })
        .sum()
}

pub(crate) fn format_size(bytes: u64) -> String {
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else {
        format!("{} MB", bytes.div_ceil(MB))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::menu::test_support::FakePlatform;

    #[test]
    fn removal_requires_stopped_services_and_explicit_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let mut platform = FakePlatform::with_dir(dir.path());
        remove_with_confirmation(platform.as_fpc(), |_| false).unwrap();
        assert!(!platform.removed.get());
        platform.blocked.set(true);
        assert!(
            remove_with_confirmation(platform.as_fpc(), |_| panic!("Must not prompt")).is_err()
        );
        assert!(!platform.removed.get());
        platform.blocked.set(false);
        // Starting a service while the confirmation is open also prevents removal.
        assert!(
            remove_with_confirmation(platform.as_fpc(), |_| {
                platform.blocked.set(true);
                true
            })
            .is_err()
        );
        assert!(!platform.removed.get());
        platform.blocked.set(false);
        platform.fail = Some("remove");
        assert!(remove_with_confirmation(platform.as_fpc(), |_| true).is_err());
        assert!(!platform.removed.get());
        platform.fail = None;
        remove_with_confirmation(platform.as_fpc(), |question| {
            assert!(question.contains("packet captures"));
            assert!(question.contains(&dir.path().display().to_string()));
            true
        })
        .unwrap();
        assert!(platform.removed.get());
    }

    #[test]
    fn labels_and_notes_depend_on_leftover_size() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(remove_label("packet captures", dir.path()), None);
        std::fs::write(dir.path().join("log.0.1.pcap"), [0u8; 1000]).unwrap();
        let label = remove_label("packet captures", dir.path()).unwrap();
        assert!(label.starts_with("Remove existing packet captures (~1 MB in "));
        assert!(label.contains(&dir.path().display().to_string()));
    }

    #[test]
    fn dir_size_is_recursive_and_ignores_missing_directories() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(dir_size(dir.path()), 0);
        std::fs::create_dir_all(dir.path().join("ab")).unwrap();
        std::fs::create_dir_all(dir.path().join("tmp")).unwrap();
        std::fs::create_dir(dir.path().join("empty")).unwrap();
        std::fs::write(dir.path().join("ab").join("ab12"), [0u8; 1000]).unwrap();
        std::fs::write(dir.path().join("tmp").join("partial"), [0u8; 24]).unwrap();
        assert_eq!(dir_size(dir.path()), 1024);
        assert_eq!(dir_size(&dir.path().join("missing")), 0);
    }

    #[test]
    fn format_size_rounds_sensibly() {
        assert_eq!(format_size(1), "1 MB");
        assert_eq!(format_size(256 * 1024 * 1024), "256 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(
            format_size(25 * 1024 * 1024 * 1024 + 512 * 1024 * 1024),
            "25.5 GB"
        );
    }
}
