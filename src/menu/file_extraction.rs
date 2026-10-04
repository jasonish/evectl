// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Suricata file extraction settings, entered from the Suricata menu.
//!
//! File extraction enables Suricata's file-store output, writing
//! files seen on the network to the Suricata log directory, where they
//! are kept until pruned by age.

use std::path::Path;

use crate::config::FileExtractionConfig;
use crate::menu::fpc::format_size;
use crate::prelude::*;
use crate::prompt::Selections;
use crate::suricata::configuration::Backend;

/// Shared settings prompt for native Windows and container installations.
pub(crate) fn toggle_config(config: &mut Config, dir: &Path) {
    if config.suricata.file_extraction.enabled {
        config.suricata.file_extraction.enabled = false;
        if dir_size(dir) > 0 {
            info!(
                "Existing extracted files remain in {}; they can be removed from this menu after \
                 restarting services",
                dir.display()
            );
            crate::prompt::enter();
        }
        return;
    }

    if !config.suricata.enabled {
        error!("File extraction requires Suricata to be enabled");
        crate::prompt::enter();
        return;
    }

    if config.evebox_agent.enabled && !crate::menu::evebox_agent::setup_retrieval(config) {
        return;
    }

    config.suricata.file_extraction.enabled = true;
}

pub(crate) fn force_filestore_label(config: &Config) -> String {
    format!(
        "    outputs.file-store.force-filestore (current: {})",
        if config.suricata.file_extraction.force_filestore {
            "yes"
        } else {
            "no"
        }
    )
}

fn force_filestore_name(force_filestore: bool) -> &'static str {
    if force_filestore {
        "yes, store all files"
    } else {
        "no, only files matching filestore rules"
    }
}

pub(crate) fn set_force_filestore(config: &mut Config) {
    let mut selections = Selections::new();
    selections.push(false, force_filestore_name(false));
    selections.push(true, force_filestore_name(true));
    let current = usize::from(config.suricata.file_extraction.force_filestore);
    if let Ok(selection) =
        inquire::Select::new("outputs.file-store.force-filestore", selections.to_vec())
            .with_starting_cursor(current)
            .with_help_message("Without force, rules use the filestore keyword to select files")
            .prompt()
    {
        config.suricata.file_extraction.force_filestore = selection.tag;
    }
}

pub(crate) fn max_size_label(config: &Config) -> String {
    format!(
        "    Max Extract Size (current: {})",
        config.suricata.file_extraction.max_size()
    )
}

pub(crate) fn set_max_size(config: &mut Config) {
    let validator = crate::prompt::validator(|input| {
        if FileExtractionConfig::is_valid_size(input) {
            Ok(())
        } else {
            Err("Must be a size greater than 0 and less than 4gb, e.g. 4mb".to_string())
        }
    });
    if let Ok(value) = inquire::Text::new("Max extract size:")
        .with_default(config.suricata.file_extraction.max_size())
        .with_help_message(
            "Larger files are stored truncated, e.g. 4mb, 512kb, 1gb; \
             with force-filestore, raises limits for all traffic",
        )
        .with_validator(validator)
        .prompt()
    {
        let value = value.trim().to_lowercase();
        config.suricata.file_extraction.max_size =
            (value != FileExtractionConfig::DEFAULT_MAX_SIZE).then_some(value);
    }
}

pub(crate) fn retention_label(config: &Config) -> String {
    let current = match config.suricata.file_extraction.max_age_days() {
        0 => "forever".to_string(),
        1 => "1 day".to_string(),
        days => format!("{days} days"),
    };
    format!("    Retention (current: {current})")
}

pub(crate) fn set_retention(config: &mut Config) {
    let validator = crate::prompt::validator(|input| {
        input
            .trim()
            .parse::<u32>()
            .map(|_| ())
            .map_err(|_| "Must be a number of days, 0 to keep files forever".to_string())
    });
    if let Ok(value) = inquire::Text::new("Days to keep extracted files:")
        .with_default(&config.suricata.file_extraction.max_age_days().to_string())
        .with_help_message("0 keeps files until removed manually")
        .with_validator(validator)
        .prompt()
        && let Ok(days) = value.trim().parse::<u32>()
    {
        config.suricata.file_extraction.max_age_days =
            if days == FileExtractionConfig::DEFAULT_MAX_AGE_DAYS {
                None
            } else {
                Some(days)
            };
    }
}

/// Label for removing extracted files left behind after disabling
/// extraction, or None if there are none. Nothing manages these files
/// once extraction is disabled.
pub(crate) fn remove_label_for(config: &Config, dir: &Path) -> Option<String> {
    if config.suricata.file_extraction.enabled {
        return None;
    }
    let size = dir_size(dir);
    (size > 0).then(|| {
        format!(
            "Remove Extracted Files (~{} in {})",
            format_size(size),
            dir.display()
        )
    })
}

pub(crate) fn remove_files(backend: &dyn Backend) -> Result<()> {
    remove_files_with_confirmation(backend, crate::prompt::confirm_destructive)
}

fn remove_files_with_confirmation(
    backend: &dyn Backend,
    confirm: impl FnOnce(&str) -> bool,
) -> Result<()> {
    backend.check_remove_extracted_files()?;
    let dir = backend.filestore_dir()?;
    let question = format!(
        "Remove all extracted files in {} (~{})?",
        dir.display(),
        format_size(dir_size(&dir)),
    );
    if confirm(&question) {
        backend.remove_extracted_files()?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EveOutput;
    use crate::suricata::configuration::Interface;
    use std::cell::Cell;
    use std::path::PathBuf;

    struct CleanupBackend {
        directory: PathBuf,
        blocked: Cell<bool>,
        removed: Cell<bool>,
        fail_remove: bool,
    }

    impl Backend for CleanupBackend {
        fn interfaces(&self) -> Result<Vec<Interface>> {
            unreachable!()
        }
        fn eve_outputs(&self) -> &'static [EveOutput] {
            &[EveOutput::File]
        }
        fn filestore_dir(&self) -> Result<PathBuf> {
            Ok(self.directory.clone())
        }
        fn check_remove_extracted_files(&self) -> Result<()> {
            if self.blocked.get() {
                bail!("Service is running or cannot be inspected");
            }
            Ok(())
        }
        fn remove_extracted_files(&self) -> Result<()> {
            self.check_remove_extracted_files()?;
            if self.fail_remove {
                bail!("Removal failed");
            }
            self.removed.set(true);
            Ok(())
        }
    }

    #[test]
    fn cleanup_requires_confirmation_and_propagates_failures() {
        let directory = tempfile::tempdir().unwrap();
        let mut backend = CleanupBackend {
            directory: directory.path().to_path_buf(),
            blocked: Cell::new(false),
            removed: Cell::new(false),
            fail_remove: false,
        };
        remove_files_with_confirmation(&backend, |_| false).unwrap();
        assert!(!backend.removed.get());
        backend.blocked.set(true);
        assert!(remove_files_with_confirmation(&backend, |_| panic!("Must not prompt")).is_err());
        assert!(!backend.removed.get());
        backend.blocked.set(false);
        // Starting a service while the confirmation is open also prevents removal.
        assert!(
            remove_files_with_confirmation(&backend, |_| {
                backend.blocked.set(true);
                true
            })
            .is_err()
        );
        assert!(!backend.removed.get());
        backend.blocked.set(false);
        backend.fail_remove = true;
        assert!(remove_files_with_confirmation(&backend, |_| true).is_err());
        assert!(!backend.removed.get());
        backend.fail_remove = false;
        remove_files_with_confirmation(&backend, |question| {
            assert!(question.contains(&directory.path().display().to_string()));
            true
        })
        .unwrap();
        assert!(backend.removed.get());
    }

    #[test]
    fn dir_size_is_recursive() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(dir_size(dir.path()), 0);
        std::fs::create_dir_all(dir.path().join("ab")).unwrap();
        std::fs::create_dir_all(dir.path().join("tmp")).unwrap();
        std::fs::write(dir.path().join("ab").join("ab12"), [0u8; 1000]).unwrap();
        std::fs::write(dir.path().join("tmp").join("partial"), [0u8; 24]).unwrap();
        assert_eq!(dir_size(dir.path()), 1024);
        assert_eq!(dir_size(&dir.path().join("missing")), 0);
    }
}
