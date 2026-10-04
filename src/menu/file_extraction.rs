// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Suricata file extraction settings, entered from the Suricata menu.
//!
//! File extraction enables Suricata's file-store output, writing
//! files seen on the network to the Suricata log directory, where they
//! are kept until pruned by age.

use std::path::Path;

use crate::config::FileExtractionConfig;
use crate::menu::cleanup;
use crate::prelude::*;
use crate::prompt::Selections;

/// Shared settings prompt for native Windows and container installations.
pub(crate) fn toggle_config(config: &mut Config, dir: &Path) {
    if config.suricata.file_extraction.enabled {
        config.suricata.file_extraction.enabled = false;
        cleanup::note_remaining("extracted files", dir);
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
    if let Ok(Some(force_filestore)) =
        selections.prompt_with("outputs.file-store.force-filestore", |select| {
            select
                .with_starting_cursor(current)
                .with_help_message("Without force, rules use the filestore keyword to select files")
        })
    {
        config.suricata.file_extraction.force_filestore = force_filestore;
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
/// extraction, or None if there are none.
pub(crate) fn remove_label_for(config: &Config, dir: &Path) -> Option<String> {
    if config.suricata.file_extraction.enabled {
        return None;
    }
    cleanup::remove_label("extracted files", dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EveOutput;
    use crate::suricata::configuration::{Backend, Interface};
    use std::cell::Cell;
    use std::path::PathBuf;

    struct CleanupBackend {
        directory: PathBuf,
        removed: Cell<bool>,
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
            Ok(())
        }
        fn remove_extracted_files(&self) -> Result<()> {
            self.removed.set(true);
            Ok(())
        }
    }

    #[test]
    fn extracted_files_are_removed_through_the_backend() {
        let directory = tempfile::tempdir().unwrap();
        let fake = CleanupBackend {
            directory: directory.path().to_path_buf(),
            removed: Cell::new(false),
        };
        let backend: &dyn Backend = &fake;
        cleanup::remove_with_confirmation(backend, |question| {
            assert!(question.contains("extracted files"));
            assert!(question.contains(&directory.path().display().to_string()));
            true
        })
        .unwrap();
        assert!(fake.removed.get());
    }

    #[test]
    fn removal_is_only_offered_while_disabled_with_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        assert_eq!(remove_label_for(&config, dir.path()), None);
        std::fs::write(dir.path().join("extracted"), b"fixture").unwrap();
        assert!(remove_label_for(&config, dir.path()).is_some());
        config.suricata.file_extraction.enabled = true;
        assert_eq!(remove_label_for(&config, dir.path()), None);
    }
}
