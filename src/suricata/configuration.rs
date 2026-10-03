// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Platform operations used by the shared Suricata configuration menu.

use std::path::PathBuf;

use crate::config::EveOutput;
use crate::container::CommandExt;
use crate::prelude::*;

#[derive(Debug, Clone)]
pub(crate) struct Interface {
    /// Stored in the configuration. Windows resolves this name to a GUID
    /// when starting Suricata, rather than storing a display label or GUID.
    pub name: String,
    pub address: Option<String>,
}

pub(crate) trait Backend {
    fn interfaces(&self) -> Result<Vec<Interface>>;
    fn eve_outputs(&self) -> &'static [EveOutput];
    fn filestore_dir(&self) -> Result<PathBuf>;
    fn check_remove_extracted_files(&self) -> Result<()>;
    /// Recheck service state before deleting, even if checked before prompting.
    fn remove_extracted_files(&self) -> Result<()>;
}

pub(crate) fn container_interfaces() -> Result<Vec<Interface>> {
    Ok(evectl::system::get_interfaces()?
        .into_iter()
        .map(|interface| Interface {
            name: interface.name,
            address: interface.addr4.into_iter().next(),
        })
        .collect())
}

pub(crate) struct ContainerBackend<'a>(pub(crate) &'a Context);

impl Backend for ContainerBackend<'_> {
    fn interfaces(&self) -> Result<Vec<Interface>> {
        container_interfaces()
    }

    fn eve_outputs(&self) -> &'static [EveOutput] {
        &[EveOutput::UnixStream, EveOutput::File]
    }

    fn filestore_dir(&self) -> Result<PathBuf> {
        Ok(super::filestore_dir(self.0))
    }

    fn check_remove_extracted_files(&self) -> Result<()> {
        // Listing distinguishes missing containers from runtime failures.
        // Never treat a failed inspection as permission to delete files.
        let output = self
            .0
            .manager
            .command()
            .args(["ps", "--all", "--format", "{{.Names}}"])
            .status_output()?;
        let existing = String::from_utf8(output)?;
        for name in [
            super::container_name(self.0),
            crate::housekeeper::container_name(self.0),
            crate::housekeeper::legacy_container_name(self.0),
        ] {
            if existing.lines().any(|existing| existing == name) {
                let state = self.0.manager.state(&name)?;
                if state.running || state.restarting {
                    bail!(
                        "Suricata or housekeeping is running; stop services before removing extracted files"
                    );
                }
            }
        }
        Ok(())
    }

    fn remove_extracted_files(&self) -> Result<()> {
        self.check_remove_extracted_files()?;
        let directory = self.filestore_dir()?;
        if directory.exists() {
            crate::uninstall::remove_directory(self.0, &directory)?;
        }
        Ok(())
    }
}
