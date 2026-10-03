// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Platform operations for the shared packet-capture configuration menu.

use std::path::PathBuf;

use crate::container::CommandExt;
use crate::prelude::*;

pub(crate) trait Backend {
    fn spool_dir(&self) -> Result<PathBuf>;
    fn check_remove_spool(&self) -> Result<()>;
    /// Recheck service state after confirmation, before deleting the spool.
    fn remove_spool(&self) -> Result<()>;
}

pub(crate) struct ContainerBackend<'a>(pub(crate) &'a Context);

impl Backend for ContainerBackend<'_> {
    fn spool_dir(&self) -> Result<PathBuf> {
        // Bind mounted into the containers as /var/log/suricata/pcap.
        Ok(self.0.data_dir().join("suricata").join("log").join("pcap"))
    }

    fn check_remove_spool(&self) -> Result<()> {
        // Confirm absence by listing; an inspect failure may mean the daemon
        // is unavailable, not that Suricata has stopped.
        let output = self
            .0
            .manager
            .command()
            .args(["ps", "--all", "--format", "{{.Names}}"])
            .status_output()?;
        let existing = String::from_utf8(output)?;
        let name = crate::suricata::container_name(self.0);
        if existing.lines().any(|existing| existing == name) {
            let state = self.0.manager.state(&name)?;
            if state.running || state.restarting {
                bail!("Suricata is running; stop services before removing packet captures");
            }
        }
        Ok(())
    }

    fn remove_spool(&self) -> Result<()> {
        self.check_remove_spool()?;
        let directory = self.spool_dir()?;
        if directory.exists() {
            crate::uninstall::remove_directory(self.0, &directory)?;
        }
        Ok(())
    }
}
