// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Platform operations for the shared packet-capture configuration menu.

use std::path::PathBuf;

use crate::prelude::*;

pub(crate) trait Backend {
    fn spool_dir(&self) -> Result<PathBuf>;
    fn check_remove_spool(&self) -> Result<()>;
    /// Recheck service state after confirmation, before deleting the spool.
    fn remove_spool(&self) -> Result<()>;
}
