// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Platform operations used by the shared Suricata configuration menu.

use std::path::PathBuf;

use crate::config::EveOutput;
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
