// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

pub(crate) fn mkdirs(context: &Context) -> Result<()> {
    let dirs = vec![
        context.config_directory.join("suricata").join("lib"),
        context
            .config_directory
            .join("suricata")
            .join("lib")
            .join("rules"),
        context
            .config_directory
            .join("suricata")
            .join("lib")
            .join("update"),
        context.data_directory.join("suricata").join("log"),
        context.data_directory.join("suricata").join("run"),
    ];

    for dir in dirs {
        info!("Creating directory: {}", dir.display());
        std::fs::create_dir_all(&dir)?;
    }

    Ok(())
}
