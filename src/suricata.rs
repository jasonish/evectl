// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

pub(crate) fn container_name(context: &Context) -> String {
    let parent = context.root.file_name().unwrap().to_string_lossy();
    format!("{}-evectl-suricata", parent)
}

pub(crate) fn mkdirs(context: &Context) -> Result<()> {
    let dirs = vec![
        context.config_dir().join("suricata").join("lib"),
        context
            .config_dir()
            .join("suricata")
            .join("lib")
            .join("rules"),
        context
            .config_dir()
            .join("suricata")
            .join("lib")
            .join("update"),
        context
            .config_dir()
            .join("suricata")
            .join("lib")
            .join("update")
            .join("cache"),
        context.data_dir().join("suricata").join("log"),
        context.data_dir().join("suricata").join("run"),
    ];

    for dir in dirs {
        info!("Creating directory: {}", dir.display());
        std::fs::create_dir_all(&dir)?;
    }

    Ok(())
}
